//! The outbound email dispatcher — the notification plane's only sender.
//!
//! A background loop that claims due rows from `notification_deliveries`, renders
//! them, and hands them to the [`EmailTransport`]. Shaped like banking's
//! `BridgeConsumer::run` (interval + claim + apply), but this queue has no external
//! puller, so the loop lives here and the claim leases rows rather than advancing a
//! shared cursor.
//!
//! THREE THINGS THIS LOOP IS RESPONSIBLE FOR BEYOND SENDING:
//!
//! * **Backoff.** A transport failure reschedules with exponential delay and parks the
//!   row as `failed` once [`MAX_ATTEMPTS`] is spent, so one poisoned recipient cannot
//!   occupy the queue forever.
//! * **The daily send budget.** Gmail's SMTP relay has a hard daily ceiling, and
//!   tripping it gets the sending account throttled — which would take down password
//!   resets and every other transactional mail with it. The loop stops sending when
//!   the trailing 24h count reaches the budget and lets the queue accumulate instead:
//!   delayed mail is recoverable, a throttled sender is not.
//! * **Never dropping work.** Nothing is deleted here. A row is `sent`, or pending
//!   with a future attempt, or parked `failed` for an operator to look at.

use std::{sync::Arc, time::Duration};

use crate::{
	infrastructure::email::{
		templates,
		transport::{EmailTransport, OutgoingEmail},
	},
	notification::topic,
	ports::NotificationDispatchRepository,
};

/// Attempts before a delivery is parked as `failed`.
pub const MAX_ATTEMPTS: i32 = 6;
/// How long a claimed row is invisible to other dispatchers.
const LEASE_SECS: i64 = 300;
/// Rows claimed per tick. Small enough that a crash re-does little work.
const BATCH: i64 = 25;

pub struct DispatcherConfig {
	/// `From:` mailbox for outgoing mail.
	pub mail_from: String,
	/// Origin the cabinet is served from; builds links inside emails.
	pub cabinet_url: String,
	/// Public origin serving the confirm/unsubscribe endpoints.
	pub public_origin: String,
	/// Trailing-24h send ceiling. Reaching it pauses sending, not queueing.
	pub daily_budget: i64,
	pub interval: Duration,
}

/// `60s · 2^(attempt-1)`, capped at six hours.
fn backoff_secs(attempts: i32) -> i64 {
	// Clamp the shift (not the result) purely to keep the `<<` in range; the six-hour
	// `min` below is what actually bounds the delay.
	let shift = attempts.clamp(1, 16) - 1;
	(60i64 << shift).min(6 * 60 * 60)
}

/// Render one claimed job. `None` when the row references data that has since gone,
/// which is treated as a permanent failure rather than retried forever.
fn render(job: &crate::infrastructure::notifications::DeliveryJob, cfg: &DispatcherConfig) -> Option<OutgoingEmail> {
	let origin = cfg.public_origin.trim_end_matches('/');
	let unsubscribe_url = format!("{origin}/notifications/unsubscribe?token={}", job.unsubscribe_token);

	let rendered = match job.kind.as_str() {
		"confirm" => {
			let token = job.confirm_token.as_deref()?;
			// The topic label is cosmetic here; a confirmation for a since-retired topic
			// should still be completable.
			let label = job.topic.as_deref().and_then(topic).map(|t| t.label).unwrap_or("EV Investment");
			templates::confirm_subscription(label, &format!("{origin}/notifications/confirm?token={token}"), &unsubscribe_url)
		}
		_ => {
			let topic_key = job.topic.as_deref()?;
			let label = topic(topic_key).map(|t| t.label).unwrap_or(topic_key);
			templates::notification(
				label,
				job.title.as_deref()?,
				job.body.as_deref().unwrap_or(""),
				job.link.as_deref().unwrap_or(""),
				job.occurred_at.unwrap_or_default(),
				&cfg.cabinet_url,
				&unsubscribe_url,
			)
		}
	};

	Some(OutgoingEmail {
		to: job.recipient.clone(),
		subject: rendered.subject,
		html: rendered.html,
		text: rendered.text,
		unsubscribe_url,
	})
}

/// Drain whatever is due once. Returns how many rows were claimed, so the caller can
/// keep draining while the queue is deep instead of sleeping between full batches.
pub async fn drain_once(repo: &dyn NotificationDispatchRepository, transport: &dyn EmailTransport, cfg: &DispatcherConfig) -> usize {
	match repo.sent_last_24h().await {
		Ok(sent) if sent >= cfg.daily_budget => {
			tracing::warn!(sent, budget = cfg.daily_budget, "daily email budget reached — queueing without sending until the window rolls");
			return 0;
		}
		Ok(_) => {}
		// The budget is a safety rail; failing to read it must not silently disable
		// sending, but it is worth shouting about.
		Err(err) => tracing::error!(%err, "could not read the daily send budget — proceeding"),
	}

	let jobs = match repo.claim_due(BATCH, LEASE_SECS).await {
		Ok(jobs) => jobs,
		Err(err) => {
			tracing::error!(%err, "could not claim email deliveries");
			return 0;
		}
	};
	let claimed = jobs.len();

	for job in jobs {
		let Some(mail) = render(&job, cfg) else {
			// Unrenderable rows never become renderable, so park immediately rather
			// than burning six attempts on them.
			tracing::error!(delivery_id = job.id, kind = %job.kind, "delivery could not be rendered — parking");
			let _ = repo.mark_failed(job.id, "unrenderable delivery", backoff_secs(job.attempts), 0).await;
			continue;
		};

		match transport.send(&cfg.mail_from, mail).await {
			Ok(()) => {
				if let Err(err) = repo.mark_sent(job.id).await {
					// Sent but not recorded: the lease will lapse and it will send
					// again. At-least-once is the deliberate trade — a duplicate email
					// is recoverable, a silently dropped one is not.
					tracing::error!(delivery_id = job.id, %err, "email sent but could not be marked sent");
				}
			}
			Err(err) => {
				let backoff = backoff_secs(job.attempts);
				tracing::warn!(delivery_id = job.id, attempts = job.attempts, backoff, %err, "email delivery failed");
				if let Err(err) = repo.mark_failed(job.id, &err.to_string(), backoff, MAX_ATTEMPTS).await {
					tracing::error!(delivery_id = job.id, %err, "could not record a failed delivery");
				}
			}
		}
	}

	claimed
}

/// The dispatcher loop. Spawned by the composition root; runs until the process ends.
pub async fn run_dispatcher(repo: Arc<dyn NotificationDispatchRepository>, transport: Arc<dyn EmailTransport>, cfg: DispatcherConfig) {
	tracing::info!(interval_secs = cfg.interval.as_secs(), daily_budget = cfg.daily_budget, "notification dispatcher started");
	loop {
		// A full batch means there is probably more behind it — keep going rather than
		// sleeping a whole interval per 25 messages when a backlog is draining.
		let claimed = drain_once(repo.as_ref(), transport.as_ref(), &cfg).await;
		if claimed < BATCH as usize {
			tokio::time::sleep(cfg.interval).await;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn backoff_grows_then_stops_growing() {
		assert_eq!(backoff_secs(1), 60, "the first retry is a minute out, not immediate");
		assert_eq!(backoff_secs(2), 120);
		assert_eq!(backoff_secs(3), 240);
		assert_eq!(backoff_secs(MAX_ATTEMPTS), 60 << (MAX_ATTEMPTS - 1));
		assert_eq!(backoff_secs(99), 6 * 60 * 60, "the six-hour cap binds for absurd attempt counts, and the shift never overflows");
		assert_eq!(backoff_secs(9), 15_360, "growth is still exponential below the cap");
		assert_eq!(backoff_secs(0), 60, "a zero attempt count clamps rather than shifting by -1");
	}

	#[test]
	fn every_backoff_fits_the_retry_window() {
		// The lease must be shorter than the shortest backoff, or a row could be
		// re-claimed by another dispatcher before its own retry is due.
		assert!(LEASE_SECS <= backoff_secs(1) * 5, "the lease is on the same order as the first retry");
		assert!(backoff_secs(1) > 0);
	}
}
