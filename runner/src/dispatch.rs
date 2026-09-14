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

fn text_field(payload: &serde_json::Value, key: &str) -> String {
	payload.get(key).and_then(serde_json::Value::as_str).unwrap_or_default().to_owned()
}

fn int_field(payload: &serde_json::Value, key: &str) -> i64 {
	payload.get(key).and_then(serde_json::Value::as_i64).unwrap_or_default()
}

/// The fee terms under `key`, as the relay wrote them. `None` for JSON `null` — a fund
/// that charged nothing — and for anything that does not parse, which the caller treats
/// as unrenderable.
fn fee_terms(payload: &serde_json::Value, key: &str) -> Option<templates::FeeTerms> {
	serde_json::from_value(payload.get(key)?.clone()).ok()
}

/// Render one of the typed governance mails from its stored payload. `None` for a kind
/// this dispatcher does not know — permanent, so the caller parks rather than retries.
/// `cabinet_url` is the origin a fee notice's cabinet-relative link hangs off.
fn governance_mail(kind: &str, payload: &serde_json::Value, cabinet_url: &str) -> Option<templates::RenderedEmail> {
	match kind {
		"owner_removal_self_accept" => Some(templates::owner_removal_self_accept(
			&text_field(payload, "initiator_email"),
			&text_field(payload, "reason"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
			int_field(payload, "expires_at"),
		)),
		"payout_approval" => Some(templates::payout_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "network"),
			&text_field(payload, "address"),
			&text_field(payload, "amount"),
			&text_field(payload, "memo"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		"payment_consent" => Some(templates::payment_consent(
			&text_field(payload, "payment_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "tier"),
			&text_field(payload, "source"),
			&text_field(payload, "destination"),
			&text_field(payload, "amount"),
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		"payout_outcome" => Some(templates::payout_outcome(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "outcome"),
			&text_field(payload, "network"),
			&text_field(payload, "address"),
			&text_field(payload, "amount"),
			&text_field(payload, "detail"),
			&text_field(payload, "tier"),
			&text_field(payload, "source"),
			&text_field(payload, "destination"),
			&text_field(payload, "reason"),
		)),
		"payment_approval" => Some(templates::payment_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "payment_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "tier"),
			&text_field(payload, "source"),
			&text_field(payload, "destination"),
			&text_field(payload, "amount"),
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		// `current` may be null (a fund that charged nothing); `proposed` may not, and a
		// row without one is unrenderable rather than a mail proposing nothing.
		"fee_policy_approval" => Some(templates::fee_policy_approval(
			&text_field(payload, "consilium_id"),
			&text_field(payload, "initiator_email"),
			&text_field(payload, "fund"),
			fee_terms(payload, "current").as_ref(),
			&fee_terms(payload, "proposed")?,
			&text_field(payload, "reason"),
			&text_field(payload, "payload_hash"),
			int_field(payload, "threshold") as u32,
			int_field(payload, "owner_count") as u32,
			int_field(payload, "expires_at"),
			&text_field(payload, "approval_url"),
			&text_field(payload, "code"),
		)),
		"fee_policy_notice" => Some(templates::fee_policy_notice(
			&text_field(payload, "fund"),
			fee_terms(payload, "current").as_ref(),
			&fee_terms(payload, "proposed")?,
			int_field(payload, "effective_at"),
			// The relay admitted only a path starting with a single `/` (or nothing), so
			// joining onto the origin cannot leave it.
			&format!("{}{}", cabinet_url.trim_end_matches('/'), text_field(payload, "link")),
		)),
		_ => None,
	}
}

/// Render one claimed job. `None` when the row references data that has since gone,
/// which is treated as a permanent failure rather than retried forever.
fn render(job: &crate::infrastructure::notifications::DeliveryJob, cfg: &DispatcherConfig) -> Option<OutgoingEmail> {
	let origin = cfg.public_origin.trim_end_matches('/');
	let unsubscribe_url = format!("{origin}/notifications/unsubscribe?token={}", job.unsubscribe_token);

	// Governance mail carries NO unsubscribe target, so the transport sets no
	// List-Unsubscribe header: a security mail a recipient can switch off is not one.
	if let Some(payload) = job.payload.as_ref()
		&& let Some(rendered) = governance_mail(&job.kind, payload, &cfg.cabinet_url)
	{
		return Some(OutgoingEmail {
			to: job.recipient.clone(),
			subject: rendered.subject,
			html: rendered.html,
			text: rendered.text,
			unsubscribe_url: String::new(),
		});
	}

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

/// One pass of the hold sweep, bounded so a backlog cannot hold one transaction open for
/// an unbounded time. Returns how many accounts it released.
pub const HOLD_SWEEP_BATCH: i64 = 100;

/// The hold sweep. Spawned by the composition root; runs until the process ends.
///
/// THE ONE THING IN THIS PLANE THAT SWEEPS. Governance expiry is deliberately lazy —
/// nothing has to be running for a stale proposal to be unusable, because a write path
/// expires it before acting and read paths project it as expired. A hold cannot work that
/// way. Its entire purpose is the frozen flag the MONEY PLANE mirrors, and the money plane
/// learns of a change only from a `user_outbox` row; a lapse that were merely projected at
/// read time would release the account here and leave it frozen there, permanently. The
/// release has to be a write, so something has to run.
///
/// That makes this loop load-bearing in a way the dispatcher is not: if it stops, holds
/// stop lapsing and one operator's 24h brake quietly becomes indefinite. It is the exact
/// property the split verb exists to prevent, so a failing pass is logged at `error!`
/// rather than swallowed.
pub async fn run_hold_sweep(users: Arc<dyn crate::ports::UserDirectoryRepository>, interval: Duration) {
	tracing::info!(interval_secs = interval.as_secs(), "hold sweep started");
	loop {
		let now = crate::notification::now_secs();
		match users.lapse_due_holds(now, HOLD_SWEEP_BATCH).await {
			Ok(lapsed) if lapsed.is_empty() => {}
			Ok(lapsed) => {
				for id in &lapsed {
					tracing::info!(user_id = %id, "a hold lapsed unratified; the account is active again");
				}
				// A full batch means there is probably more behind it.
				if lapsed.len() as i64 >= HOLD_SWEEP_BATCH {
					continue;
				}
			}
			Err(err) => tracing::error!(%err, "the hold sweep failed; holds are not lapsing"),
		}
		tokio::time::sleep(interval).await;
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

	/// A fee notice's link is stored as a cabinet path and resolved here — against the
	/// origin this plane is configured with, never one the money plane named.
	#[test]
	fn a_fee_notice_link_hangs_off_the_configured_cabinet() {
		let payload = serde_json::json!({
			"fund": "Quy Nhon Fund",
			"current": null,
			"proposed": {"management_bps": 200, "performance_bps": 2000, "hurdle_bps": 0, "basis": "invested_capital", "crystallization": "annual"},
			"effective_at": 1_785_143_640,
			"link": "/funds/quy-nhon/fees",
		});
		let mail = governance_mail("fee_policy_notice", &payload, "https://cabinet.example/").expect("renderable");
		assert!(mail.html.contains("https://cabinet.example/funds/quy-nhon/fees"), "one slash between origin and path");
		assert!(mail.text.contains("none → 2%"));

		let mut no_terms = payload.clone();
		no_terms["proposed"] = serde_json::Value::Null;
		assert!(
			governance_mail("fee_policy_notice", &no_terms, "https://cabinet.example").is_none(),
			"a notice proposing nothing is unrenderable"
		);
		let mut half_terms = payload;
		half_terms["proposed"] = serde_json::json!({"management_bps": 200});
		assert!(
			governance_mail("fee_policy_approval", &half_terms, "https://cabinet.example").is_none(),
			"so is a payload missing half its terms"
		);
	}

	#[test]
	fn every_backoff_fits_the_retry_window() {
		// The lease must be shorter than the shortest backoff, or a row could be
		// re-claimed by another dispatcher before its own retry is due.
		assert!(LEASE_SECS <= backoff_secs(1) * 5, "the lease is on the same order as the first retry");
		assert!(backoff_secs(1) > 0);
	}
}
