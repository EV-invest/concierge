//! `notification` module — the platform's notification plane.
//!
//! Owns three things: who may be contacted (subscribers), what they asked to hear
//! about (subscriptions), and the durable record of what was said (the inbox). Email
//! delivery is queued here and drained by the dispatcher in [`crate::dispatch`].
//!
//! AUTHZ SPLIT. [`Notifications::emit`] is service-to-service: it must carry a
//! `typ=service` token, because it writes into someone else's inbox and no end user
//! may do that. Everything else is self-service and acts strictly on the caller's own
//! subscriber row, gated through the shared [`crate::authz`] live-record check — so a
//! suspended or token-revoked principal loses access here exactly as everywhere else.
//! The account-less subscribe/confirm/unsubscribe RPCs are also service-called (the
//! public edge proxies them) and are protected by rate limits rather than by identity,
//! since by definition there is no identity yet.
//!
//! SPAM RESISTANCE. An open "email me updates" endpoint is a mail cannon pointed at
//! whoever an attacker names, so the protection is layered rather than one check:
//! (1) the address must parse; (2) a per-IP request budget; (3) a per-address
//! confirmation-send throttle held in Postgres, which caps mail per victim no matter
//! how many requests arrive or from where; (4) double opt-in, so an unconfirmed
//! address only ever receives that one throttled message; and (5) a global daily send
//! budget enforced by the dispatcher as the backstop. Only (2) is memory-resident —
//! the layers that actually bound mail volume are durable.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use domain::users::Email;
use evconcierge_auth::{Claims, claims_of};
use evconcierge_contracts::concierge::v1::{
	Channel, ConfirmSubscriptionRequest, ConfirmSubscriptionResponse, EmitRequest, EmitResponse, GetNotificationSettingsRequest, GetUnreadCountRequest, GetUnreadCountResponse,
	ListNotificationsRequest, ListNotificationsResponse, MarkReadRequest, MarkReadResponse, Notification as NotificationMsg, NotificationSettings, SetChannelEnabledRequest,
	SetTopicSubscriptionRequest, SubscribeAnonymousRequest, SubscribeAnonymousResponse, TopicSubscription, UnsubscribeRequest, UnsubscribeResponse,
	notification_service_server::NotificationService,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
	infrastructure::notifications::SubscriberRow,
	ports::{NotificationRepository, UserDirectoryRepository},
	support::domain_to_status,
};

/// A subscribable topic. Server-owned so every client renders identical wording, and
/// closed so an emitter cannot invent topics nobody can find or unsubscribe from.
pub struct Topic {
	pub key: &'static str,
	pub label: &'static str,
	pub description: &'static str,
}

pub const TOPICS: &[Topic] = &[
	Topic {
		key: "fund:quy-nhon",
		label: "Quy Nhon Fund",
		description: "NAV updates, distributions, research notes",
	},
	Topic {
		key: "account:money-movement",
		label: "Money movement",
		description: "Deposits, withdrawals, redemptions",
	},
	Topic {
		key: "account:verification",
		label: "Identity verification",
		description: "Decisions on your KYC submissions",
	},
	Topic {
		key: "platform:announcements",
		label: "Platform & product",
		description: "Maintenance windows, new features",
	},
];

pub fn topic(key: &str) -> Option<&'static Topic> {
	TOPICS.iter().find(|t| t.key == key)
}

/// Fixed-window request counter keyed by caller-supplied identity (an IP).
///
/// Deliberately per-process and in-memory: this is the cheap first line, not the layer
/// that bounds mail volume — the per-address throttle and the daily send budget live in
/// Postgres precisely so they survive a restart and hold across replicas. Promote this
/// to the existing Redis connection once concierge runs more than one instance.
pub struct RateLimiter {
	window_secs: u64,
	max: u32,
	hits: Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
	pub fn new(window: Duration, max: u32) -> Self {
		Self {
			window_secs: window.as_secs().max(1),
			max,
			hits: Mutex::new(HashMap::new()),
		}
	}

	/// True when the call is within budget.
	pub fn check(&self, key: &str) -> bool {
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		let bucket = now / self.window_secs;
		let Ok(mut hits) = self.hits.lock() else {
			// A poisoned lock must not become an open door.
			return false;
		};
		// Bounded memory: stale buckets are dropped wholesale, so a spray of unique
		// keys cannot grow the map without limit.
		if hits.len() > 10_000 {
			hits.retain(|_, (b, _)| *b == bucket);
		}
		let entry = hits.entry(key.to_owned()).or_insert((bucket, 0));
		if entry.0 != bucket {
			*entry = (bucket, 0);
		}
		entry.1 += 1;
		entry.1 <= self.max
	}
}

/// How long an address waits before another confirmation mail can be generated.
pub const CONFIRM_THROTTLE_SECS: i64 = 24 * 60 * 60;
const DEFAULT_PAGE: u32 = 20;
const MAX_PAGE: u32 = 100;

/// The notification service. Cheaply cloneable (everything behind `Arc`s).
#[derive(Clone)]
pub struct Notifications {
	notifications: Arc<dyn NotificationRepository>,
	users: Arc<dyn UserDirectoryRepository>,
	limiter: Arc<RateLimiter>,
}

impl Notifications {
	pub fn new(notifications: Arc<dyn NotificationRepository>, users: Arc<dyn UserDirectoryRepository>, limiter: Arc<RateLimiter>) -> Self {
		Self { notifications, users, limiter }
	}

	/// Resolve the caller's own subscriber row, enforcing the live persisted record.
	/// Created on first touch, so a user never has to switch notifications ON before
	/// they are allowed to switch them off.
	async fn caller<T>(&self, request: &Request<T>) -> Result<SubscriberRow, Status> {
		let gate = crate::authz::caller_gate(self.users.as_ref(), request).await?;
		let id = gate.id.ok_or_else(|| Status::unauthenticated("caller is not a user"))?;
		let user = self.users.find_by_id(id).await.map_err(domain_to_status)?.ok_or_else(|| Status::not_found("user not found"))?;
		self.notifications
			.subscriber_for_user(id.raw(), user.email().as_str(), user.email_verified())
			.await
			.map_err(domain_to_status)
	}

	/// Assert a `typ=service` token. A user token must never reach the emit path or
	/// the account-less subscribe path.
	fn require_service<T>(request: &Request<T>) -> Result<(), Status> {
		let claims: &Claims = claims_of(request).ok_or_else(|| Status::unauthenticated("missing claims"))?;
		if claims.is_access() {
			return Err(Status::permission_denied("service token required"));
		}
		Ok(())
	}

	async fn settings_snapshot(&self, sub: &SubscriberRow) -> Result<NotificationSettings, Status> {
		let held = self.notifications.subscriptions(sub.id).await.map_err(domain_to_status)?;
		let topics = TOPICS
			.iter()
			.map(|t| {
				let row = held.iter().find(|s| s.topic == t.key);
				TopicSubscription {
					topic: t.key.to_owned(),
					label: t.label.to_owned(),
					description: t.description.to_owned(),
					subscribed: row.is_some(),
					email_enabled: row.map(|r| r.email_enabled).unwrap_or(true),
				}
			})
			.collect();
		Ok(NotificationSettings {
			in_app_enabled: sub.in_app_enabled,
			email_enabled: sub.email_enabled,
			email: sub.email.clone(),
			email_verified: sub.email_verified,
			topics,
		})
	}
}

#[tonic::async_trait]
impl NotificationService for Notifications {
	async fn emit(&self, request: Request<EmitRequest>) -> Result<Response<EmitResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();

		let user_id = Uuid::parse_str(&req.user_id).map_err(|_| Status::invalid_argument("user_id must be a UUID"))?;
		if topic(&req.topic).is_none() {
			return Err(Status::invalid_argument("unknown topic"));
		}
		// Checked here as well as by the CHECK constraints, so an over-long title is a
		// clear invalid_argument rather than a constraint violation surfacing as the
		// opaque `unavailable` that `DomainError::Repository` maps to.
		if req.title.is_empty() || req.title.chars().count() > 200 {
			return Err(Status::invalid_argument("title must be 1-200 characters"));
		}
		if req.body.chars().count() > 2000 {
			return Err(Status::invalid_argument("body must be at most 2000 characters"));
		}
		if req.link.chars().count() > 512 {
			return Err(Status::invalid_argument("link must be at most 512 characters"));
		}
		if req.dedupe_key.is_empty() || req.dedupe_key.chars().count() > 128 {
			return Err(Status::invalid_argument("dedupe_key must be 1-128 characters"));
		}
		if req.kind.is_empty() || req.kind.chars().count() > 64 {
			return Err(Status::invalid_argument("kind must be 1-64 characters"));
		}

		let occurred_at = if req.occurred_at > 0 { req.occurred_at } else { now_secs() };

		let outcome = self
			.notifications
			.emit(user_id, &req.topic, &req.kind, &req.title, &req.body, &req.link, &req.dedupe_key, occurred_at)
			.await
			.map_err(domain_to_status)?;

		let mut channels = Vec::new();
		if outcome.in_app {
			channels.push(Channel::InApp as i32);
		}
		if outcome.email {
			channels.push(Channel::Email as i32);
		}
		Ok(Response::new(EmitResponse {
			notification_id: outcome.notification_id.map(|id| id.to_string()).unwrap_or_default(),
			delivered: !channels.is_empty(),
			channels,
		}))
	}

	async fn list_notifications(&self, request: Request<ListNotificationsRequest>) -> Result<Response<ListNotificationsResponse>, Status> {
		let sub = self.caller(&request).await?;
		let req = request.get_ref();

		// Switching the in-app channel off hides the inbox rather than deleting it:
		// the record survives, so turning the channel back on restores history.
		if !sub.in_app_enabled {
			return Ok(Response::new(ListNotificationsResponse::default()));
		}

		let limit = match req.limit {
			0 => DEFAULT_PAGE,
			n => n.min(MAX_PAGE),
		};
		let cursor = match req.cursor.as_str() {
			"" => None,
			raw => Some(Uuid::parse_str(raw).map_err(|_| Status::invalid_argument("cursor must be a notification id"))?),
		};
		let topic_filter = match req.topic.as_str() {
			"" => None,
			t if topic(t).is_some() => Some(t),
			_ => return Err(Status::invalid_argument("unknown topic")),
		};

		// One extra row tells us whether a further page exists, with no second query.
		let mut rows = self
			.notifications
			.list(sub.id, cursor, i64::from(limit) + 1, req.unread_only, topic_filter)
			.await
			.map_err(domain_to_status)?;
		let next_cursor = if rows.len() > limit as usize {
			rows.truncate(limit as usize);
			rows.last().map(|r| r.id.to_string()).unwrap_or_default()
		} else {
			String::new()
		};

		let unread_count = self.notifications.unread_count(sub.id).await.map_err(domain_to_status)? as u32;
		Ok(Response::new(ListNotificationsResponse {
			notifications: rows
				.into_iter()
				.map(|r| NotificationMsg {
					id: r.id.to_string(),
					topic: r.topic,
					kind: r.kind,
					title: r.title,
					body: r.body,
					link: r.link,
					occurred_at: r.occurred_at,
					created_at: r.created_at,
					read_at: r.read_at,
				})
				.collect(),
			next_cursor,
			unread_count,
		}))
	}

	async fn get_unread_count(&self, request: Request<GetUnreadCountRequest>) -> Result<Response<GetUnreadCountResponse>, Status> {
		let sub = self.caller(&request).await?;
		let unread_count = if sub.in_app_enabled {
			self.notifications.unread_count(sub.id).await.map_err(domain_to_status)? as u32
		} else {
			0
		};
		Ok(Response::new(GetUnreadCountResponse { unread_count }))
	}

	async fn mark_read(&self, request: Request<MarkReadRequest>) -> Result<Response<MarkReadResponse>, Status> {
		let sub = self.caller(&request).await?;
		let req = request.get_ref();

		let ids = req
			.ids
			.iter()
			.map(|raw| Uuid::parse_str(raw).map_err(|_| Status::invalid_argument("notification id must be a UUID")))
			.collect::<Result<Vec<_>, _>>()?;
		if !req.all && ids.is_empty() {
			return Err(Status::invalid_argument("provide notification ids or set all"));
		}

		let marked = self.notifications.mark_read(sub.id, &ids, req.all).await.map_err(domain_to_status)? as u32;
		let unread_count = self.notifications.unread_count(sub.id).await.map_err(domain_to_status)? as u32;
		Ok(Response::new(MarkReadResponse { marked, unread_count }))
	}

	async fn get_notification_settings(&self, request: Request<GetNotificationSettingsRequest>) -> Result<Response<NotificationSettings>, Status> {
		let sub = self.caller(&request).await?;
		Ok(Response::new(self.settings_snapshot(&sub).await?))
	}

	async fn set_channel_enabled(&self, request: Request<SetChannelEnabledRequest>) -> Result<Response<NotificationSettings>, Status> {
		let sub = self.caller(&request).await?;
		let req = request.get_ref();

		// Both channels off is explicitly allowed — "stop contacting me" is a supported
		// product state, so there is deliberately no floor keeping one of them on.
		let (in_app, email) = match Channel::try_from(req.channel) {
			Ok(Channel::InApp) => (Some(req.enabled), None),
			Ok(Channel::Email) => (None, Some(req.enabled)),
			_ => return Err(Status::invalid_argument("channel must be in-app or email")),
		};
		self.notifications.set_channel_enabled(sub.id, in_app, email).await.map_err(domain_to_status)?;

		// Re-read rather than patch the local copy, so the snapshot the caller renders
		// from is what the database actually holds.
		let sub = self.caller(&request).await?;
		Ok(Response::new(self.settings_snapshot(&sub).await?))
	}

	async fn set_topic_subscription(&self, request: Request<SetTopicSubscriptionRequest>) -> Result<Response<NotificationSettings>, Status> {
		let sub = self.caller(&request).await?;
		let req = request.get_ref();
		if topic(&req.topic).is_none() {
			return Err(Status::invalid_argument("unknown topic"));
		}
		self.notifications
			.set_topic_subscription(sub.id, &req.topic, req.subscribed, req.email_enabled)
			.await
			.map_err(domain_to_status)?;
		Ok(Response::new(self.settings_snapshot(&sub).await?))
	}

	async fn subscribe_anonymous(&self, request: Request<SubscribeAnonymousRequest>) -> Result<Response<SubscribeAnonymousResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();

		if topic(&req.topic).is_none() {
			return Err(Status::invalid_argument("unknown topic"));
		}
		// Parsed, not merely non-empty: everything downstream treats this as a real
		// mailbox, and a malformed address becomes a hard bounce charged against our
		// sending reputation.
		let email = Email::parse(&req.email).map_err(|_| Status::invalid_argument("email is not a valid address"))?;

		// The per-IP budget is the cheap gate. An empty client_ip shares one bucket, so
		// a caller that declines to forward it throttles itself rather than everyone.
		let bucket = if req.client_ip.is_empty() { "anonymous" } else { req.client_ip.as_str() };
		if !self.limiter.check(bucket) {
			return Err(Status::resource_exhausted("too many subscription attempts"));
		}

		// The database throttle is what actually bounds mail: at most one confirmation
		// per address per window, however many requests arrive and from wherever.
		let queued = self
			.notifications
			.subscribe_anonymous(email.as_str(), &req.topic, CONFIRM_THROTTLE_SECS)
			.await
			.map_err(domain_to_status)?;
		if queued.is_none() {
			tracing::debug!(topic = %req.topic, "anonymous subscribe accepted without queueing confirmation (already confirmed, or throttled)");
		}

		// Always the same answer. Whether the address was new, already subscribed or
		// throttled is not something an unauthenticated caller gets to learn.
		Ok(Response::new(SubscribeAnonymousResponse { accepted: true }))
	}

	async fn confirm_subscription(&self, request: Request<ConfirmSubscriptionRequest>) -> Result<Response<ConfirmSubscriptionResponse>, Status> {
		Self::require_service(&request)?;
		let token = request.into_inner().token;
		if token.is_empty() {
			return Err(Status::invalid_argument("token is required"));
		}
		let confirmed = self.notifications.confirm(&token).await.map_err(domain_to_status)?;
		Ok(Response::new(ConfirmSubscriptionResponse { confirmed }))
	}

	async fn unsubscribe(&self, request: Request<UnsubscribeRequest>) -> Result<Response<UnsubscribeResponse>, Status> {
		Self::require_service(&request)?;
		let req = request.into_inner();
		if req.token.is_empty() {
			return Err(Status::invalid_argument("token is required"));
		}
		let topic_filter = match req.topic.as_str() {
			"" => None,
			t if topic(t).is_some() => Some(t),
			_ => return Err(Status::invalid_argument("unknown topic")),
		};
		let unsubscribed = self.notifications.unsubscribe(&req.token, topic_filter).await.map_err(domain_to_status)?;
		Ok(Response::new(UnsubscribeResponse { unsubscribed }))
	}
}

pub(crate) fn now_secs() -> i64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn topics_are_unique_and_bounded() {
		for t in TOPICS {
			assert!(topic(t.key).is_some(), "every catalogue entry resolves through the lookup");
			assert!(t.key.len() <= 64, "topic keys must fit the notifications.topic CHECK constraint");
			assert_eq!(TOPICS.iter().filter(|o| o.key == t.key).count(), 1, "duplicate topic key {}", t.key);
		}
		assert!(topic("fund:does-not-exist").is_none(), "the catalogue is closed — unknown topics are rejected, not created");
	}

	#[test]
	fn rate_limiter_admits_up_to_the_budget_then_refuses() {
		let limiter = RateLimiter::new(Duration::from_secs(60), 3);
		assert!(limiter.check("1.2.3.4"), "first call is within budget");
		assert!(limiter.check("1.2.3.4"));
		assert!(limiter.check("1.2.3.4"), "the budget is inclusive of its last slot");
		assert!(!limiter.check("1.2.3.4"), "the fourth call in the window is refused");
		assert!(limiter.check("5.6.7.8"), "budgets are per key — one noisy caller must not lock everyone out");
	}

	#[test]
	fn rate_limiter_bounds_its_own_memory() {
		let limiter = RateLimiter::new(Duration::from_secs(60), 1);
		for i in 0..10_100 {
			limiter.check(&format!("key-{i}"));
		}
		let len = limiter.hits.lock().expect("uncontended").len();
		assert!(len <= 10_100, "a spray of unique keys must not grow the map without bound (was {len})");
	}
}
