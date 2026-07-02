//! `bridge` module — the cross-plane (identity → money) producer seam.
//!
//! The ONLY coupling between the two planes is this ONE-WAY bridge: concierge emits
//! [`UserLifecycleEvent`]s to `user_outbox`, and the banking money plane PULLS them
//! over [`UserEvents::pull_user_lifecycle`] to gate/freeze money ops. Concierge never
//! calls banking.
//!
//! This is a service-to-service seam, NOT a user surface — it is authenticated by a
//! shared bridge service token (config `BRIDGE_SERVICE_TOKEN`), checked here rather
//! than via the user `grpc_auth_layer` (which verifies user access tokens against the
//! JWKS). The pull is READ-ONLY: rows are never deleted, because banking dedupes by
//! `event_id` and orders per-user by `sequence` — concierge keeps the durable log.
//!
//! WHY a shared token and not mTLS: this is the platform-bring-up transport. Graduate
//! to mTLS/SPIFFE workload identity at platform scale.
//!
//! `Result<_, Status>` is tonic's mandated handler signature; `Status` is a large type
//! we don't control, so the large-err lint does not apply in this module.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use evconcierge_contracts::concierge::v1::{PullUserLifecycleRequest, PullUserLifecycleResponse, UserLifecycleEvent, user_events_server::UserEvents, user_lifecycle_event::Kind};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};

/// The largest page the bridge will serve, regardless of the request's `limit`. Caps a
/// single pull so one call can't scan the whole outbox.
const MAX_LIMIT: i64 = 500;

/// The cross-plane bridge producer. Serves `user_outbox` rows to the banking puller.
/// Cheaply cloneable (pool + token behind `Arc`s).
#[derive(Clone)]
pub struct Bridge {
	pool: PgPool,
	/// The shared service token the puller must present. `None` ⇒ the bridge is not
	/// configured and every pull is rejected (fail-closed: never leak the outbox).
	token: Option<Arc<str>>,
}

impl Bridge {
	pub fn new(pool: PgPool, token: Option<String>) -> Self {
		Self {
			pool,
			token: token.map(|t| Arc::from(t.as_str())),
		}
	}

	/// Authenticate the service-to-service caller against the shared bridge token
	/// (compared in constant time, so verification leaks nothing via timing). A
	/// missing configured token fails closed; a wrong/absent bearer is rejected.
	fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
		let Some(expected) = self.token.as_deref() else {
			return Err(Status::unavailable("bridge not configured"));
		};
		match bearer_token(request) {
			Some(presented) if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) => Ok(()),
			_ => Err(Status::unauthenticated("invalid bridge service token")),
		}
	}
}

#[derive(sqlx::FromRow)]
struct OutboxRow {
	position: i64,
	user_id: uuid::Uuid,
	kind: String,
	kyc_level: i32,
	occurred_at: i64,
	sequence: i64,
	event_id: uuid::Uuid,
	auth_subject: String,
	email: Option<String>,
	email_verified: bool,
	token_version: i64,
	role: Option<String>,
}

impl OutboxRow {
	fn into_event(self) -> UserLifecycleEvent {
		UserLifecycleEvent {
			user_id: self.user_id.to_string(),
			kind: kind_to_proto(&self.kind) as i32,
			kyc_level: self.kyc_level as u32,
			occurred_at: self.occurred_at,
			event_id: self.event_id.to_string(),
			sequence: self.sequence as u64,
			auth_subject: self.auth_subject,
			email: self.email.unwrap_or_default(),
			email_verified: self.email_verified,
			token_version: self.token_version as u64,
			// Absent (pre-role rows) → empty; the banking puller reads empty as 'investor'.
			role: self.role.unwrap_or_default(),
		}
	}
}

#[tonic::async_trait]
impl UserEvents for Bridge {
	async fn pull_user_lifecycle(&self, request: Request<PullUserLifecycleRequest>) -> Result<Response<PullUserLifecycleResponse>, Status> {
		self.authenticate(&request)?;
		let req = request.into_inner();
		let limit = (req.limit as i64).clamp(1, MAX_LIMIT);

		let rows = sqlx::query_as::<_, OutboxRow>(
			"SELECT position, user_id, kind, kyc_level, occurred_at, sequence, event_id, auth_subject, email, email_verified, token_version, role \
			FROM user_outbox WHERE position > $1 ORDER BY position ASC LIMIT $2",
		)
		.bind(req.after_position)
		.bind(limit)
		.fetch_all(&self.pool)
		.await
		// Log the real cause; never put sqlx internals on the wire.
		.map_err(|err| {
			tracing::error!("outbox read failed: {err}");
			Status::unavailable("internal error")
		})?;

		// `next_position` advances to the last row served, or stays put if none matched.
		let next_position = rows.last().map(|r| r.position).unwrap_or(req.after_position);
		let events = rows.into_iter().map(OutboxRow::into_event).collect();
		Ok(Response::new(PullUserLifecycleResponse { events, next_position }))
	}
}

/// Map the outbox `kind` string (`UserEvent::kind()`, lockstep with the proto enum) to
/// the proto [`Kind`]. An unrecognized kind degrades to `Unspecified` rather than
/// failing the whole page.
fn kind_to_proto(kind: &str) -> Kind {
	match kind {
		"CREATED" => Kind::Created,
		"SUSPENDED" => Kind::Suspended,
		"REINSTATED" => Kind::Reinstated,
		"KYC_CHANGED" => Kind::KycChanged,
		"SESSIONS_REVOKED" => Kind::SessionsRevoked,
		"ROLE_CHANGED" => Kind::RoleChanged,
		_ => Kind::Unspecified,
	}
}

fn bearer_token<T>(request: &Request<T>) -> Option<String> {
	let value = request.metadata().get("authorization")?.to_str().ok()?;
	value.strip_prefix("Bearer ").map(str::to_owned)
}

#[cfg(test)]
mod tests {
	use domain::users::UserEvent;

	use super::{Kind, kind_to_proto};

	#[test]
	fn every_user_event_kind_maps_to_a_concrete_proto_kind() {
		// Guards the bridge producer: a `UserEvent` whose `kind()` string isn't mapped
		// here degrades to `Unspecified` and is a silent no-op on the money plane — the
		// exact bug that let ROLE_CHANGED never reach banking. Keep this list exhaustive.
		for event in [
			UserEvent::Created,
			UserEvent::SessionsRevoked,
			UserEvent::Suspended,
			UserEvent::Reinstated,
			UserEvent::KycChanged,
			UserEvent::RoleChanged,
		] {
			assert_ne!(kind_to_proto(event.kind()), Kind::Unspecified, "unmapped bridge kind: {}", event.kind());
		}
		assert_eq!(kind_to_proto("ROLE_CHANGED"), Kind::RoleChanged);
	}
}
