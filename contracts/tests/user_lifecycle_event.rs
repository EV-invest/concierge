//! FB-27 / CON-ARCHCOMM-01..03, CROSS-3, CROSS-4: the cross-plane
//! `UserLifecycleEvent` envelope carries everything the banking consumer needs to
//! dedupe (`event_id`), order (`sequence`), correlate (`auth_subject`), and
//! provision/gate (`email`/`email_verified`/`token_version`).
//!
//! Pure wire test: a prost encode→decode round trip proves the new fields exist at
//! distinct, non-colliding field numbers (a collision would mis-decode and drop a
//! value). No DB, no services.

use evconcierge_contracts::concierge::v1::{UserLifecycleEvent, user_lifecycle_event::Kind};
use prost::Message;

#[test]
fn lifecycle_event_round_trips_with_full_envelope() {
	let event = UserLifecycleEvent {
		user_id: "concierge-canonical-uuid".to_string(),
		kind: Kind::Created as i32,
		kyc_level: 2,
		occurred_at: 1_700_000_000,
		event_id: "outbox-row-uuid".to_string(),
		sequence: 7,
		auth_subject: "google-sub-1234567890".to_string(),
		email: "user@example.com".to_string(),
		email_verified: true,
		token_version: 3,
	};

	let decoded = UserLifecycleEvent::decode(event.encode_to_vec().as_slice()).expect("round trips");

	assert_eq!(decoded, event);
	assert_eq!(decoded.event_id, "outbox-row-uuid");
	assert_eq!(decoded.sequence, 7);
	assert_eq!(decoded.auth_subject, "google-sub-1234567890");
	assert_eq!(decoded.email, "user@example.com");
	assert!(decoded.email_verified);
	assert_eq!(decoded.token_version, 3);
}
