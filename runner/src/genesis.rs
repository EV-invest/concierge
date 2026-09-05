//! `genesis` — the one-shot seeding of the fund's first owner registry.
//!
//! `users.role` is the single source of truth about ownership: the consilium counts
//! it, the quorum is taken from it, and the money plane mirrors it over the bridge.
//! That leaves one gap the consilium cannot close by design — an EMPTY registry.
//! Admission requires `owners \ {initiator}` to be non-empty, so it can never produce
//! the second owner, let alone the first. Genesis is the only writer that can, and it
//! runs at boot, before the gRPC surface is up.
//!
//! # The rule, exactly
//!
//! 1. If the persisted registry already holds anyone, do nothing, ever again. Genesis
//!    is closed and `OWNER_SUBJECTS` is inert from then on.
//! 2. Otherwise resolve every entry against `users`. An entry is either a canonical
//!    user id (a UUID) or an e-mail address.
//! 3. If fewer than [`MIN_OWNERS`] resolve, seat NOBODY. A fund of one cannot admit a
//!    second owner — admission needs a non-empty "every owner but the initiator" — so
//!    seating one person would build a dead end, not a start.
//! 4. Otherwise seat everyone who resolved, in one transaction, through the same write
//!    path `SetRole` uses, so each of them gets a `user_outbox` `ROLE_CHANGED` row.
//!    That row is what mirrors the seat into the money plane.
//!
//! # Why e-mail is accepted, and why a missing one is not an error
//!
//! A canonical user id does not exist until its owner has signed in at least once, so
//! a UUID-only list could only ever be filled in AFTER the fact — by reading production
//! SQL. An operator knows the mailboxes up front, so the intended workflow is: write
//! the three addresses into `OWNER_SUBJECTS` before anyone has logged in, let the
//! founders sign in whenever they get round to it, and genesis fires on the first boot
//! at which at least two of them resolve. An address with no row yet is therefore the
//! EXPECTED state, logged at `info`; a UUID with no row is a typo, because an id can
//! only have been copied from a row that exists.
//!
//! # Why this can only ever happen once
//!
//! Not because anything here remembers that it ran, but because step 1 reads a state
//! that is irreversible. `users.role = 'owner'` can never return to zero: both
//! expulsion and `ResignOwnership` refuse to leave fewer than [`MIN_OWNERS`]
//! (`domain::governance::check_floor`). So a fourth id appended to the environment
//! after genesis buys nothing at all, and the emergency access in [`crate::authz`] —
//! which is gated on the same emptiness — is closed by the same act.

use domain::{
	error::DomainError,
	governance::MIN_OWNERS,
	users::{Email, UserId},
};
use uuid::Uuid;

use crate::ports::OwnerGenesisRepository;

/// One classified entry of `OWNER_SUBJECTS`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GenesisSubject {
	/// A concierge canonical user id. Only obtainable from a row that already exists.
	Id(UserId),
	/// A mailbox, normalized by [`Email::parse`] exactly as the directory normalizes
	/// the addresses it stores — so the two are comparable without a second convention.
	Mailbox(Email),
}

/// Classify the configured list. Anything that is not a UUID must be a valid mailbox;
/// a value that is neither is a typo, and a typo means the operator's intended roster
/// is not the one we would seat.
pub fn classify(raw: &[String]) -> Result<Vec<GenesisSubject>, String> {
	raw.iter()
		.map(|entry| {
			let entry = entry.trim();
			match Uuid::parse_str(entry) {
				Ok(id) => Ok(GenesisSubject::Id(UserId::from_raw(id))),
				Err(_) => Email::parse(entry).map(GenesisSubject::Mailbox).map_err(|_| entry.to_owned()),
			}
		})
		.collect()
}

/// What resolving the list against the directory produced. Deduplicated by user id, so
/// naming the same person by both id and mailbox counts once.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Resolution {
	/// Entries that named an existing user.
	pub found: Vec<UserId>,
	/// Configured ids with no `users` row — a wrong UUID.
	pub missing_ids: Vec<UserId>,
	/// Configured mailboxes nobody has signed in with yet. The ordinary waiting state.
	pub missing_mailboxes: Vec<Email>,
}

/// The branch genesis took. Returned rather than only logged, so each one is
/// assertable in a test.
#[derive(Debug, Eq, PartialEq)]
pub enum GenesisOutcome {
	/// `OWNER_SUBJECTS` is empty — nothing was even looked up.
	Unconfigured,
	/// An entry is neither a UUID nor a mailbox. Nobody is seated: a partially
	/// understood roster is not the roster the operator meant.
	Malformed { entry: String },
	/// The registry already holds owners. The permanent end state.
	Closed { owners: i64 },
	/// A configured mailbox matches more than one user. Refuse to guess which.
	Ambiguous { mailbox: Email, matches: i64 },
	/// Fewer than [`MIN_OWNERS`] resolved — nobody seated, retried next boot.
	TooFew(Resolution),
	/// Every resolved subject now holds a seat.
	Seated(Resolution),
}

/// Run genesis and narrate it. Only a control-plane failure is an `Err`; every policy
/// outcome — including a refusal — is an `Ok`, because none of them should keep the
/// plane from booting. Genesis is retried, unchanged, on the next start.
pub async fn seed(repo: &dyn OwnerGenesisRepository, subjects: &[String]) -> Result<GenesisOutcome, DomainError> {
	if subjects.is_empty() {
		tracing::info!("OWNER_SUBJECTS is empty — no genesis roster configured");
		return Ok(GenesisOutcome::Unconfigured);
	}
	let classified = match classify(subjects) {
		Ok(classified) => classified,
		Err(entry) => {
			tracing::error!(%entry, "OWNER_SUBJECTS holds an entry that is neither a user id nor an e-mail — seating nobody");
			return Ok(GenesisOutcome::Malformed { entry });
		}
	};

	let outcome = repo.seed_owners(&classified).await?;
	match &outcome {
		GenesisOutcome::Closed { owners } => {
			tracing::info!(owners, "owner genesis is closed — the registry is already populated and OWNER_SUBJECTS is inert");
		}
		GenesisOutcome::Ambiguous { mailbox, matches } => {
			tracing::error!(%mailbox, matches, "an OWNER_SUBJECTS e-mail matches more than one user — seating nobody; name these founders by user id instead");
		}
		GenesisOutcome::TooFew(resolution) => {
			report_unresolved(resolution);
			tracing::warn!(
				resolved = resolution.found.len(),
				required = MIN_OWNERS,
				"owner genesis did not run: a fund seated with fewer than {MIN_OWNERS} owners could never admit another, because admission requires a non-empty set of owners other than the initiator. \
				 Add the missing entries — or wait for those founders' first sign-in — and restart."
			);
		}
		GenesisOutcome::Seated(resolution) => {
			report_unresolved(resolution);
			for id in &resolution.found {
				tracing::info!(user_id = %id, "owner genesis seated a founder");
			}
			tracing::info!(owners = resolution.found.len(), "owner genesis complete — OWNER_SUBJECTS is inert from now on");
		}
		GenesisOutcome::Unconfigured | GenesisOutcome::Malformed { .. } => {}
	}
	Ok(outcome)
}

/// Name every unresolved entry individually — a roster the operator cannot see is a
/// roster they cannot fix.
fn report_unresolved(resolution: &Resolution) {
	for id in &resolution.missing_ids {
		tracing::warn!(user_id = %id, "OWNER_SUBJECTS names a user id with no record — a canonical id only exists once its owner has signed in, so this one is a typo");
	}
	for mailbox in &resolution.missing_mailboxes {
		tracing::info!(%mailbox, "OWNER_SUBJECTS names an address that has never signed in — genesis waits for them");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_entry_is_a_user_id_or_a_mailbox() {
		let id = Uuid::new_v4();
		let classified = classify(&[id.to_string(), "Founder@Example.COM".into()]).expect("both forms are legal");
		assert_eq!(classified[0], GenesisSubject::Id(UserId::from_raw(id)));
		// The mailbox is normalized by the SAME parser the directory stores through, so
		// a differently-cased env value still matches the stored row.
		assert_eq!(classified[1], GenesisSubject::Mailbox(Email::parse("founder@example.com").unwrap()));
	}

	#[test]
	fn surrounding_whitespace_is_not_part_of_an_entry() {
		let id = Uuid::new_v4();
		let classified = classify(&[format!("  {id}  ")]).expect("a padded id is still an id");
		assert_eq!(classified[0], GenesisSubject::Id(UserId::from_raw(id)));
	}

	#[test]
	fn a_value_that_is_neither_is_named_rather_than_ignored() {
		let bad = classify(&["not-a-uuid-or-a-mailbox".into()]).unwrap_err();
		assert_eq!(bad, "not-a-uuid-or-a-mailbox", "the refusal has to name the entry the operator must fix");
	}
}
