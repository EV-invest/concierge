//! Per-key single-flight: at most one in-flight operation per key inside THIS process.
//!
//! The two callers are the session refresh (two racing rotations of one refresh token
//! read as theft upstream) and `/kyc/start` (two racing starts buy two paid vendor
//! sessions). Both need the same thing — "the second caller waits for the first and then
//! re-reads" — and neither wants a database lock, because what they hold it across is a
//! network round trip.
//!
//! ponytail: in-process, so correct for one replica. Going multi-replica means a
//! distributed lock (`SET NX`) for both callers at once; the map is the one place to
//! swap it.

use std::{collections::HashMap, hash::Hash, sync::Arc};

use tokio::sync::{Mutex, OwnedMutexGuard};

pub(super) struct KeyedLocks<K> {
	locks: Mutex<HashMap<K, Arc<Mutex<()>>>>,
}

impl<K: Hash + Eq> Default for KeyedLocks<K> {
	fn default() -> Self {
		Self { locks: Mutex::new(HashMap::new()) }
	}
}

impl<K: Hash + Eq> KeyedLocks<K> {
	/// Wait for the key's turn. The guard is what holds the turn: keep it alive across
	/// everything that must not interleave with another caller on the same key.
	pub(super) async fn acquire(&self, key: K) -> OwnedMutexGuard<()> {
		let lock = {
			let mut locks = self.locks.lock().await;
			// The owned guard keeps its `Arc` alive, so a count of one means nobody holds
			// or awaits the key — reaping here bounds the map by in-flight keys, not by
			// every key ever seen.
			locks.retain(|_, l| Arc::strong_count(l) > 1);
			locks.entry(key).or_default().clone()
		};
		lock.lock_owned().await
	}
}
