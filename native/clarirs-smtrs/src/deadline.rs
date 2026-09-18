//! Wall-clock deadlines for smtrs, which only knows a cooperative terminate
//! flag: one watchdog thread per process sets the flag when a query's
//! deadline passes.
//!
//! A deadline is armed for the duration of an [`Armed`] guard. Dropping the
//! guard bumps the engine's generation token, so a deadline that fires late
//! (after the query it was armed for returned) sees a stale generation and
//! leaves the flag alone; the next query starts from a cleared flag.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

struct Entry {
    at: Instant,
    flag: Arc<AtomicBool>,
    token: Arc<AtomicU64>,
    generation: u64,
}

// Ordered by deadline only, earliest first out of a max-heap.
impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.at.cmp(&self.at)
    }
}

static WATCHDOG: OnceLock<Mutex<Sender<Entry>>> = OnceLock::new();

fn watchdog() -> &'static Mutex<Sender<Entry>> {
    WATCHDOG.get_or_init(|| {
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("clarirs-smtrs-deadline".into())
            .spawn(move || run(rx))
            .expect("spawn deadline watchdog thread");
        Mutex::new(tx)
    })
}

fn run(rx: Receiver<Entry>) {
    let mut pending: BinaryHeap<Entry> = BinaryHeap::new();
    loop {
        let wait = match pending.peek() {
            Some(next) => next.at.saturating_duration_since(Instant::now()),
            None => Duration::from_secs(3600),
        };
        match rx.recv_timeout(wait) {
            Ok(entry) => pending.push(entry),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        while pending.peek().is_some_and(|e| e.at <= now) {
            let e = pending.pop().expect("peeked");
            if e.token.load(AtomicOrdering::Acquire) == e.generation {
                e.flag.store(true, AtomicOrdering::Release);
            }
        }
    }
}

/// An armed deadline; dropping it disarms.
pub(crate) struct Armed {
    token: Arc<AtomicU64>,
}

impl Drop for Armed {
    fn drop(&mut self) {
        self.token.fetch_add(1, AtomicOrdering::AcqRel);
    }
}

/// Clear `flag` and arrange for it to be set `timeout` from now unless the
/// returned guard is dropped first.
pub(crate) fn arm(flag: &Arc<AtomicBool>, token: &Arc<AtomicU64>, timeout: Duration) -> Armed {
    let generation = token.fetch_add(1, AtomicOrdering::AcqRel) + 1;
    flag.store(false, AtomicOrdering::Release);
    let entry = Entry {
        at: Instant::now() + timeout,
        flag: flag.clone(),
        token: token.clone(),
        generation,
    };
    // A poisoned lock only means a sender panicked mid-send; the channel is
    // still usable.
    let tx = watchdog().lock().unwrap_or_else(|e| e.into_inner());
    // The receiver lives for the process; a failed send means the watchdog
    // thread is gone, in which case the query simply runs unbounded.
    let _ = tx.send(entry);
    Armed {
        token: token.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_after_the_timeout() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = Arc::new(AtomicU64::new(0));
        let armed = arm(&flag, &token, Duration::from_millis(20));
        let start = Instant::now();
        while !flag.load(AtomicOrdering::Acquire) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "deadline never fired"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(armed);
    }

    #[test]
    fn disarmed_deadlines_do_not_fire() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = Arc::new(AtomicU64::new(0));
        drop(arm(&flag, &token, Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!flag.load(AtomicOrdering::Acquire));
    }

    #[test]
    fn rearming_clears_the_flag() {
        let flag = Arc::new(AtomicBool::new(true));
        let token = Arc::new(AtomicU64::new(0));
        let _armed = arm(&flag, &token, Duration::from_secs(60));
        assert!(!flag.load(AtomicOrdering::Acquire));
    }
}
