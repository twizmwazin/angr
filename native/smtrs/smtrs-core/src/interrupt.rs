//! The throttle every cooperative-interrupt poll shares.
//!
//! Three passes walk a large structure and must notice a terminate request
//! without checking an atomic on every node: the rewriter (`smtrs-rewrite`,
//! per node rewrite), the bit-blaster (`smtrs-bitblast`, per encoded node) and
//! the AIG's Tseitin emission (`smtrs-aig`, per worklist step). All three want
//! the same schedule, and it has one subtlety that is worth stating once
//! rather than three times.
//!
//! The counter is incremented **before** the test and the test is `== 1`, not
//! `== 0`. So the *first* step of a pass polls. Each pass resets its counter
//! when it begins, and a flag that was already set at that moment — the common
//! case, since the deadline usually expires during an earlier stage — is then
//! observed at the first node instead of [`POLL_PERIOD`] nodes later. Written
//! `== 0` the schedule looks identical and quietly loses that, which is
//! precisely the kind of difference three copies drift into.

/// Steps between two polls. One atomic load per 1024 units of work: frequent
/// enough that the response to a terminate request is milliseconds, rare
/// enough not to show up in a profile — the surrounding hashing dominates by
/// orders of magnitude. A power of two so the test is a mask.
pub const POLL_PERIOD: u32 = 1024;

/// Throttle for a cooperative-interrupt poll: advance it once per unit of
/// work and act only when it says so.
///
/// Wrapping is deliberate and harmless — the schedule is periodic, and a pass
/// long enough to wrap `u32` has polled four million times already.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PollTick(u32);

impl PollTick {
    /// A tick at the start of a pass: the next [`Self::due`] returns `true`.
    pub const fn new() -> PollTick {
        PollTick(0)
    }

    /// Advance one step. `true` once per [`POLL_PERIOD`] steps, **starting at
    /// the first step** — see the module docs for why that is load-bearing.
    #[inline]
    pub fn due(&mut self) -> bool {
        self.0 = self.0.wrapping_add(1);
        self.0 & (POLL_PERIOD - 1) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first step polls, and then every `POLL_PERIOD`th. A `== 0` test
    /// would move the whole sequence one step on and lose the first.
    #[test]
    fn the_first_step_polls() {
        let mut t = PollTick::new();
        assert!(
            t.due(),
            "a flag set before the pass began must be seen at once"
        );
        for _ in 1..POLL_PERIOD {
            assert!(!t.due());
        }
        assert!(t.due(), "and again exactly one period later");
    }

    /// A fresh tick behaves like a reset one, so a pass that restarts its
    /// throttle gets the same immediate first poll.
    #[test]
    fn a_reset_tick_polls_again_immediately() {
        let mut t = PollTick::new();
        for _ in 0..POLL_PERIOD + 7 {
            t.due();
        }
        t = PollTick::new();
        assert!(t.due());
    }

    /// The period is a power of two, or the mask in `due` is not the test the
    /// docs claim.
    #[test]
    fn the_period_is_a_power_of_two() {
        assert!(POLL_PERIOD.is_power_of_two());
    }
}
