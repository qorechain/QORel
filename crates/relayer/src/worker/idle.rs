//! Idle shutdown of the packet workers.
//!
//! The packet command and clear command workers stop after a number of blocks
//! without IBC events; the supervisor spawns them again on the next event for
//! their channel. A worker must not stop while relaying work is unfinished,
//! for example when the last clearing round failed because an endpoint
//! rate-limited the relayer: nothing would retry the pending packets until a
//! new packet is sent on that channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::warn;

use crate::util::task::TaskError;

use super::RunError;

/// Shared by the tasks of one packet worker: set when a relay or clearing step
/// fails with a retryable error, reset when a clearing round succeeds.
#[derive(Clone, Debug, Default)]
pub struct RelayBacklog(Arc<AtomicBool>);

impl RelayBacklog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_unfinished(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn mark_cleared(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    pub fn is_unfinished(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Passes `result` through, recording a retryable failure as unfinished work.
    pub fn track<T>(
        &self,
        result: Result<T, TaskError<RunError>>,
    ) -> Result<T, TaskError<RunError>> {
        if let Err(TaskError::Ignore(_)) = &result {
            self.mark_unfinished();
        }
        result
    }
}

/// Counts blocks without IBC events and decides when a worker may stop.
#[derive(Debug)]
pub struct IdleTimer {
    idle_blocks: u64,
    limit: u64,
    holding: bool,
}

impl IdleTimer {
    pub fn new(limit: u64) -> Self {
        Self {
            idle_blocks: 0,
            limit,
            holding: false,
        }
    }

    /// Records one processed command and returns whether the worker may stop:
    /// only after more than `limit` blocks without IBC events, and never while
    /// `backlog` holds unfinished work.
    pub fn should_stop(&mut self, is_new_batch: bool, backlog: &RelayBacklog) -> bool {
        if is_new_batch {
            self.idle_blocks = 0;
        } else {
            self.idle_blocks += 1;
        }

        if self.idle_blocks <= self.limit {
            self.holding = false;
            return false;
        }

        if backlog.is_unfinished() {
            if !self.holding {
                warn!(
                    "worker idle for more than {} blocks but the last relay or clearing attempt failed; \
                     staying up to retry at the next clear interval",
                    self.limit
                );
                self.holding = true;
            }
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn retryable() -> Result<(), TaskError<RunError>> {
        Err(TaskError::Ignore(Box::new(RunError::relayer(
            Error::other("status: 429 Too Many Requests".to_string()),
        ))))
    }

    fn fatal() -> Result<(), TaskError<RunError>> {
        Err(TaskError::Fatal(Box::new(RunError::relayer(Error::other(
            "client expired".to_string(),
        )))))
    }

    #[test]
    fn stops_after_the_idle_limit_without_backlog() {
        let backlog = RelayBacklog::new();
        let mut timer = IdleTimer::new(3);
        for _ in 0..3 {
            assert!(!timer.should_stop(false, &backlog));
        }
        assert!(timer.should_stop(false, &backlog));
    }

    #[test]
    fn new_ibc_events_reset_the_idle_count() {
        let backlog = RelayBacklog::new();
        let mut timer = IdleTimer::new(2);
        assert!(!timer.should_stop(false, &backlog));
        assert!(!timer.should_stop(false, &backlog));
        assert!(!timer.should_stop(true, &backlog));
        assert!(!timer.should_stop(false, &backlog));
        assert!(!timer.should_stop(false, &backlog));
        assert!(timer.should_stop(false, &backlog));
    }

    #[test]
    fn stays_up_while_a_failed_clearing_left_packets_pending() {
        // The diana incident: clearing failed with 429s, no new packets came,
        // and the worker stopped with a packet still pending.
        let backlog = RelayBacklog::new();
        let mut timer = IdleTimer::new(5);
        assert!(backlog.track(retryable()).is_err());
        assert!(backlog.is_unfinished());

        for _ in 0..50 {
            assert!(!timer.should_stop(false, &backlog));
        }

        // The next clearing round succeeds: the worker may stop again.
        backlog.mark_cleared();
        assert!(timer.should_stop(false, &backlog));
    }

    #[test]
    fn only_retryable_failures_count_as_unfinished_work() {
        let backlog = RelayBacklog::new();
        assert!(backlog.track(Ok::<_, TaskError<RunError>>(7)).is_ok());
        assert!(!backlog.is_unfinished());

        // A fatal error stops the worker anyway (expired or frozen client).
        assert!(backlog.track(fatal()).is_err());
        assert!(!backlog.is_unfinished());

        assert!(backlog.track(retryable()).is_err());
        assert!(backlog.is_unfinished());
    }

    #[test]
    fn backlog_is_shared_between_the_worker_tasks() {
        let clear_task = RelayBacklog::new();
        let packet_task = clear_task.clone();
        let _ = packet_task.track(retryable());
        assert!(clear_task.is_unfinished());
        clear_task.mark_cleared();
        assert!(!packet_task.is_unfinished());
    }
}
