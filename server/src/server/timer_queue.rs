use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::runtime::assets::content::Content;
use crate::runtime::server;
use crate::runtime::server::error::ServerError;
use crate::runtime::server::router::Router;
use crate::runtime::server::server::HttpServer;

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ScheduledTaskType {
    SyncDatabase,
    UpdateContent,
}
#[derive(Debug)]

pub struct ScheduledTask {
    delay: Duration,
    deadline: Instant,
    repeating: bool,
    expected_duration: Duration,
    typ: ScheduledTaskType,
}

impl PartialEq for ScheduledTask {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for ScheduledTask {}

impl PartialOrd for ScheduledTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledTask {
    fn cmp(&self, other: &Self) -> Ordering {
        other.deadline.cmp(&self.deadline)
    }
}

pub struct Scheduler {
    queue: BinaryHeap<ScheduledTask>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
        }
    }

    pub fn schedule(&mut self, typ: ScheduledTaskType, delay: Duration) {
        self.queue.push(ScheduledTask {
            delay,
            deadline: Instant::now() + delay,
            typ,
            repeating: false,
            expected_duration: Duration::ZERO,
        });
    }

    pub fn schedule_repeating(&mut self, typ: ScheduledTaskType, delay: Duration) {
        self.queue.push(ScheduledTask {
            delay,
            deadline: Instant::now() + delay,
            typ,
            repeating: true,
            expected_duration: Duration::ZERO,
        });
    }

    pub fn execute_due_tasks_with_budget(
        &mut self,
        server: &mut HttpServer,
        router: &mut Router,
        template_cache: &mut HashMap<String, String>,
        budget: Duration,
    ) -> Result<(), ServerError> {
        let mut out_of_budget = vec![];
        while let Some(task) = self.queue.peek()
            && task.deadline <= Instant::now()
        {
            let mut task = self.queue.pop().unwrap();
            if task.expected_duration >= budget {
                out_of_budget.push(task);
                // println!("skipped task because expected duration is not within budget");
                continue;
            }

            let task_duration_start = Instant::now();
            match task.typ {
                ScheduledTaskType::SyncDatabase => {
                    router.db.sync()?;
                }
                ScheduledTaskType::UpdateContent => {
                    if Content::check_update(router)? {
                        template_cache.clear();
                        server.reload_websockets();
                    }
                }
            }

            if task.repeating {
                let duration = task_duration_start.elapsed();

                task.expected_duration = compute_running_average_delay_bounded(
                    task.expected_duration,
                    duration,
                    Duration::from_secs(1),
                );
                task.deadline = Instant::now() + task.delay;
                self.queue.push(task);
            }
        }
        self.queue.extend(out_of_budget);

        Ok(())
    }
}

// Computes running average with fast ascend and slow decay
pub fn compute_running_average_delay_bounded(
    expected: Duration,
    actual: Duration,
    bound: Duration,
) -> Duration {
    if actual > bound {
        return bound;
    }
    let alpha = if actual > expected { 0.5 } else { 0.1 };

    Duration::from_secs_f64(expected.as_secs_f64() * (1.0 - alpha) + actual.as_secs_f64() * alpha)
}
