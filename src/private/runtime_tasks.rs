#[path = "runtime_tasks/fallback.rs"]
mod runtime_tasks_fallback;
#[path = "runtime_tasks/scheduler.rs"]
mod runtime_tasks_scheduler;

#[allow(unused_imports)]
use self::runtime_tasks_fallback::{AttemptBudget, FallbackAttemptPolicy};
use self::runtime_tasks_fallback::FallbackRuntime;
use self::runtime_tasks_scheduler::FallbackScheduler;
