#![forbid(unsafe_code)]
//! Compatibility import path for local tooling. The normal Gateway crate owns
//! the only ordinary implementation; this crate has no router, database or runtime.
pub use pushgo_gateway::ordinary::*;
