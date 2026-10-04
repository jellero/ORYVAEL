#![forbid(unsafe_code)]

#[path = "enforced.rs"]
mod core;

pub use core::*;

#[cfg(unix)]
pub mod service;
