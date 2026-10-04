#![deny(unsafe_code)]

#[path = "enforced.rs"]
mod core;

pub use core::*;

#[cfg(unix)]
#[allow(unsafe_code)]
mod peercred;

#[cfg(unix)]
pub mod service;
