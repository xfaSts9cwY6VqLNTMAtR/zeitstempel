//! Zeitstempel — standalone OpenTimestamps library.
//!
//! Provides binary `.ots` parsing, hash-chain replay, calendar
//! interaction, and Bitcoin-anchor verification without depending on
//! the reference `python-opentimestamps` implementation.
//!
//! This library is consumed both by the `zeitstempel` CLI in this
//! same crate and by the sibling `zeitstempel-gui` crate.

pub mod bitcoin;
pub mod operations;
pub mod parser;
pub mod stamp;
pub mod upgrade;
pub mod verify;
pub mod writer;
