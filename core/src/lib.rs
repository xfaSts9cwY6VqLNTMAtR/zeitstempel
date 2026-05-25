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

/// Format a Unix epoch timestamp (seconds) as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Hand-rolled to avoid pulling in `chrono`. Used by both the CLI's
/// `verify` output and the GUI's result panel.
pub fn format_unix_utc(ts: u64) -> String {
    const DAYS_TO_MONTH: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let days_total = (ts / 86400) as u32;
    let time_of_day = (ts % 86400) as u32;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut remaining_days = days_total;
    let mut year: u32 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let mut month: u32 = 12;
    for m in (0..12).rev() {
        let mut d = DAYS_TO_MONTH[m];
        if m >= 2 && leap {
            d += 1;
        }
        if remaining_days >= d {
            month = (m + 1) as u32;
            remaining_days -= d;
            break;
        }
    }
    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
}

fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
