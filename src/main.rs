mod parser;
mod operations;
mod verify;
mod bitcoin;

use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        // ots-verify --help
        2 if args[1] == "--help" || args[1] == "-h" => {
            print_usage();
        }
        // ots-verify --info <proof.ots>
        3 if args[1] == "--info" => {
            run_info(&args[2]);
        }
        // ots-verify <file> <proof.ots>
        3 => {
            run_verify(&args[1], &args[2]);
        }
        _ => {
            eprintln!("Usage: ots-verify <file> <proof.ots>");
            eprintln!("       ots-verify --info <proof.ots>");
            eprintln!("       ots-verify --help");
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!("ots-verify — Standalone OpenTimestamps proof verifier");
    println!();
    println!("USAGE:");
    println!("  ots-verify <file> <proof.ots>    Verify a file against its .ots proof");
    println!("  ots-verify --info <proof.ots>    Display proof structure (no network)");
    println!("  ots-verify --help                Show this help");
    println!();
    println!("EXAMPLES:");
    println!("  ots-verify document.pdf document.pdf.ots");
    println!("  ots-verify content-hash.txt proof.ots");
    println!("  ots-verify --info proof.ots");
    println!();
    println!("Verifies .ots proofs by parsing the binary format from scratch,");
    println!("replaying hash operations, and checking against Bitcoin block headers");
    println!("via the Blockstream.info API (with mempool.space fallback).");
}

/// --info mode: parse and display proof structure without network access.
fn run_info(ots_path: &str) {
    let ots_data = read_file_or_exit(ots_path);

    match verify::parse_only(&ots_data) {
        Ok(ots) => {
            println!("Proof structure for: {}", ots_path);
            println!();
            parser::print_info(&ots);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

/// Verify mode: hash the input file and check against Bitcoin.
fn run_verify(file_path: &str, ots_path: &str) {
    let file_data = read_file_or_exit(file_path);
    let ots_data = read_file_or_exit(ots_path);

    let results = match verify::verify_file(&file_data, &ots_data) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    if results.is_empty() {
        println!("Warning: proof contains no attestations.");
        process::exit(1);
    }

    let mut any_verified = false;
    let mut any_failed = false;

    for result in &results {
        match result {
            verify::VerifyResult::BitcoinVerified { height, block_hash, timestamp } => {
                any_verified = true;
                let dt = format_unix_timestamp(*timestamp);
                println!();
                println!("  Verified! Data existed before Bitcoin block #{}", height);
                println!("  Block time: {}", dt);
                println!("  Block hash: {}", block_hash);
                println!("  Merkle root match confirmed");
            }
            verify::VerifyResult::Pending { uri } => {
                println!();
                println!("  Pending — proof not yet anchored to Bitcoin");
                println!("  Calendar: {}", uri);
            }
            verify::VerifyResult::Failed { height, expected, got } => {
                any_failed = true;
                println!();
                println!("  Verification FAILED — merkle root mismatch at block #{}", height);
                println!("  Expected: {}", parser::hex(expected));
                println!("  Got:      {}", parser::hex(got));
            }
            verify::VerifyResult::Skipped { reason } => {
                println!();
                println!("  Skipped: {}", reason);
            }
            verify::VerifyResult::Error { message } => {
                println!();
                println!("  Error: {}", message);
            }
        }
    }

    println!();

    if any_failed {
        process::exit(1);
    } else if !any_verified {
        // No failures but also no successful Bitcoin verifications
        process::exit(0);
    }
}

/// Read a file or print an error and exit.
fn read_file_or_exit(path: &str) -> Vec<u8> {
    match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading '{}': {}", path, e);
            process::exit(1);
        }
    }
}

/// Format a Unix timestamp as a human-readable UTC string.
///
/// We do this by hand to avoid pulling in the `chrono` crate.
fn format_unix_timestamp(ts: u64) -> String {
    // Days from Unix epoch to each month start (non-leap year)
    const DAYS_TO_MONTH: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let secs = ts;
    let days_total = (secs / 86400) as u32;
    let time_of_day = (secs % 86400) as u32;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Compute year and day-of-year from days since epoch
    // Using the algorithm: count 400-year, 100-year, 4-year, 1-year cycles
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

    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", year, month, day, hours, minutes, seconds)
}

fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
