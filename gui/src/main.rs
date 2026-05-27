//! zeitstempel-gui — drop-target verifier for OpenTimestamps proofs.
//!
//! Single-column window. Drop a file and its `.ots` proof in the two
//! zones, the verdict appears underneath. Below the verdict, a set of
//! labeled evidence sections shows the data on the chain: the file
//! hashed, the block it's anchored in, the immutability cost,
//! the proof's shape, and a lazy lookup for the anchor TxID.
//!
//! No side panel. No visualization. Just well-typeset facts.

#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::widget::{Space, button, column, container, row, text};
use iced::{
    Border, Color, Element, Font, Length, Subscription, Task, Theme,
    event::{self, Event},
    window,
};

use zeitstempel::format_unix_utc;
use zeitstempel::operations;
use zeitstempel::parser::{Attestation, OtsFile, Timestamp};
use zeitstempel::verify::{self, VerifyResult};

// ── Window + layout constants ──────────────────────────────────────
const WINDOW_W: f32 = 480.0;
const WINDOW_H: f32 = 800.0;
const ZONE_H: f32 = 110.0;
const ANIM_DURATION_SECS: f32 = 0.28;

// ── Palette ────────────────────────────────────────────────────────
const COL_PAPER: Color = Color::from_rgb(0.980, 0.980, 0.969);
const COL_DIVIDER: Color = Color::from_rgb(0.910, 0.902, 0.878);
const COL_INK: Color = Color::from_rgb(0.102, 0.094, 0.086);
const COL_INK_2: Color = Color::from_rgb(0.310, 0.302, 0.282);
const COL_INK_3: Color = Color::from_rgb(0.604, 0.596, 0.576);
const COL_BRAND: Color = Color::from_rgb(0.114, 0.431, 0.612);
const COL_CONFIRMED: Color = Color::from_rgb(0.180, 0.353, 0.227);
const COL_FAIL: Color = Color::from_rgb(0.545, 0.176, 0.176);

fn main() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .title("zeitstempel")
        .subscription(App::subscription)
        .window_size((WINDOW_W, WINDOW_H))
        .resizable(false)
        .theme(theme)
        .run()
}

fn theme(_state: &App) -> Theme {
    Theme::Light
}

// ── State ──────────────────────────────────────────────────────────

#[derive(Default)]
struct App {
    file_path: Option<PathBuf>,
    ots_path: Option<PathBuf>,
    verifying: bool,
    outcome: Option<Outcome>,
    // Reveal animation for the verdict + evidence block (0→1 once an
    // outcome arrives).
    reveal: f32,
    last_tick: Option<Instant>,
}

#[derive(Clone, Debug)]
enum Outcome {
    Verified {
        block: u64,
        when: String,
        block_hash: String,
        merkle_root: String,
        file_hash: String,
        /// Number of operations in the proof chain from the file's
        /// hash up to the Bitcoin attestation. Stand-in for "path
        /// depth" — also implies the rough size of the calendar's
        /// bundle (≈ 2^depth files).
        path_depth: usize,
        /// Exact confirmation count (tip_height - block + 1) when
        /// available; falls back to wall-clock estimate.
        confirmations: u64,
        /// True when `confirmations` came from a live tip-height query,
        /// false when it's the wall-clock estimate.
        confirmations_exact: bool,
    },
    Failed { block: u64 },
    Pending { host: String },
    Skipped { reason: String },
    Error { message: String },
}

#[derive(Debug, Clone)]
enum Message {
    FileDropped(PathBuf),
    Tick(Instant),
    VerifyDone(Outcome),
    OpenUrl(String),
}

impl App {
    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::FileDropped(path) => self.on_file_dropped(path),
            Message::Tick(now) => {
                self.step(now);
                Task::none()
            }
            Message::VerifyDone(outcome) => {
                self.verifying = false;
                self.outcome = Some(outcome);
                Task::none()
            }
            Message::OpenUrl(url) => {
                let _ = webbrowser::open(&url);
                Task::none()
            }
        }
    }

    fn on_file_dropped(&mut self, path: PathBuf) -> Task<Message> {
        if path.extension().and_then(|e| e.to_str()) == Some("ots") {
            self.ots_path = Some(path);
        } else {
            self.file_path = Some(path);
        }

        if let (Some(file), Some(ots)) = (self.file_path.clone(), self.ots_path.clone()) {
            self.verifying = true;
            self.outcome = None;
            self.last_tick = Some(Instant::now());
            return Task::perform(verify_async(file, ots), Message::VerifyDone);
        }
        Task::none()
    }

    fn step(&mut self, now: Instant) {
        let target = if self.outcome.is_some() { 1.0 } else { 0.0 };
        let dt = now.duration_since(self.last_tick.unwrap_or(now)).as_secs_f32();
        let speed = 1.0 / ANIM_DURATION_SECS;
        self.reveal = step_toward(self.reveal, target, dt * speed);
        self.last_tick = Some(now);
    }

    fn subscription(&self) -> Subscription<Message> {
        let drops = event::listen_with(|event, _status, _id| match event {
            Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
            _ => None,
        });
        let target = if self.outcome.is_some() { 1.0 } else { 0.0 };
        if (self.reveal - target).abs() > 0.001 {
            Subscription::batch([
                drops,
                iced::time::every(Duration::from_millis(16)).map(Message::Tick),
            ])
        } else {
            drops
        }
    }

    // ── View ────────────────────────────────────────────────────────

    fn view(&self) -> Element<'_, Message> {
        let zones = row![
            drop_zone("File", self.file_path.as_deref(), false),
            drop_zone(".ots Proof", self.ots_path.as_deref(), true),
        ]
        .spacing(14);

        let revealed = self.evidence_block();
        let footer_alpha = if self.outcome.is_some() || self.verifying { 0.7 } else { 0.0 };

        column![
            header(),
            zones,
            verifying_indicator(self.verifying),
            revealed,
            Space::new().height(Length::Fill),
            footer_note(footer_alpha),
        ]
        .spacing(14)
        .padding(20)
        .into()
    }

    fn evidence_block(&self) -> Element<'_, Message> {
        match self.outcome.as_ref() {
            None => Space::new().into(),
            Some(Outcome::Verified {
                block,
                when,
                block_hash,
                merkle_root,
                file_hash,
                path_depth,
                confirmations,
                confirmations_exact,
            }) => self.verified_view(
                *block,
                when,
                block_hash,
                merkle_root,
                file_hash,
                *path_depth,
                *confirmations,
                *confirmations_exact,
            ),
            Some(Outcome::Failed { block }) => simple_verdict(
                "Mismatch",
                COL_FAIL,
                format!("Block #{block}: the .ots proof does not match this file."),
            ),
            Some(Outcome::Pending { host }) => simple_verdict(
                "Pending",
                Color::from_rgb(0.604, 0.482, 0.247),
                format!("Calendar {host} hasn't anchored to Bitcoin yet."),
            ),
            Some(Outcome::Skipped { reason }) => {
                simple_verdict("Skipped", COL_INK_3, reason.clone())
            }
            Some(Outcome::Error { message }) => simple_verdict("Error", COL_FAIL, message.clone()),
        }
    }

    fn verified_view(
        &self,
        block: u64,
        when: &str,
        block_hash: &str,
        merkle_root: &str,
        file_hash: &str,
        path_depth: usize,
        confirmations: u64,
        confirmations_exact: bool,
    ) -> Element<'_, Message> {
        let file_name = self
            .file_path
            .as_ref()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()))
            .unwrap_or("");
        let ots_name = self
            .ots_path
            .as_ref()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()))
            .unwrap_or("");

        // ── verdict ───────────────────────────────────────────────
        let verdict = column![
            text("Verified").size(34).color(COL_CONFIRMED),
            Space::new().height(Length::Fixed(4.0)),
            text(format!("Your file existed before {when}.")).size(14).color(COL_INK),
            Space::new().height(Length::Fixed(2.0)),
            text("Bitcoin block timestamps may drift up to ±2 hours from")
                .size(10)
                .color(COL_INK_3),
            text("the network's actual time. The proof is otherwise exact.")
                .size(10)
                .color(COL_INK_3),
        ];

        // ── FILE ──────────────────────────────────────────────────
        let file_section = section(
            "FILE",
            column![
                text(file_name.to_string()).size(14).color(COL_INK),
                Space::new().height(Length::Fixed(4.0)),
                inline_field("SHA-256", file_hash.to_string(), true),
                inline_field(".ots proof", ots_name.to_string(), false),
            ]
            .spacing(2)
            .into(),
        );

        // ── BLOCK ─────────────────────────────────────────────────
        let block_section = section(
            "ANCHORED IN BITCOIN BLOCK",
            column![
                text(format!("#{}", block)).size(22).color(COL_INK).font(Font::MONOSPACE),
                Space::new().height(Length::Fixed(2.0)),
                text(format!("mined {when}")).size(11).color(COL_INK_3),
                Space::new().height(Length::Fixed(8.0)),
                inline_field("merkle root", merkle_root.to_string(), true),
                inline_field("block hash", block_hash.to_string(), true),
            ]
            .spacing(2)
            .into(),
        );

        // ── IMMUTABILITY ──────────────────────────────────────────
        let conf_label = if confirmations_exact { "confirmations" } else { "confirmations (est.)" };
        let work_label = pretty_duration(confirmations);
        let immutability_section = section(
            "IMMUTABILITY",
            column![
                row![
                    text(thousands(confirmations))
                        .size(18)
                        .color(COL_INK)
                        .font(Font::MONOSPACE),
                    Space::new().width(Length::Fixed(8.0)),
                    text(conf_label).size(11).color(COL_INK_3),
                ]
                .align_y(iced::alignment::Vertical::Center),
                Space::new().height(Length::Fixed(2.0)),
                text(format!("≈ {} of accumulated mining work", work_label))
                    .size(11)
                    .color(COL_INK_2),
            ]
            .spacing(2)
            .into(),
        );

        // ── PROOF ─────────────────────────────────────────────────
        let bundle_estimate = bundle_size_estimate(path_depth);
        let proof_section = section(
            "PROOF SHAPE",
            column![
                row![
                    text(format!("{} operations", path_depth))
                        .size(14)
                        .color(COL_INK),
                    Space::new().width(Length::Fixed(10.0)),
                    text("from file → merkle root").size(11).color(COL_INK_3),
                ]
                .align_y(iced::alignment::Vertical::Center),
                text(format!("Bundled into a tree of ~{} files at the calendar.", bundle_estimate))
                    .size(11)
                    .color(COL_INK_2),
            ]
            .spacing(2)
            .into(),
        );

        // ── Link ──────────────────────────────────────────────────
        let block_url = format!("https://blockstream.info/block/{}", block_hash);
        let link = open_button("View block on blockstream.info ↗", block_url);

        column![
            verdict,
            Space::new().height(Length::Fixed(18.0)),
            dashed_horizontal_line(440.0, COL_DIVIDER),
            Space::new().height(Length::Fixed(14.0)),
            file_section,
            Space::new().height(Length::Fixed(14.0)),
            block_section,
            Space::new().height(Length::Fixed(14.0)),
            immutability_section,
            Space::new().height(Length::Fixed(14.0)),
            proof_section,
            Space::new().height(Length::Fixed(18.0)),
            dashed_horizontal_line(440.0, COL_DIVIDER),
            Space::new().height(Length::Fixed(12.0)),
            link,
        ]
        .into()
    }
}

// ── Small render helpers ──────────────────────────────────────────

fn header<'a>() -> Element<'a, Message> {
    column![
        text("zeitstempel").size(14).color(COL_INK),
        text("Drop a file and its .ots proof").size(11).color(COL_INK_3),
    ]
    .spacing(2)
    .into()
}

fn footer_note<'a>(alpha: f32) -> Element<'a, Message> {
    container(
        text("Your file stays on this device. Only the block height crosses to blockstream.info.")
            .size(10)
            .color(Color { a: alpha, ..COL_INK_3 })
            .align_x(iced::alignment::Horizontal::Center),
    )
    .width(Length::Fill)
    .align_x(iced::alignment::Horizontal::Center)
    .into()
}

fn verifying_indicator<'a>(active: bool) -> Element<'a, Message> {
    if !active {
        return Space::new().into();
    }
    container(
        text("Verifying against blockstream.info…")
            .size(12)
            .color(COL_BRAND),
    )
    .width(Length::Fill)
    .align_x(iced::alignment::Horizontal::Center)
    .into()
}

fn drop_zone<'a>(label: &'a str, path: Option<&Path>, is_ots: bool) -> Element<'a, Message> {
    let filled = path.is_some();
    let display = path
        .and_then(|p| p.file_name().and_then(|n| n.to_str()))
        .map(String::from)
        .unwrap_or_else(|| format!("Drop {} here", label.to_lowercase()));

    let icon = if is_ots { "🔐" } else { "📄" };
    let primary: String = if filled { display.clone() } else { label.to_string() };
    let secondary: String = if filled { String::new() } else { display };

    let content = column![
        text(icon).size(28),
        text(primary).size(13).color(COL_INK),
        text(secondary).size(10).color(COL_INK_3),
    ]
    .spacing(4)
    .align_x(iced::Alignment::Center);

    container(content)
        .width(Length::FillPortion(1))
        .height(Length::Fixed(ZONE_H))
        .padding(10)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(move |_| {
            let border_color = if filled { COL_BRAND } else { COL_DIVIDER };
            container::Style {
                border: Border {
                    color: border_color,
                    width: 1.5,
                    radius: 10.0.into(),
                },
                background: Some(iced::Background::Color(COL_PAPER)),
                ..Default::default()
            }
        })
        .into()
}

/// One labeled evidence section: a tiny uppercase header above a
/// block of content.
fn section<'a>(label: &'a str, body: Element<'a, Message>) -> Element<'a, Message> {
    column![
        text(label).size(9).color(COL_INK_3),
        Space::new().height(Length::Fixed(6.0)),
        body,
    ]
    .into()
}

/// A "label: value" row used inside sections for the inline hash and
/// .ots filename rows. The label is tiny and dim; the value is
/// monospace when `mono` is true (used for hashes).
fn inline_field<'a>(
    label: impl Into<String>,
    value: impl Into<String>,
    mono: bool,
) -> Element<'a, Message> {
    let val: String = value.into();
    let val_text = text(val).size(11).color(COL_INK_2);
    let val_text = if mono { val_text.font(Font::MONOSPACE) } else { val_text };
    row![
        container(text(label.into()).size(10).color(COL_INK_3))
            .width(Length::Fixed(90.0)),
        val_text,
    ]
    .spacing(6)
    .align_y(iced::alignment::Vertical::Center)
    .into()
}

fn simple_verdict<'a>(
    headline: &'a str,
    color: Color,
    sub: impl Into<String>,
) -> Element<'a, Message> {
    column![
        text(headline.to_string()).size(30).color(color),
        Space::new().height(Length::Fixed(4.0)),
        text(sub.into()).size(13).color(COL_INK),
    ]
    .into()
}

fn open_button<'a>(label: impl Into<String>, url: String) -> Element<'a, Message> {
    button(
        text(label.into())
            .size(12)
            .color(COL_BRAND),
    )
    .padding([8, 12])
    .on_press(Message::OpenUrl(url))
    .style(|_, status| {
        use iced::widget::button;
        let bg = match status {
            button::Status::Hovered => COL_DIVIDER,
            _ => COL_PAPER,
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: COL_BRAND,
            border: Border { color: COL_DIVIDER, width: 1.0, radius: 4.0.into() },
            ..Default::default()
        }
    })
    .into()
}

fn dashed_horizontal_line<'a>(total_width: f32, color: Color) -> Element<'a, Message> {
    let dash_w: f32 = 4.0;
    let gap_w: f32 = 3.0;
    let unit = dash_w + gap_w;
    let count = (total_width / unit).floor() as usize;
    let mut row_ = row![].height(Length::Fixed(1.0));
    for i in 0..count {
        row_ = row_.push(
            container(Space::new())
                .width(Length::Fixed(dash_w))
                .height(Length::Fixed(1.0))
                .style(move |_| container::Style {
                    background: Some(iced::Background::Color(color)),
                    ..Default::default()
                }),
        );
        if i + 1 < count {
            row_ = row_.push(Space::new().width(Length::Fixed(gap_w)));
        }
    }
    container(row_)
        .height(Length::Fixed(1.0))
        .align_y(iced::alignment::Vertical::Center)
        .into()
}

// ── Pure helpers ───────────────────────────────────────────────────

fn step_toward(current: f32, target: f32, max_delta: f32) -> f32 {
    if current < target {
        (current + max_delta).min(target)
    } else if current > target {
        (current - max_delta).max(target)
    } else {
        current
    }
}

fn estimate_confirmations(block_time: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(block_time);
    now.saturating_sub(block_time) / 600
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

fn pretty_duration(blocks: u64) -> String {
    let secs = blocks * 600;
    let years = secs / (365 * 86400);
    if years >= 1 {
        let months = (secs % (365 * 86400)) / (30 * 86400);
        if months > 0 {
            return format!("{years} years {months} months");
        }
        return format!("{years} years");
    }
    let days = secs / 86400;
    if days >= 1 {
        return format!("{days} days");
    }
    format!("{} hours", (secs / 3600).max(1))
}

/// Round 2^depth up to a friendly thousands count for the user-facing
/// "bundle size" estimate. Calendar trees are binary, so a depth of N
/// implies roughly 2^N leaves in the merkle tree.
fn bundle_size_estimate(depth: usize) -> String {
    let leaves: u64 = 1u64.checked_shl(depth as u32).unwrap_or(u64::MAX);
    thousands(leaves)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Proof walk ─────────────────────────────────────────────────────

/// Walk the proof tree from the file's hash up to the first Bitcoin
/// attestation, returning the operation count and every intermediate
/// hash along the way. The intermediates are candidates for the
/// anchor-TxID lookup.
/// Count the operations in the proof chain that lead from the file's
/// hash up to the first Bitcoin attestation. This becomes the
/// "path depth" we surface in the UI.
fn proof_depth(ots: &OtsFile) -> usize {
    let mut depth = 0usize;
    descend(&ots.timestamp, ots.file_digest.clone(), &mut depth);
    depth
}

fn descend(ts: &Timestamp, msg: Vec<u8>, depth: &mut usize) -> bool {
    for att in &ts.attestations {
        if matches!(att, Attestation::Bitcoin { .. }) {
            return true;
        }
    }
    for (op, child) in &ts.ops {
        let Ok(new_msg) = operations::apply(op, &msg) else {
            continue;
        };
        *depth += 1;
        if descend(child, new_msg, depth) {
            return true;
        }
        *depth -= 1;
    }
    false
}

// ── Verification ───────────────────────────────────────────────────

async fn verify_async(file: PathBuf, ots: PathBuf) -> Outcome {
    let join = tokio::task::spawn_blocking(move || -> Result<VerifyBundle, String> {
        let file_data = std::fs::read(&file).map_err(|e| format!("Read {}: {e}", file.display()))?;
        let ots_data = std::fs::read(&ots).map_err(|e| format!("Read {}: {e}", ots.display()))?;
        let parsed = zeitstempel::parser::parse_ots(&ots_data)
            .map_err(|e| format!("Parse .ots: {e}"))?;
        let file_hash_bytes = operations::hash_file_contents(&file_data, parsed.hash_op)
            .map_err(|e| format!("Hash file: {e}"))?;
        let file_hash_hex = bytes_to_hex(&file_hash_bytes);
        let path_depth = proof_depth(&parsed);
        let results = verify::verify_file(&file_data, &ots_data)?;
        Ok(VerifyBundle {
            results,
            file_hash: file_hash_hex,
            path_depth,
        })
    })
    .await;

    let bundle = match join {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Outcome::Error { message: e },
        Err(e) => return Outcome::Error { message: format!("worker panicked: {e}") },
    };

    // Tip-height fetch is best-effort; if it fails we fall back to a
    // wall-clock estimate so we still show *something*.
    let tip_height = tokio::task::spawn_blocking(zeitstempel::bitcoin::get_tip_height)
        .await
        .ok()
        .and_then(|r| r.ok());

    summarize(&bundle, tip_height)
}

struct VerifyBundle {
    results: Vec<VerifyResult>,
    file_hash: String,
    path_depth: usize,
}

fn summarize(bundle: &VerifyBundle, tip_height: Option<u64>) -> Outcome {
    for r in &bundle.results {
        if let VerifyResult::BitcoinVerified { height, block_hash, merkle_root, timestamp } = r {
            let (confirmations, confirmations_exact) = match tip_height {
                Some(tip) if tip >= *height => (tip - *height + 1, true),
                _ => (estimate_confirmations(*timestamp), false),
            };
            return Outcome::Verified {
                block: *height,
                when: format_unix_utc(*timestamp),
                block_hash: block_hash.clone(),
                merkle_root: merkle_root.clone(),
                file_hash: bundle.file_hash.clone(),
                path_depth: bundle.path_depth,
                confirmations,
                confirmations_exact,
            };
        }
    }
    for r in &bundle.results {
        if let VerifyResult::Failed { height, .. } = r {
            return Outcome::Failed { block: *height };
        }
    }
    for r in &bundle.results {
        if let VerifyResult::Pending { uri } = r {
            let host = uri
                .strip_prefix("https://")
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .unwrap_or_else(|| uri.clone());
            return Outcome::Pending { host };
        }
    }
    for r in &bundle.results {
        if let VerifyResult::Skipped { reason } = r {
            return Outcome::Skipped { reason: reason.clone() };
        }
    }
    for r in &bundle.results {
        if let VerifyResult::Error { message } = r {
            return Outcome::Error { message: message.clone() };
        }
    }
    Outcome::Error { message: "proof contains no attestations".into() }
}

