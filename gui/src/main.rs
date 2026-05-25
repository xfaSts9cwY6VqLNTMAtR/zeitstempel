//! zeitstempel-gui — a tiny drop-target verifier for OpenTimestamps proofs.
//!
//! Drop a file in the left zone and its `.ots` in the right zone. The
//! result panel unrolls underneath with the Bitcoin block height,
//! confirmation timestamp, and block hash.
//!
//! v1 scope is verify-only. Stamp/upgrade live in the CLI.

#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::widget::{column, container, row, text, Space};
use iced::{
    Border, Color, Element, Length, Subscription, Task, Theme,
    event::{self, Event},
    window,
};

use zeitstempel::format_unix_utc;
use zeitstempel::verify::{self, VerifyResult};

const WINDOW_W: f32 = 480.0;
const WINDOW_H: f32 = 420.0;
const ZONE_H: f32 = 130.0;
const PANEL_H_MAX: f32 = 200.0;
const ANIM_DURATION_SECS: f32 = 0.28;

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

#[derive(Default)]
struct App {
    file_path: Option<PathBuf>,
    ots_path: Option<PathBuf>,
    status: Status,
    reveal: f32,
    last_tick: Option<Instant>,
}

#[derive(Default, Clone, Debug)]
enum Status {
    #[default]
    Idle,
    Verifying,
    Done(Outcome),
}

#[derive(Clone, Debug)]
enum Outcome {
    Verified { block: u64, when: String, hash: String },
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
}

impl App {
    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::FileDropped(path) => self.on_file_dropped(path),
            Message::Tick(now) => {
                self.step_animation(now);
                Task::none()
            }
            Message::VerifyDone(outcome) => {
                self.status = Status::Done(outcome);
                Task::none()
            }
        }
    }

    fn on_file_dropped(&mut self, path: PathBuf) -> Task<Message> {
        // Route by extension: .ots → proof slot; anything else → file slot.
        // Dropping a third file replaces the slot its extension implies.
        if path.extension().and_then(|e| e.to_str()) == Some("ots") {
            self.ots_path = Some(path);
        } else {
            self.file_path = Some(path);
        }

        // Reset any prior result and kick off verify once both slots are filled.
        if let (Some(file), Some(ots)) = (self.file_path.clone(), self.ots_path.clone()) {
            self.status = Status::Verifying;
            self.last_tick = Some(Instant::now());
            return Task::perform(verify_async(file, ots), Message::VerifyDone);
        }

        // Only one slot filled — wait quietly, no animation yet.
        Task::none()
    }

    fn step_animation(&mut self, now: Instant) {
        let dt = now.duration_since(self.last_tick.unwrap_or(now)).as_secs_f32();
        let target = if matches!(self.status, Status::Idle) { 0.0 } else { 1.0 };
        let speed = 1.0 / ANIM_DURATION_SECS;
        if self.reveal < target {
            self.reveal = (self.reveal + dt * speed).min(target);
        } else if self.reveal > target {
            self.reveal = (self.reveal - dt * speed).max(target);
        }
        self.last_tick = Some(now);
    }

    fn subscription(&self) -> Subscription<Message> {
        let drops = event::listen_with(|event, _status, _window| match event {
            Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
            _ => None,
        });

        let target = if matches!(self.status, Status::Idle) { 0.0 } else { 1.0 };
        let animating = (self.reveal - target).abs() > 0.001;

        if animating {
            Subscription::batch([
                drops,
                iced::time::every(Duration::from_millis(16)).map(Message::Tick),
            ])
        } else {
            drops
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let zones = row![
            drop_zone("File", self.file_path.as_deref(), false),
            drop_zone(".ots Proof", self.ots_path.as_deref(), true),
        ]
        .spacing(14);

        // Reveal panel height is driven by the eased animation progress.
        let panel_height = ease_out_cubic(self.reveal) * PANEL_H_MAX;
        let panel = container(self.result_view())
            .width(Length::Fill)
            .height(Length::Fixed(panel_height))
            .padding(if panel_height > 8.0 { 14 } else { 0 })
            .center_x(Length::Fill);

        column![header(), zones, panel]
            .spacing(14)
            .padding(20)
            .into()
    }

    fn result_view(&self) -> Element<'_, Message> {
        match &self.status {
            Status::Idle => Space::new().into(),
            Status::Verifying => column![
                text("Verifying against Bitcoin…").size(15).color(Color::from_rgb(0.3, 0.3, 0.3)),
                text("Live lookup via blockstream.info").size(11).color(Color::from_rgb(0.55, 0.55, 0.55)),
            ]
            .spacing(4)
            .into(),
            Status::Done(Outcome::Verified { block, when, hash }) => column![
                text("Verified").size(22).color(Color::from_rgb(0.15, 0.55, 0.25)),
                text(format!("Block #{block} · {when}")).size(13),
                text(short_hash(hash)).size(11).color(Color::from_rgb(0.4, 0.4, 0.4)),
            ]
            .spacing(6)
            .into(),
            Status::Done(Outcome::Failed { block }) => column![
                text("Merkle root mismatch").size(18).color(Color::from_rgb(0.7, 0.15, 0.15)),
                text(format!("Block #{block}: the proof does not match this file.")).size(12),
            ]
            .spacing(4)
            .into(),
            Status::Done(Outcome::Pending { host }) => column![
                text("Pending").size(18).color(Color::from_rgb(0.7, 0.5, 0.0)),
                text(format!("Calendar {host} has the proof but Bitcoin has not anchored it yet.")).size(12),
                text("Run `zeitstempel upgrade` later, then drop the upgraded .ots here.").size(11)
                    .color(Color::from_rgb(0.5, 0.5, 0.5)),
            ]
            .spacing(4)
            .into(),
            Status::Done(Outcome::Skipped { reason }) => column![
                text("Skipped").size(18).color(Color::from_rgb(0.4, 0.4, 0.4)),
                text(reason.clone()).size(12),
            ]
            .spacing(4)
            .into(),
            Status::Done(Outcome::Error { message }) => column![
                text("Error").size(18).color(Color::from_rgb(0.7, 0.15, 0.15)),
                text(message.clone()).size(12),
            ]
            .spacing(4)
            .into(),
        }
    }
}

fn header<'a>() -> Element<'a, Message> {
    column![
        text("zeitstempel").size(13).color(Color::from_rgb(0.4, 0.4, 0.4)),
        text("Drop a file and its .ots proof").size(11).color(Color::from_rgb(0.55, 0.55, 0.55)),
    ]
    .spacing(2)
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
        text(primary).size(13),
        text(secondary).size(10).color(Color::from_rgb(0.55, 0.55, 0.55)),
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
            let border_color = if filled {
                Color::from_rgb(0.30, 0.55, 0.85)
            } else {
                Color::from_rgb(0.78, 0.78, 0.80)
            };
            container::Style {
                border: Border {
                    color: border_color,
                    width: 1.5,
                    radius: 10.0.into(),
                },
                background: Some(iced::Background::Color(Color::from_rgb(0.985, 0.985, 0.99))),
                ..Default::default()
            }
        })
        .into()
}

fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

fn short_hash(hash: &str) -> String {
    if hash.len() <= 14 {
        return hash.to_string();
    }
    let head = &hash[..6];
    let tail = &hash[hash.len() - 6..];
    format!("Hash {head}…{tail}")
}

/// Run verify on a worker thread so the UI thread keeps animating.
async fn verify_async(file: PathBuf, ots: PathBuf) -> Outcome {
    let join = tokio::task::spawn_blocking(move || {
        let file_data = std::fs::read(&file).map_err(|e| format!("Read {}: {e}", file.display()))?;
        let ots_data = std::fs::read(&ots).map_err(|e| format!("Read {}: {e}", ots.display()))?;
        let results = verify::verify_file(&file_data, &ots_data)?;
        Ok::<Vec<VerifyResult>, String>(results)
    })
    .await;

    let results = match join {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Outcome::Error { message: e },
        Err(e) => return Outcome::Error { message: format!("worker panicked: {e}") },
    };

    summarize(&results)
}

/// Reduce a list of verify results into the single most-interesting outcome.
///
/// A verified Bitcoin anchor wins over everything; otherwise we surface the
/// most informative state in order failed > pending > skipped > error.
fn summarize(results: &[VerifyResult]) -> Outcome {
    for r in results {
        if let VerifyResult::BitcoinVerified { height, block_hash, timestamp } = r {
            return Outcome::Verified {
                block: *height,
                when: format_unix_utc(*timestamp),
                hash: block_hash.clone(),
            };
        }
    }
    for r in results {
        if let VerifyResult::Failed { height, .. } = r {
            return Outcome::Failed { block: *height };
        }
    }
    for r in results {
        if let VerifyResult::Pending { uri } = r {
            // Show just the host so an attacker-supplied URI in a
            // verified-but-mixed proof doesn't get a megaphone.
            let host = uri
                .strip_prefix("https://")
                .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
                .unwrap_or_else(|| uri.clone());
            return Outcome::Pending { host };
        }
    }
    for r in results {
        if let VerifyResult::Skipped { reason } = r {
            return Outcome::Skipped { reason: reason.clone() };
        }
    }
    for r in results {
        if let VerifyResult::Error { message } = r {
            return Outcome::Error { message: message.clone() };
        }
    }
    Outcome::Error {
        message: "proof contains no attestations".into(),
    }
}
