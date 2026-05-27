//! zeitstempel-gui — drop-target verifier for OpenTimestamps proofs.
//!
//! Editorial-trust aesthetic: serif headlines, hand-typeset evidence
//! rows, color used only for state. Window resizes with state to
//! avoid the "empty box" feel — compact when waiting for input,
//! taller when there's a result to show.

#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::widget::{Space, button, column, container, row, text};
use iced::{
    Border, Color, Element, Font, Length, Subscription, Task, Theme,
    event::{self, Event},
    font::{Family, Style, Stretch, Weight},
    window,
};

use zeitstempel::format_unix_utc;
use zeitstempel::operations;
use zeitstempel::parser::{Attestation, OtsFile, Timestamp};
use zeitstempel::verify::{self, VerifyResult};

// ── Window sizes per state ────────────────────────────────────────
const WINDOW_W: f32 = 480.0;
const WINDOW_H_EMPTY: f32 = 400.0;
const WINDOW_H_VERIFYING: f32 = 400.0;
const WINDOW_H_VERIFIED: f32 = 780.0;
const WINDOW_H_FAILED: f32 = 520.0;
const WINDOW_H_OTHER: f32 = 460.0;
const ANIM_DURATION_SECS: f32 = 0.28;

// ── Palette ───────────────────────────────────────────────────────
const COL_PAPER:      Color = Color::from_rgb(0.984, 0.980, 0.969); // #FBFAF7
const COL_INK:        Color = Color::from_rgb(0.102, 0.094, 0.086); // #1A1816
const COL_INK_2:      Color = Color::from_rgb(0.353, 0.341, 0.318); // #5A5751
const COL_INK_3:      Color = Color::from_rgb(0.545, 0.529, 0.514); // #8B8783
const COL_HAIRLINE:   Color = Color::from_rgb(0.910, 0.898, 0.871); // #E8E5DE
const COL_HAIRLINE_2: Color = Color::from_rgb(0.835, 0.824, 0.788); // #D5D2C9
const COL_VERIFIED:   Color = Color::from_rgb(0.165, 0.482, 0.278); // #2A7B47
const COL_FAILED:     Color = Color::from_rgb(0.659, 0.196, 0.196); // #A83232
const COL_HOVER_BG:   Color = Color::from_rgb(0.941, 0.929, 0.898); // #F0EDE5

// ── Type scale (Pixels) ───────────────────────────────────────────
const T_VERDICT:  f32 = 52.0;
const T_H1:       f32 = 28.0;
const T_TAGLINE:  f32 = 20.0;
const T_BODY:     f32 = 13.5;
const T_META:     f32 = 11.5;
const T_MONO:     f32 = 11.5;
const T_FOOTNOTE: f32 = 11.0;

// ── Fonts ─────────────────────────────────────────────────────────
//
// Three families are bundled as TTFs and loaded at app start. The
// `Font::with_name` lookups below match the family-name strings
// embedded in those files. Variable fonts cover all weights/styles
// in a single file each.

const NEWSREADER_BYTES:          &[u8] = include_bytes!("../fonts/Newsreader.ttf");
const NEWSREADER_ITALIC_BYTES:   &[u8] = include_bytes!("../fonts/Newsreader-Italic.ttf");
const DM_SANS_BYTES:             &[u8] = include_bytes!("../fonts/DMSans.ttf");
const JETBRAINS_MONO_BYTES:      &[u8] = include_bytes!("../fonts/JetBrainsMono.ttf");

fn newsreader(weight: Weight, italic: bool) -> Font {
    Font {
        family: Family::Name("Newsreader"),
        weight,
        stretch: Stretch::Normal,
        style: if italic { Style::Italic } else { Style::Normal },
    }
}

fn dm_sans(weight: Weight) -> Font {
    Font {
        family: Family::Name("DM Sans"),
        weight,
        stretch: Stretch::Normal,
        style: Style::Normal,
    }
}

fn jetbrains() -> Font {
    Font {
        family: Family::Name("JetBrains Mono"),
        weight: Weight::Normal,
        stretch: Stretch::Normal,
        style: Style::Normal,
    }
}

fn main() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .title("zeitstempel")
        .subscription(App::subscription)
        .font(NEWSREADER_BYTES)
        .font(NEWSREADER_ITALIC_BYTES)
        .font(DM_SANS_BYTES)
        .font(JETBRAINS_MONO_BYTES)
        .default_font(dm_sans(Weight::Normal))
        .window_size((WINDOW_W, WINDOW_H_EMPTY))
        .resizable(false)
        .theme(theme)
        .run()
}

fn theme(_state: &App) -> Theme {
    Theme::Light
}

// ── State ─────────────────────────────────────────────────────────

#[derive(Default)]
struct App {
    file_path: Option<PathBuf>,
    ots_path: Option<PathBuf>,
    verifying: bool,
    outcome: Option<Outcome>,
    /// Time the verify request started — used to drive the indicator
    /// bar's sweep animation.
    verifying_started: Option<Instant>,
    /// Latest tick time, used for delta-based animation stepping.
    last_tick: Option<Instant>,
    /// Reveal animation for the result block (0→1 once an outcome lands).
    reveal: f32,
    /// Captured at first WindowOpened so we can issue resize tasks.
    window_id: Option<window::Id>,
}

#[derive(Clone, Debug)]
enum Outcome {
    Verified {
        block: u64,
        when: String,
        block_hash: String,
        merkle_root: String,
        file_hash: String,
        path_depth: usize,
        confirmations: u64,
        confirmations_exact: bool,
    },
    Mismatch {
        file_hash: String,
        expected_hash: String,
    },
    Pending {
        host: String,
    },
    Skipped {
        reason: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone)]
enum Message {
    FileDropped(PathBuf),
    Tick(Instant),
    VerifyDone(Outcome),
    OpenUrl(String),
    CopyToClipboard(String),
    Reset,
    ExportPdf,
    WindowOpened(window::Id),
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
                self.resize_to_state()
            }
            Message::OpenUrl(url) => {
                let _ = webbrowser::open(&url);
                Task::none()
            }
            Message::CopyToClipboard(s) => iced::clipboard::write(s),
            Message::Reset => {
                self.file_path = None;
                self.ots_path = None;
                self.verifying = false;
                self.outcome = None;
                self.reveal = 0.0;
                self.verifying_started = None;
                self.resize_to_state()
            }
            Message::ExportPdf => {
                // Phase B will wire this. For now the button is silent.
                Task::none()
            }
            Message::WindowOpened(id) => {
                self.window_id = Some(id);
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
            let now = Instant::now();
            self.verifying_started = Some(now);
            self.last_tick = Some(now);
            return Task::batch([
                Task::perform(verify_async(file, ots), Message::VerifyDone),
                self.resize_to_state(),
            ]);
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
        let events = event::listen_with(|event, _status, id| match event {
            Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
            Event::Window(window::Event::Opened { .. }) => Some(Message::WindowOpened(id)),
            _ => None,
        });
        // Tick while either the reveal is in flight or a verify is
        // running (the indicator bar needs an animation clock).
        let target = if self.outcome.is_some() { 1.0 } else { 0.0 };
        let need_tick = (self.reveal - target).abs() > 0.001 || self.verifying;
        if need_tick {
            Subscription::batch([
                events,
                iced::time::every(Duration::from_millis(16)).map(Message::Tick),
            ])
        } else {
            events
        }
    }

    fn resize_to_state(&self) -> Task<Message> {
        let Some(id) = self.window_id else {
            return Task::none();
        };
        let h = self.target_height();
        window::resize(id, iced::Size::new(WINDOW_W, h))
    }

    fn target_height(&self) -> f32 {
        if self.verifying {
            WINDOW_H_VERIFYING
        } else {
            match self.outcome.as_ref() {
                None => WINDOW_H_EMPTY,
                Some(Outcome::Verified { .. }) => WINDOW_H_VERIFIED,
                Some(Outcome::Mismatch { .. }) => WINDOW_H_FAILED,
                Some(_) => WINDOW_H_OTHER,
            }
        }
    }

    // ── View ────────────────────────────────────────────────────────

    fn view(&self) -> Element<'_, Message> {
        let body: Element<'_, Message> = if self.verifying {
            self.view_verifying()
        } else {
            match self.outcome.as_ref() {
                None => self.view_empty(),
                Some(Outcome::Verified { .. }) => self.view_verified(),
                Some(Outcome::Mismatch { .. }) => self.view_mismatch(),
                Some(Outcome::Pending { host }) => self.view_simple(
                    "Pending.",
                    COL_INK_2,
                    format!("Calendar {host} hasn't anchored to Bitcoin yet."),
                ),
                Some(Outcome::Skipped { reason }) => {
                    self.view_simple("Skipped.", COL_INK_3, reason.clone())
                }
                Some(Outcome::Error { message }) => self.view_simple("Error.", COL_FAILED, message.clone()),
            }
        };

        container(body)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding([24, 32])
            .style(|_| container::Style {
                background: Some(iced::Background::Color(COL_PAPER)),
                ..Default::default()
            })
            .into()
    }

    fn view_empty(&self) -> Element<'_, Message> {
        column![
            Space::new().height(Length::Fixed(6.0)),
            hero(),
            Space::new().height(Length::Fixed(20.0)),
            drop_zones(self.file_path.as_deref(), self.ots_path.as_deref()),
            Space::new().height(Length::Fill),
            footer_note(),
        ]
        .spacing(0)
        .into()
    }

    fn view_verifying(&self) -> Element<'_, Message> {
        let pulse_phase = pulse_phase(self.verifying_started);
        column![
            drop_zones(self.file_path.as_deref(), self.ots_path.as_deref()),
            Space::new().height(Length::Fixed(8.0)),
            verifying_indicator(pulse_phase),
            Space::new().height(Length::Fill),
            footer_note(),
        ]
        .spacing(0)
        .into()
    }

    fn view_verified(&self) -> Element<'_, Message> {
        let Some(Outcome::Verified {
            block,
            when,
            block_hash,
            merkle_root,
            file_hash,
            path_depth,
            confirmations,
            confirmations_exact,
            ..
        }) = self.outcome.as_ref()
        else {
            return Space::new().into();
        };

        let file_name = path_filename(self.file_path.as_deref()).unwrap_or("(file)");

        let actions = action_row(*block, block_hash.clone(), true);

        column![
            drop_zones_compact(self.file_path.as_deref(), self.ots_path.as_deref()),
            Space::new().height(Length::Fixed(20.0)),
            verdict(false, "Verified.", &verified_conclusion(when), Some(verified_footnote())),
            Space::new().height(Length::Fixed(22.0)),
            divider(),
            Space::new().height(Length::Fixed(18.0)),

            section("The file", column![
                evidence_row("name", text_value(file_name.to_string())),
                evidence_row("SHA-256", hash_value(file_hash.clone())),
            ]),
            Space::new().height(Length::Fixed(18.0)),
            section("The Bitcoin block", column![
                evidence_row("height", large_value(format!("#{}", block))),
                evidence_row("mined", muted_value(when.clone())),
                evidence_row("merkle root", hash_value(merkle_root.clone())),
                evidence_row("block hash", hash_value(block_hash.clone())),
            ]),
            Space::new().height(Length::Fixed(18.0)),
            section("Immutability", column![
                evidence_row(
                    if *confirmations_exact { "confirmations" } else { "confirmations (est.)" },
                    confirmations_value(*confirmations),
                ),
                evidence_row("work", muted_value(format!("≈ {} of accumulated mining", pretty_duration(*confirmations)))),
            ]),
            Space::new().height(Length::Fixed(18.0)),
            section("Proof shape", column![
                evidence_row("path depth", text_value(format!("{} operations from file to merkle root", path_depth))),
                evidence_row("bundle", muted_value(format!("~{} files at the calendar that day", thousands(1u64.checked_shl(*path_depth as u32).unwrap_or(u64::MAX))))),
            ]),

            Space::new().height(Length::Fixed(24.0)),
            actions,

            Space::new().height(Length::Fixed(20.0)),
            footer_note(),
        ]
        .spacing(0)
        .into()
    }

    fn view_mismatch(&self) -> Element<'_, Message> {
        let Some(Outcome::Mismatch { file_hash, expected_hash }) = self.outcome.as_ref() else {
            return Space::new().into();
        };
        let file_name = path_filename(self.file_path.as_deref()).unwrap_or("the dropped file");

        column![
            drop_zones_compact(self.file_path.as_deref(), self.ots_path.as_deref()),
            Space::new().height(Length::Fixed(20.0)),
            verdict(
                true,
                "Mismatch.",
                "This .ots proof was made for a different file.",
                Some(format!(
                    "The proof itself is valid — it just doesn't belong to {file_name}."
                )),
            ),
            Space::new().height(Length::Fixed(22.0)),
            divider(),
            Space::new().height(Length::Fixed(18.0)),
            section("What you dropped", column![
                evidence_row("file SHA-256", hash_value(file_hash.clone())),
                evidence_row(".ots expects", hash_value(expected_hash.clone())),
            ]),

            Space::new().height(Length::Fixed(24.0)),
            row![
                action_btn("Reset", Message::Reset),
            ].spacing(8).align_y(iced::Alignment::Center),

            Space::new().height(Length::Fill),
            footer_note(),
        ]
        .spacing(0)
        .into()
    }

    fn view_simple(
        &self,
        headline: &'static str,
        color: Color,
        sub: String,
    ) -> Element<'_, Message> {
        column![
            drop_zones_compact(self.file_path.as_deref(), self.ots_path.as_deref()),
            Space::new().height(Length::Fixed(28.0)),
            verdict_color(headline, color, sub, None),
            Space::new().height(Length::Fixed(24.0)),
            row![action_btn("Reset", Message::Reset)]
                .spacing(8)
                .align_y(iced::Alignment::Center),
            Space::new().height(Length::Fill),
            footer_note(),
        ]
        .spacing(0)
        .into()
    }
}

// ── Composed views ────────────────────────────────────────────────

fn hero<'a>() -> Element<'a, Message> {
    column![
        text("Prove when this file existed.")
            .size(T_TAGLINE)
            .color(COL_INK)
            .font(newsreader(Weight::Normal, true))
            .align_x(iced::alignment::Horizontal::Center),
        Space::new().height(Length::Fixed(8.0)),
        text("Drop a file and its .ots proof.")
            .size(12.5)
            .color(COL_INK_2)
            .font(dm_sans(Weight::Normal))
            .align_x(iced::alignment::Horizontal::Center),
    ]
    .width(Length::Fill)
    .align_x(iced::Alignment::Center)
    .into()
}

fn drop_zones<'a>(
    file: Option<&Path>,
    ots: Option<&Path>,
) -> Element<'a, Message> {
    row![
        drop_zone(file, false, 138.0),
        drop_zone(ots, true, 138.0),
    ]
    .spacing(14)
    .into()
}

fn drop_zones_compact<'a>(
    file: Option<&Path>,
    ots: Option<&Path>,
) -> Element<'a, Message> {
    row![
        drop_zone(file, false, 60.0),
        drop_zone(ots, true, 60.0),
    ]
    .spacing(14)
    .into()
}

fn drop_zone<'a>(path: Option<&Path>, is_ots: bool, height: f32) -> Element<'a, Message> {
    let filled = path.is_some();
    let filename = path_filename(path).map(String::from);

    let glyph: Element<'a, Message> = if is_ots {
        text(".ots")
            .size(if height > 100.0 { 24.0 } else { 16.0 })
            .color(if filled { COL_INK } else { COL_INK_3 })
            .font(newsreader(Weight::Medium, true))
            .into()
    } else {
        text("\u{1D453}") // mathematical italic 'f'
            .size(if height > 100.0 { 28.0 } else { 20.0 })
            .color(if filled { COL_INK } else { COL_INK_3 })
            .font(newsreader(Weight::Medium, true))
            .into()
    };

    let content: Element<'a, Message> = if filled {
        let name = filename.unwrap_or_default();
        if height > 100.0 {
            column![
                glyph,
                Space::new().height(Length::Fixed(6.0)),
                text(name).size(10.5).color(COL_INK).font(jetbrains()),
            ]
            .align_x(iced::Alignment::Center)
            .into()
        } else {
            row![
                glyph,
                Space::new().width(Length::Fixed(10.0)),
                text(name).size(11.0).color(COL_INK).font(jetbrains()),
            ]
            .align_y(iced::Alignment::Center)
            .into()
        }
    } else {
        let label = if is_ots { "The proof" } else { "The file" };
        column![
            glyph,
            Space::new().height(Length::Fixed(4.0)),
            text(label).size(12.5).color(COL_INK_2).font(dm_sans(Weight::Medium)),
            Space::new().height(Length::Fixed(2.0)),
            text("drop here").size(11.0).color(COL_INK_3).font(dm_sans(Weight::Normal)),
        ]
        .align_x(iced::Alignment::Center)
        .into()
    };

    container(content)
        .width(Length::FillPortion(1))
        .height(Length::Fixed(height))
        .padding(10)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(move |_| {
            let border_color = if filled { COL_INK } else { COL_HAIRLINE_2 };
            container::Style {
                border: Border { color: border_color, width: 1.5, radius: 8.0.into() },
                background: Some(iced::Background::Color(if filled {
                    Color::from_rgb(1.0, 1.0, 1.0)
                } else {
                    Color::from_rgba(1.0, 1.0, 1.0, 0.55)
                })),
                ..Default::default()
            }
        })
        .into()
}

fn verifying_indicator<'a>(phase: f32) -> Element<'a, Message> {
    // phase is in [0, 1) — drives a 38%-wide bar sliding across a
    // 220-px track. We position the bar with a leading Space whose
    // width is interpolated each frame, and clip the parent.
    let bar_w: f32 = 220.0;
    let segment_w: f32 = bar_w * 0.38;
    let travel: f32 = bar_w + segment_w;
    let offset: f32 = (phase * travel) - segment_w;

    let track_inner = row![
        Space::new().width(Length::Fixed(offset.max(0.0))),
        container(Space::new())
            .width(Length::Fixed(segment_w))
            .height(Length::Fixed(2.0))
            .style(|_| container::Style {
                background: Some(iced::Background::Color(COL_INK)),
                ..Default::default()
            }),
    ]
    .align_y(iced::Alignment::Center);

    let track = container(track_inner)
        .width(Length::Fixed(bar_w))
        .height(Length::Fixed(2.0))
        .clip(true)
        .style(|_| container::Style {
            background: Some(iced::Background::Color(COL_HAIRLINE)),
            border: Border { color: Color::TRANSPARENT, width: 0.0, radius: 1.0.into() },
            ..Default::default()
        });

    column![
        text("verifying against the Bitcoin chain…")
            .size(15.0)
            .color(COL_INK_2)
            .font(newsreader(Weight::Normal, true))
            .align_x(iced::alignment::Horizontal::Center),
        Space::new().height(Length::Fixed(14.0)),
        container(track)
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center),
    ]
    .padding([16, 0])
    .width(Length::Fill)
    .align_x(iced::Alignment::Center)
    .into()
}

fn verdict<'a>(
    failed: bool,
    headline: &'a str,
    conclusion: impl Into<String>,
    footnote: Option<String>,
) -> Element<'a, Message> {
    verdict_color(
        headline,
        if failed { COL_FAILED } else { COL_VERIFIED },
        conclusion.into(),
        footnote,
    )
}

fn verdict_color<'a>(
    headline: &'a str,
    color: Color,
    conclusion: String,
    footnote: Option<String>,
) -> Element<'a, Message> {
    let mut cols = column![
        text(headline.to_string())
            .size(T_VERDICT)
            .color(color)
            .font(newsreader(Weight::Medium, true))
            .align_x(iced::alignment::Horizontal::Center),
        Space::new().height(Length::Fixed(12.0)),
        text(conclusion)
            .size(T_BODY)
            .color(COL_INK)
            .font(dm_sans(Weight::Normal))
            .align_x(iced::alignment::Horizontal::Center),
    ];
    if let Some(fn_text) = footnote {
        cols = cols
            .push(Space::new().height(Length::Fixed(8.0)))
            .push(
                container(
                    text(fn_text)
                        .size(T_FOOTNOTE)
                        .color(COL_INK_3)
                        .font(newsreader(Weight::Normal, true))
                        .align_x(iced::alignment::Horizontal::Center),
                )
                .max_width(360.0)
                .align_x(iced::alignment::Horizontal::Center),
            );
    }
    cols.width(Length::Fill)
        .align_x(iced::Alignment::Center)
        .into()
}

fn verified_conclusion(when: &str) -> String {
    format!("Your file existed before {}.", when)
}

fn verified_footnote() -> String {
    "Bitcoin block timestamps may drift up to ±2 hours from the network's actual time. The proof is otherwise mathematically exact.".to_string()
}

fn divider<'a>() -> Element<'a, Message> {
    container(Space::new())
        .width(Length::Fill)
        .height(Length::Fixed(1.0))
        .style(|_| container::Style {
            background: Some(iced::Background::Color(COL_HAIRLINE)),
            ..Default::default()
        })
        .into()
}

fn section<'a>(
    heading: &'a str,
    body: iced::widget::Column<'a, Message>,
) -> Element<'a, Message> {
    column![
        text(heading.to_string())
            .size(14.0)
            .color(COL_INK_2)
            .font(newsreader(Weight::Normal, true)),
        Space::new().height(Length::Fixed(10.0)),
        body,
    ]
    .into()
}

fn evidence_row<'a>(
    label: &'a str,
    value: Element<'a, Message>,
) -> Element<'a, Message> {
    row![
        container(
            text(label.to_string())
                .size(T_META)
                .color(COL_INK_3)
                .font(dm_sans(Weight::Medium)),
        )
        .width(Length::Fixed(96.0)),
        container(value).width(Length::Fill),
    ]
    .spacing(14)
    .align_y(iced::Alignment::Start)
    .padding([3, 0])
    .into()
}

fn text_value<'a>(value: String) -> Element<'a, Message> {
    text(value)
        .size(T_BODY)
        .color(COL_INK)
        .font(dm_sans(Weight::Normal))
        .into()
}

fn muted_value<'a>(value: String) -> Element<'a, Message> {
    text(value)
        .size(T_BODY)
        .color(COL_INK_2)
        .font(dm_sans(Weight::Normal))
        .into()
}

fn large_value<'a>(value: String) -> Element<'a, Message> {
    text(value)
        .size(T_H1)
        .color(COL_INK)
        .font(jetbrains())
        .into()
}

fn confirmations_value<'a>(n: u64) -> Element<'a, Message> {
    row![
        text(thousands(n))
            .size(T_BODY + 1.0)
            .color(COL_INK)
            .font(jetbrains()),
        Space::new().width(Length::Fixed(8.0)),
        text("blocks built on top since")
            .size(T_BODY)
            .color(COL_INK)
            .font(dm_sans(Weight::Normal)),
    ]
    .align_y(iced::Alignment::Center)
    .into()
}

/// A hash value rendered as a click-to-copy mono text. iced has no
/// `cursor: copy` per se, but the button gives it a clickable affordance
/// and the OS pointer cursor is close enough.
fn hash_value<'a>(hex: String) -> Element<'a, Message> {
    let label = hex.clone();
    button(
        text(label)
            .size(T_MONO)
            .color(COL_INK)
            .font(jetbrains()),
    )
    .padding([1, 4])
    .on_press(Message::CopyToClipboard(hex))
    .style(|_, status| {
        use iced::widget::button;
        let bg = match status {
            button::Status::Hovered => Color::from_rgba(0.0, 0.0, 0.0, 0.025),
            _ => Color::TRANSPARENT,
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: COL_INK,
            border: Border { color: Color::TRANSPARENT, width: 0.0, radius: 2.0.into() },
            ..Default::default()
        }
    })
    .into()
}

fn action_row<'a>(
    _block: u64,
    block_hash: String,
    show_export: bool,
) -> Element<'a, Message> {
    let url = format!("https://blockstream.info/block/{block_hash}");
    let mut r = row![
        action_btn("Reset", Message::Reset),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center);
    if show_export {
        r = r.push(action_btn("Export PDF", Message::ExportPdf));
    }
    r = r.push(text_link("Open block on blockstream.info ↗", Message::OpenUrl(url)));

    container(r)
        .width(Length::Fill)
        .align_x(iced::alignment::Horizontal::Center)
        .into()
}

fn action_btn<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(
        text(label.to_string())
            .size(12.0)
            .color(COL_INK)
            .font(dm_sans(Weight::Medium)),
    )
    .padding([7, 14])
    .on_press(msg)
    .style(|_, status| {
        use iced::widget::button;
        let bg = match status {
            button::Status::Hovered => COL_HOVER_BG,
            _ => Color::TRANSPARENT,
        };
        let border_color = match status {
            button::Status::Hovered => COL_INK_3,
            _ => COL_HAIRLINE_2,
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: COL_INK,
            border: Border { color: border_color, width: 1.0, radius: 5.0.into() },
            ..Default::default()
        }
    })
    .into()
}

fn text_link<'a>(label: &'a str, msg: Message) -> Element<'a, Message> {
    button(
        text(label.to_string())
            .size(12.0)
            .color(COL_INK)
            .font(dm_sans(Weight::Medium)),
    )
    .padding([6, 4])
    .on_press(msg)
    .style(|_, status| {
        use iced::widget::button;
        let bg = match status {
            button::Status::Hovered => COL_HOVER_BG,
            _ => Color::TRANSPARENT,
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: COL_INK,
            border: Border { color: Color::TRANSPARENT, width: 0.0, radius: 3.0.into() },
            ..Default::default()
        }
    })
    .into()
}

fn footer_note<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Your file stays on this device.")
                .size(10.5)
                .color(COL_INK_3)
                .font(dm_sans(Weight::Normal))
                .align_x(iced::alignment::Horizontal::Center),
            text("Only the block height crosses to blockstream.info.")
                .size(10.5)
                .color(COL_INK_3)
                .font(dm_sans(Weight::Normal))
                .align_x(iced::alignment::Horizontal::Center),
        ]
        .spacing(2)
        .align_x(iced::Alignment::Center),
    )
    .width(Length::Fill)
    .align_x(iced::alignment::Horizontal::Center)
    .into()
}

// ── Helpers ────────────────────────────────────────────────────────

fn step_toward(current: f32, target: f32, max_delta: f32) -> f32 {
    if current < target {
        (current + max_delta).min(target)
    } else if current > target {
        (current - max_delta).max(target)
    } else {
        current
    }
}

fn pulse_phase(started: Option<Instant>) -> f32 {
    let Some(start) = started else { return 0.0; };
    let elapsed = start.elapsed().as_secs_f32();
    let period = 1.4;
    (elapsed / period).fract()
}

fn path_filename(path: Option<&Path>) -> Option<&str> {
    path.and_then(|p| p.file_name().and_then(|n| n.to_str()))
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Proof walk for path depth ─────────────────────────────────────

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

// ── Verification ──────────────────────────────────────────────────

async fn verify_async(file: PathBuf, ots: PathBuf) -> Outcome {
    let join = tokio::task::spawn_blocking(move || -> Result<VerifyBundle, BundleError> {
        let file_data = std::fs::read(&file).map_err(|e| BundleError::Generic(format!("Read {}: {e}", file.display())))?;
        let ots_data = std::fs::read(&ots).map_err(|e| BundleError::Generic(format!("Read {}: {e}", ots.display())))?;
        let parsed = zeitstempel::parser::parse_ots(&ots_data)
            .map_err(|e| BundleError::Generic(format!("Parse .ots: {e}")))?;
        let file_hash_bytes = operations::hash_file_contents(&file_data, parsed.hash_op)
            .map_err(|e| BundleError::Generic(format!("Hash file: {e}")))?;
        let file_hash_hex = bytes_to_hex(&file_hash_bytes);
        let expected_hex = bytes_to_hex(&parsed.file_digest);
        if file_hash_bytes != parsed.file_digest {
            // The digest mismatch case — surface it as a structured
            // Mismatch outcome with both hashes for display.
            return Err(BundleError::Mismatch {
                file_hash: file_hash_hex,
                expected_hash: expected_hex,
            });
        }
        let path_depth = proof_depth(&parsed);
        let results = verify::verify_file(&file_data, &ots_data)
            .map_err(BundleError::Generic)?;
        Ok(VerifyBundle {
            results,
            file_hash: file_hash_hex,
            expected_hash: expected_hex,
            path_depth,
        })
    })
    .await;

    let bundle = match join {
        Ok(Ok(b)) => b,
        Ok(Err(BundleError::Mismatch { file_hash, expected_hash })) => {
            return Outcome::Mismatch { file_hash, expected_hash };
        }
        Ok(Err(BundleError::Generic(e))) => return Outcome::Error { message: e },
        Err(e) => return Outcome::Error { message: format!("worker panicked: {e}") },
    };

    let tip_height = tokio::task::spawn_blocking(zeitstempel::bitcoin::get_tip_height)
        .await
        .ok()
        .and_then(|r| r.ok());

    summarize(&bundle, tip_height)
}

enum BundleError {
    Mismatch { file_hash: String, expected_hash: String },
    Generic(String),
}

struct VerifyBundle {
    results: Vec<VerifyResult>,
    file_hash: String,
    expected_hash: String,
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
        if let VerifyResult::Failed { .. } = r {
            return Outcome::Mismatch {
                file_hash: bundle.file_hash.clone(),
                expected_hash: bundle.expected_hash.clone(),
            };
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
