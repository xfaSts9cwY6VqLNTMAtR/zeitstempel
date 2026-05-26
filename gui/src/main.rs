//! zeitstempel-gui — a tiny drop-target verifier for OpenTimestamps proofs.
//!
//! Drop a file in the left zone and its `.ots` in the right zone. A
//! verification-flow diagram appears showing each step from local
//! hashing through the Bitcoin block lookup, then the result panel
//! unrolls underneath with the block height, confirmation timestamp,
//! and block hash.
//!
//! v1 scope is verify-only. Stamp/upgrade live in the CLI.

#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::widget::canvas::{self, Canvas, Frame, Geometry, Path as CanvasPath, Stroke};
use iced::widget::{Space, column, container, row, text};
use iced::{
    Border, Color, Element, Length, Point as IcedPoint, Rectangle, Renderer,
    Size as IcedSize, Subscription, Task, Theme,
    event::{self, Event},
    mouse, window,
};

use zeitstempel::format_unix_utc;
use zeitstempel::operations;
use zeitstempel::verify::{self, VerifyResult};

// ── Window + layout constants ──────────────────────────────────────
const WINDOW_W_COLLAPSED: f32 = 480.0;
const SIDE_PANEL_W: f32 = 520.0;
const WINDOW_W_EXPANDED: f32 = WINDOW_W_COLLAPSED + SIDE_PANEL_W;
const WINDOW_H: f32 = 680.0;
const ZONE_H: f32 = 110.0;
const ANIM_DURATION_SECS: f32 = 0.28;

// We can't ask the windowing system for the user's primary monitor
// width through iced 0.14's public API. We make a sensible guess so
// that when the toggle is hit, the panel opens toward whichever side
// has more room. The heuristic falls back gracefully if the guess is
// wrong — the worst that happens is the panel opens slightly off the
// preferred side.
const ASSUMED_SCREEN_W: f32 = 1920.0;


// ── Palette ────────────────────────────────────────────────────────
//
// Editorial-minimal direction: warm off-white paper, hand-set typography
// hierarchy, color used only to mark state (active brand-blue, done
// botanical-green, failure muted oxblood). No tinted card backgrounds.

const COL_PAPER:        Color = Color::from_rgb(0.980, 0.980, 0.969);  // #FAFAF7
const COL_DIVIDER:      Color = Color::from_rgb(0.910, 0.902, 0.878);  // #E8E6E0
const COL_INK:          Color = Color::from_rgb(0.102, 0.094, 0.086);  // #1A1816
const COL_INK_2:        Color = Color::from_rgb(0.310, 0.302, 0.282);  // #4F4D48
const COL_INK_3:        Color = Color::from_rgb(0.604, 0.596, 0.576);  // #9A9893
const COL_BRAND:        Color = Color::from_rgb(0.114, 0.431, 0.612);  // #1D6E9C
const COL_CONFIRMED:    Color = Color::from_rgb(0.180, 0.353, 0.227);  // #2E5A3A
const COL_NETWORK_MARK: Color = Color::from_rgb(0.604, 0.482, 0.247);  // #9A7B3F
const COL_FAIL:         Color = Color::from_rgb(0.545, 0.176, 0.176);  // #8B2D2D

// Aliases kept for the drop-zone styles + status colors used in the
// header/footer; the rest of the file uses the editorial palette
// directly.
const COL_BG: Color = COL_PAPER;
const COL_TEXT: Color = COL_INK;
const COL_TEXT_DIM: Color = COL_INK_3;
const COL_BORDER_DIM: Color = COL_DIVIDER;
const COL_BORDER_ACTIVE: Color = COL_BRAND;

fn main() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .title("zeitstempel")
        .subscription(App::subscription)
        .window_size((WINDOW_W_COLLAPSED, WINDOW_H))
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
    /// A verify task is in flight — the drop-zones row shows a small
    /// "Verifying…" caption until it lands.
    verifying: bool,
    /// The settled outcome, if any. Set once the verify task resolves;
    /// cleared at the start of a fresh run.
    outcome: Option<Outcome>,
    /// Reveal animation for the result block: 0→1 when an outcome
    /// arrives, 1→0 when a fresh run kicks off.
    panel_reveal: f32,
    last_tick: Option<Instant>,

    // The visualization panel is collapsible. Default false: only the
    // drop zones + result + toggle are visible. When the user toggles
    // it open, the window grows horizontally to expose the flow panel.
    expanded: bool,
    expand_side: ExpandSide,
    window_id: Option<window::Id>,
    window_pos: iced::Point,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
enum ExpandSide {
    #[default]
    Right,
    Left,
}

#[derive(Clone, Debug)]
enum Outcome {
    Verified {
        block: u64,
        /// Unix epoch seconds — kept so the UI can compute "blocks
        /// built on top of this since" without re-parsing the date.
        block_time: u64,
        when: String,
        /// Bitcoin block hash (the entire block's identifier).
        block_hash: String,
        /// The merkle root committed in this block's header — the
        /// specific 32-byte value the proof chain matches.
        merkle_root: String,
        /// SHA-256 of the file the user dropped, in lowercase hex.
        /// We show this so the user can see their file's actual
        /// digest as the input to the proof chain.
        file_hash: String,
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
    ToggleExpand,
    WindowOpened(window::Id, iced::Point, iced::Size),
    WindowMoved(window::Id, iced::Point),
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
            Message::ToggleExpand => self.on_toggle_expand(),
            Message::WindowOpened(id, pos, _size) => {
                self.window_id = Some(id);
                self.window_pos = pos;
                Task::none()
            }
            Message::WindowMoved(id, pos) => {
                if self.window_id == Some(id) {
                    self.window_pos = pos;
                }
                Task::none()
            }
            Message::OpenUrl(url) => {
                // Fire-and-forget — opening the browser is the
                // OS's problem, not ours.
                let _ = webbrowser::open(&url);
                Task::none()
            }
        }
    }

    /// Toggle the side panel open/closed. When opening, we pick a side
    /// based on which has more screen real estate, then issue resize
    /// + move-to tasks so the panel grows away from the window's
    /// current "anchor" edge.
    fn on_toggle_expand(&mut self) -> Task<Message> {
        let id = match self.window_id {
            Some(id) => id,
            None => return Task::none(),
        };

        if self.expanded {
            // Collapse: shrink the window back. If it had grown leftward,
            // restore the right-anchor position.
            let new_size = iced::Size::new(WINDOW_W_COLLAPSED, WINDOW_H);
            let mut tasks = vec![window::resize(id, new_size)];
            if matches!(self.expand_side, ExpandSide::Left) {
                let new_pos = iced::Point::new(self.window_pos.x + SIDE_PANEL_W, self.window_pos.y);
                tasks.push(window::move_to(id, new_pos));
                self.window_pos = new_pos;
            }
            self.expanded = false;
            Task::batch(tasks)
        } else {
            // Expand: pick the side with more room, then grow.
            let right_room = ASSUMED_SCREEN_W - (self.window_pos.x + WINDOW_W_COLLAPSED);
            let left_room = self.window_pos.x;
            let side = if left_room > right_room && left_room >= SIDE_PANEL_W {
                ExpandSide::Left
            } else {
                ExpandSide::Right
            };
            self.expand_side = side;
            self.expanded = true;

            let new_size = iced::Size::new(WINDOW_W_EXPANDED, WINDOW_H);
            let mut tasks = vec![window::resize(id, new_size)];
            if matches!(side, ExpandSide::Left) {
                let new_x = (self.window_pos.x - SIDE_PANEL_W).max(0.0);
                let new_pos = iced::Point::new(new_x, self.window_pos.y);
                tasks.push(window::move_to(id, new_pos));
                self.window_pos = new_pos;
            }
            Task::batch(tasks)
        }
    }

    fn on_file_dropped(&mut self, path: PathBuf) -> Task<Message> {
        if path.extension().and_then(|e| e.to_str()) == Some("ots") {
            self.ots_path = Some(path);
        } else {
            self.file_path = Some(path);
        }

        if let (Some(file), Some(ots)) = (self.file_path.clone(), self.ots_path.clone()) {
            // Begin a fresh run — clear any prior outcome and kick off
            // the worker. The panel collapses while the run is in flight
            // and re-opens once it settles.
            self.verifying = true;
            self.outcome = None;
            self.last_tick = Some(Instant::now());
            return Task::perform(verify_async(file, ots), Message::VerifyDone);
        }

        Task::none()
    }

    /// Tick the result-panel reveal animation. Driven only while the
    /// reveal is in flight (not while verifying — the running task
    /// holds that state by itself).
    fn step(&mut self, now: Instant) {
        let panel_target = if self.outcome.is_some() { 1.0 } else { 0.0 };
        let dt = now.duration_since(self.last_tick.unwrap_or(now)).as_secs_f32();
        let speed = 1.0 / ANIM_DURATION_SECS;
        self.panel_reveal = step_toward(self.panel_reveal, panel_target, dt * speed);
        self.last_tick = Some(now);
    }

    fn subscription(&self) -> Subscription<Message> {
        let window_events = event::listen_with(|event, _status, id| match event {
            Event::Window(window::Event::FileDropped(path)) => Some(Message::FileDropped(path)),
            Event::Window(window::Event::Opened { position, size }) => Some(Message::WindowOpened(
                id,
                position.unwrap_or(iced::Point::ORIGIN),
                size,
            )),
            Event::Window(window::Event::Moved(position)) => {
                Some(Message::WindowMoved(id, position))
            }
            _ => None,
        });

        let panel_target = if self.outcome.is_some() { 1.0 } else { 0.0 };
        if (self.panel_reveal - panel_target).abs() > 0.001 {
            Subscription::batch([
                window_events,
                iced::time::every(Duration::from_millis(16)).map(Message::Tick),
            ])
        } else {
            window_events
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let main_column = self.main_column();
        let main_container = container(main_column)
            .width(Length::Fixed(WINDOW_W_COLLAPSED))
            .height(Length::Fill);

        if self.expanded {
            // Side-by-side. The panel sits on the side we expanded toward.
            let side_panel = container(self.side_panel())
                .width(Length::Fixed(SIDE_PANEL_W))
                .height(Length::Fill)
                .padding(20)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(COL_PAPER)),
                    ..Default::default()
                });

            let divider = container(Space::new())
                .width(Length::Fixed(1.0))
                .height(Length::Fill)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(COL_DIVIDER)),
                    ..Default::default()
                });

            match self.expand_side {
                ExpandSide::Right => row![main_container, divider, side_panel].into(),
                ExpandSide::Left => row![side_panel, divider, main_container].into(),
            }
        } else {
            main_container.into()
        }
    }

    /// The always-visible left/main column. Drop zones at the top, the
    /// result block directly underneath, then the toggle, then footer.
    fn main_column(&self) -> Element<'_, Message> {
        let zones = row![
            drop_zone("File", self.file_path.as_deref(), false),
            drop_zone(".ots Proof", self.ots_path.as_deref(), true),
        ]
        .spacing(14);

        let panel_eased = ease_out_cubic(self.panel_reveal);
        let result = container(self.result_view())
            .width(Length::Fill)
            .height(Length::Fixed(panel_eased * 170.0))
            .clip(true);

        let has_run = self.verifying || self.outcome.is_some();
        let toggle = toggle_button(self.expanded, self.expand_side, has_run);
        let footer_alpha = if has_run { 1.0 } else { 0.0 };

        column![
            header(),
            zones,
            verifying_indicator(self.verifying),
            result,
            toggle,
            Space::new().height(Length::Fill), // pushes footer to bottom
            footer_note(footer_alpha),
        ]
        .spacing(12)
        .padding(20)
        .into()
    }

    /// The collapsible side panel — the verification flow visualization.
    fn side_panel(&self) -> Element<'_, Message> {
        column![
            text("How we know").size(20).color(COL_INK),
            text("From your file to a permanent Bitcoin block.")
                .size(13)
                .color(COL_INK_3),
            Space::new().height(Length::Fixed(18.0)),
            self.flow_diagram(),
        ]
        .spacing(4)
        .into()
    }

    // ── Flow diagram ────────────────────────────────────────────────
    //
    // Vertical narrative. Top to bottom: the file → its hash → walked
    // up through the merkle tree using the .ots proof → the calculated
    // merkle root. Then a horizontal "your machine | Bitcoin chain"
    // boundary. Then the actual block, rendered as a header artifact
    // with its merkle_root field highlighted as the value the user's
    // file's hash chain produced. Then the conclusion.

    fn flow_diagram(&self) -> Element<'_, Message> {
        let outcome = self.outcome.as_ref();
        let verified = matches!(outcome, Some(Outcome::Verified { .. }));

        let file_name = self
            .file_path
            .as_ref()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()))
            .map(String::from)
            .unwrap_or_else(|| "(drop a file)".to_string());

        let file_hash = outcome.and_then(|o| match o {
            Outcome::Verified { file_hash, .. } => Some(file_hash.clone()),
            _ => None,
        });
        let merkle_root = outcome.and_then(|o| match o {
            Outcome::Verified { merkle_root, .. } => Some(merkle_root.clone()),
            _ => None,
        });

        column![
            data_card_label("Your file"),
            value_card(file_name, false, false),
            Space::new().height(Length::Fixed(10.0)),
            connector("hashed with SHA-256 — produces a 32-byte fingerprint of the file"),
            Space::new().height(Length::Fixed(10.0)),

            data_card_label("File hash"),
            value_card_optional(file_hash.clone(), 14, 12, true, false),

            Space::new().height(Length::Fixed(16.0)),
            tree_intro(),
            Space::new().height(Length::Fixed(4.0)),
            merkle_tree_canvas(verified),

            Space::new().height(Length::Fixed(12.0)),
            data_card_label("Calculated merkle root"),
            value_card_optional(merkle_root.clone(), 10, 8, true, verified),

            Space::new().height(Length::Fixed(18.0)),
            boundary_marker("your machine", "Bitcoin chain"),
            Space::new().height(Length::Fixed(14.0)),

            self.block_artifact_card(merkle_root.clone(), verified),
            Space::new().height(Length::Fixed(16.0)),
            self.proof_sentence(),
            Space::new().height(Length::Fixed(14.0)),
            forgery_explainer(),
            Space::new().height(Length::Fixed(20.0)),
            self.block_evidence(),
        ]
        .into()
    }

    /// The Bitcoin block, rendered as an artifact: a labeled box whose
    /// rows show real header fields. The merkle_root row is the bridge
    /// to your file — it carries the same hex value as the calculated
    /// merkle root above it.
    fn block_artifact_card(&self, merkle_root: Option<String>, matched: bool) -> Element<'_, Message> {
        let Some(Outcome::Verified { block, when, block_hash, .. }) = self.outcome.as_ref() else {
            return container(
                column![
                    text("Bitcoin block").size(11).color(COL_INK_3),
                    text("(no block looked up yet)").size(14).color(COL_INK_3),
                ]
                .spacing(6),
            )
            .padding(14)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(COL_PAPER)),
                border: Border { color: COL_DIVIDER, width: 1.0, radius: 6.0.into() },
                ..Default::default()
            })
            .into();
        };

        let merkle_display = merkle_root
            .as_deref()
            .map(|h| middle_truncate(h, 14, 12))
            .unwrap_or_else(|| "─".into());

        let block_hash_display = middle_truncate(block_hash, 14, 12);

        column![
            text(format!("Bitcoin block #{block}")).size(15).color(COL_INK),
            text(format!("mined {when}")).size(11).color(COL_INK_3),
            Space::new().height(Length::Fixed(10.0)),

            // The merkle_root field — the one that matters. Highlighted.
            field_row_highlighted(
                "merkle_root",
                merkle_display,
                if matched { COL_CONFIRMED } else { COL_BRAND },
                "← this commits to your file's hash",
            ),
            Space::new().height(Length::Fixed(8.0)),

            field_row("block_hash", block_hash_display),
            field_row("height", format!("#{block}")),
            field_row("timestamp", when.clone()),
        ]
        .spacing(4)
        .into()
    }

    fn proof_sentence(&self) -> Element<'_, Message> {
        match self.outcome.as_ref() {
            Some(Outcome::Verified { .. }) => column![
                text("The block's merkle_root is exactly the value your file's hash")
                    .size(13).color(COL_INK),
                text("was bundled into when timestamped. Bitcoin's chain has carried")
                    .size(13).color(COL_INK),
                text("that value, unchanged, since the block was mined.")
                    .size(13).color(COL_INK),
            ]
            .spacing(3)
            .into(),
            _ => Space::new().into(),
        }
    }

    /// Block-level evidence appearing after the merkle-root meeting
    /// point: which block it was, when it was mined, how many blocks
    /// have built on top, and a button to open the block on
    /// blockstream.info for independent verification.
    fn block_evidence(&self) -> Element<'_, Message> {
        let Some(Outcome::Verified {
            block,
            block_time,
            when,
            block_hash,
            ..
        }) = self.outcome.as_ref() else {
            return container(
                text("Drop a file and its .ots to see the evidence on chain.")
                    .size(11)
                    .color(COL_INK_3),
            )
            .width(Length::Fill)
            .align_x(iced::alignment::Horizontal::Center)
            .into();
        };

        let confirmations = estimate_confirmations(*block_time);
        let work = pretty_duration(confirmations);
        let url = format!("https://blockstream.info/block/{block_hash}");

        let open_btn = iced::widget::button(
            text("View block on blockstream.info  ↗")
                .size(11)
                .color(COL_BRAND),
        )
        .padding([6, 10])
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
                border: Border {
                    color: COL_DIVIDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        });

        column![
            text(format!("Block #{block} was mined on {when}."))
                .size(11)
                .color(COL_INK),
            text(format!(
                "~{} blocks have been built on top since — {}.",
                thousands(confirmations),
                work
            ))
            .size(11)
            .color(COL_INK_2),
            text("Re-doing that work is what would be required to alter this commitment.")
                .size(10)
                .color(COL_INK_3),
            Space::new().height(Length::Fixed(10.0)),
            open_btn,
        ]
        .spacing(3)
        .into()
    }

    // ── Result panel ────────────────────────────────────────────────

    fn result_view(&self) -> Element<'_, Message> {
        if self.outcome.is_none() {
            return Space::new().into();
        }
        let body: Element<'_, Message> = match self.outcome.as_ref() {
            None => return Space::new().into(),
            Some(Outcome::Verified { when, .. }) => column![
                text("Verified").size(32).color(COL_CONFIRMED),
                text(format!("Your file existed before {when}.")).size(13).color(COL_INK),
            ]
            .spacing(8)
            .into(),
            Some(Outcome::Failed { block }) => column![
                text("Mismatch").size(28).color(COL_FAIL),
                text(format!("Block #{block}: the .ots proof does not match this file.")).size(13).color(COL_INK),
            ]
            .spacing(8)
            .into(),
            Some(Outcome::Pending { host }) => column![
                text("Pending").size(26).color(COL_NETWORK_MARK),
                text(format!("Calendar {host} has the proof but Bitcoin has not anchored it yet.")).size(12).color(COL_INK),
            ]
            .spacing(6)
            .into(),
            Some(Outcome::Skipped { reason }) => column![
                text("Skipped").size(24).color(COL_INK_3),
                text(reason.clone()).size(12).color(COL_INK),
            ]
            .spacing(6)
            .into(),
            Some(Outcome::Error { message }) => column![
                text("Error").size(24).color(COL_FAIL),
                text(message.clone()).size(12).color(COL_INK),
            ]
            .spacing(6)
            .into(),
        };

        column![
            dashed_horizontal_line(440.0, COL_DIVIDER),
            Space::new().height(Length::Fixed(14.0)),
            body,
        ]
        .into()
    }
}

// ── Verification-flow primitives ──────────────────────────────────

/// A tiny uppercase label that introduces a value card below.
fn data_card_label<'a>(label: impl Into<String>) -> Element<'a, Message> {
    text(label.into()).size(10).color(COL_INK_3).into()
}

/// A subtle boxed value — used for the file name and (when no hash yet)
/// for placeholder cards. `mono` controls whether the value is
/// rendered with the monospace font; `highlight` toggles a confirmed
/// (green) border once the value is part of a successful match.
fn value_card<'a>(value: impl Into<String>, mono: bool, highlight: bool) -> Element<'a, Message> {
    let border_color = if highlight { COL_CONFIRMED } else { COL_DIVIDER };
    let value_text = if mono {
        text(value.into()).size(14).color(COL_INK).font(iced::Font::MONOSPACE)
    } else {
        text(value.into()).size(15).color(COL_INK)
    };
    container(value_text)
        .width(Length::Fill)
        .padding([10, 14])
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(COL_PAPER)),
            border: Border {
                color: border_color,
                width: if highlight { 1.5 } else { 1.0 },
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .into()
}

/// Like `value_card`, but shows a placeholder when we don't have a
/// value yet (e.g. before verification has run).
fn value_card_optional<'a>(
    value: Option<String>,
    head: usize,
    tail: usize,
    mono: bool,
    highlight: bool,
) -> Element<'a, Message> {
    match value {
        Some(v) => value_card(middle_truncate(&v, head, tail), mono, highlight),
        None => container(
            text("waiting for verification…")
                .size(13)
                .color(COL_INK_3),
        )
        .width(Length::Fill)
        .padding([10, 14])
        .style(|_| container::Style {
            background: Some(iced::Background::Color(COL_PAPER)),
            border: Border {
                color: COL_DIVIDER,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        })
        .into(),
    }
}

/// The narrative connective between two cards — a vertical pipe with
/// a small descriptive caption alongside.
fn connector<'a>(caption: impl Into<String>) -> Element<'a, Message> {
    row![
        Space::new().width(Length::Fixed(18.0)),
        container(Space::new())
            .width(Length::Fixed(1.0))
            .height(Length::Fixed(14.0))
            .style(|_| container::Style {
                background: Some(iced::Background::Color(COL_INK_3)),
                ..Default::default()
            }),
        Space::new().width(Length::Fixed(10.0)),
        text(caption.into()).size(12).color(COL_INK_2),
    ]
    .align_y(iced::Alignment::Center)
    .into()
}

/// The full-width horizontal divider that separates the local
/// computation from the on-chain evidence. Two captions sit either
/// side of the dashed line, one in each half.
fn boundary_marker<'a>(left_label: &'a str, right_label: &'a str) -> Element<'a, Message> {
    row![
        text(left_label.to_uppercase()).size(9).color(COL_INK_3),
        Space::new().width(Length::Fixed(10.0)),
        container(dashed_horizontal_line(280.0, COL_DIVIDER))
            .width(Length::Fill)
            .align_y(iced::alignment::Vertical::Center),
        Space::new().width(Length::Fixed(10.0)),
        text(right_label.to_uppercase()).size(9).color(COL_NETWORK_MARK),
    ]
    .align_y(iced::Alignment::Center)
    .into()
}

/// A row inside the block-artifact card: field name on the left,
/// value on the right.
fn field_row<'a>(name: impl Into<String>, value: impl Into<String>) -> Element<'a, Message> {
    row![
        container(text(name.into()).size(11).color(COL_INK_3))
            .width(Length::Fixed(130.0)),
        text(value.into())
            .size(12)
            .color(COL_INK_2)
            .font(iced::Font::MONOSPACE),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into()
}

/// The merkle_root row in the block-artifact card. Painted in the
/// confirmed/brand color to signal that this is the value that
/// matches the file's calculated root, with a side annotation
/// explaining the link.
fn field_row_highlighted<'a>(
    name: impl Into<String>,
    value: impl Into<String>,
    accent: Color,
    annotation: impl Into<String>,
) -> Element<'a, Message> {
    column![
        row![
            container(text(name.into()).size(11).color(accent))
                .width(Length::Fixed(130.0)),
            text(value.into())
                .size(13)
                .color(accent)
                .font(iced::Font::MONOSPACE),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center),
        row![
            Space::new().width(Length::Fixed(138.0)),
            text(annotation.into()).size(10).color(COL_INK_3),
        ],
    ]
    .spacing(3)
    .into()
}

/// Truncate "0123456789abcdef..." into "0123456789…abcdef" form.
fn middle_truncate(s: &str, head: usize, tail: usize) -> String {
    if s.len() <= head + tail + 1 {
        return s.to_string();
    }
    format!("{}…{}", &s[..head], &s[s.len() - tail..])
}

// ── Merkle-tree visualization ──────────────────────────────────────
//
// Schematic 4-level tree (8 leaves → 4 → 2 → root). One leaf is
// marked as "your file"; the path from it to the root is highlighted
// brand-blue (and root settles to confirmed-green once verified).
// The path's *siblings* — the hashes the .ots provides — are amber:
// those are the only off-path nodes the verifier actually needs.
//
// Everything else is dim: the other people's files that were
// bundled into the same merkle tree, plus the intermediate hashes
// in subtrees we never have to compute. The user sees that their
// file is one of many leaves, and that the .ots is just the path
// out of that crowd.

const TREE_W: f32 = 480.0;
const TREE_H: f32 = 210.0;

const BOX_W: f32 = 38.0;
const BOX_H: f32 = 14.0;
const ROOT_W: f32 = 78.0;
const ROOT_H: f32 = 18.0;

const LEAF_CX: [f32; 8] = [44.0, 100.0, 156.0, 212.0, 268.0, 324.0, 380.0, 436.0];
const LEAF_CY: f32 = 178.0;
const L1_CX: [f32; 4] = [72.0, 184.0, 296.0, 408.0];
const L1_CY: f32 = 130.0;
const L2_CX: [f32; 2] = [128.0, 352.0];
const L2_CY: f32 = 82.0;
const ROOT_CX: f32 = 240.0;
const ROOT_CY: f32 = 36.0;

/// Index of the highlighted leaf — the one labelled "your file".
const YOUR_LEAF: usize = 3;

struct MerkleTree {
    verified: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum NodeKind {
    OnPath,
    Sibling, // provided by the .ots
    Other,
}

impl MerkleTree {
    fn node_color(&self, kind: NodeKind, is_root: bool) -> Color {
        match kind {
            NodeKind::OnPath if is_root && self.verified => COL_CONFIRMED,
            NodeKind::OnPath => COL_BRAND,
            NodeKind::Sibling => COL_NETWORK_MARK,
            NodeKind::Other => Color::from_rgb(0.86, 0.86, 0.88),
        }
    }

    fn fill_box(&self, frame: &mut Frame, cx: f32, cy: f32, w: f32, h: f32, color: Color) {
        let top_left = IcedPoint::new(cx - w / 2.0, cy - h / 2.0);
        let path = CanvasPath::rectangle(top_left, IcedSize::new(w, h));
        frame.fill(&path, color);
    }

    fn draw_edge(&self, frame: &mut Frame, child: (f32, f32), parent: (f32, f32), highlighted: bool) {
        let stroke = if highlighted {
            Stroke::default().with_color(COL_BRAND).with_width(1.5)
        } else {
            Stroke::default().with_color(Color { a: 0.55, ..COL_INK_3 }).with_width(1.0)
        };
        let path = CanvasPath::line(IcedPoint::new(child.0, child.1), IcedPoint::new(parent.0, parent.1));
        frame.stroke(&path, stroke);
    }

    fn caption(&self, frame: &mut Frame, content: &str, pos: (f32, f32), size: f32, color: Color) {
        let t = canvas::Text {
            content: content.to_string(),
            position: IcedPoint::new(pos.0, pos.1),
            color,
            size: iced::Pixels(size),
            align_x: iced::widget::text::Alignment::Center,
            align_y: iced::alignment::Vertical::Center,
            ..canvas::Text::default()
        };
        frame.fill_text(t);
    }
}

impl<Message> canvas::Program<Message> for MerkleTree {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());

        // ── Edges ─────────────────────────────────────────────────
        // Leaf → L1
        for i in 0..8 {
            let parent = i / 2;
            let on_path = i == YOUR_LEAF || (i == YOUR_LEAF ^ 1 && false); // siblings aren't "on path"
            let highlight = i == YOUR_LEAF;
            self.draw_edge(
                &mut frame,
                (LEAF_CX[i], LEAF_CY - BOX_H / 2.0),
                (L1_CX[parent], L1_CY + BOX_H / 2.0),
                highlight,
            );
            let _ = on_path;
        }
        // L1 → L2
        for i in 0..4 {
            let parent = i / 2;
            let highlight = i == YOUR_LEAF / 2;
            self.draw_edge(
                &mut frame,
                (L1_CX[i], L1_CY - BOX_H / 2.0),
                (L2_CX[parent], L2_CY + BOX_H / 2.0),
                highlight,
            );
        }
        // L2 → root
        for i in 0..2 {
            let highlight = i == YOUR_LEAF / 4;
            self.draw_edge(
                &mut frame,
                (L2_CX[i], L2_CY - BOX_H / 2.0),
                (ROOT_CX, ROOT_CY + ROOT_H / 2.0),
                highlight,
            );
        }

        // ── Leaves ────────────────────────────────────────────────
        for i in 0..8 {
            let kind = if i == YOUR_LEAF {
                NodeKind::OnPath
            } else if i == YOUR_LEAF ^ 1 {
                NodeKind::Sibling
            } else {
                NodeKind::Other
            };
            let color = self.node_color(kind, false);
            self.fill_box(&mut frame, LEAF_CX[i], LEAF_CY, BOX_W, BOX_H, color);
        }
        // Label your leaf
        self.caption(
            &mut frame,
            "your file",
            (LEAF_CX[YOUR_LEAF], LEAF_CY + BOX_H / 2.0 + 12.0),
            10.0,
            COL_BRAND,
        );
        // Tiny "other files…" label under one of the dim leaves
        self.caption(
            &mut frame,
            "other timestamped files in the same bundle",
            (TREE_W / 2.0, LEAF_CY + BOX_H / 2.0 + 28.0),
            9.0,
            COL_INK_3,
        );

        // ── L1 ────────────────────────────────────────────────────
        for i in 0..4 {
            let kind = if i == YOUR_LEAF / 2 {
                NodeKind::OnPath
            } else if i == (YOUR_LEAF / 2) ^ 1 {
                NodeKind::Sibling
            } else {
                NodeKind::Other
            };
            let color = self.node_color(kind, false);
            self.fill_box(&mut frame, L1_CX[i], L1_CY, BOX_W, BOX_H, color);
        }

        // ── L2 ────────────────────────────────────────────────────
        for i in 0..2 {
            let kind = if i == YOUR_LEAF / 4 {
                NodeKind::OnPath
            } else {
                NodeKind::Sibling
            };
            let color = self.node_color(kind, false);
            self.fill_box(&mut frame, L2_CX[i], L2_CY, BOX_W, BOX_H, color);
        }

        // ── Root ──────────────────────────────────────────────────
        let root_color = self.node_color(NodeKind::OnPath, true);
        self.fill_box(&mut frame, ROOT_CX, ROOT_CY, ROOT_W, ROOT_H, root_color);
        self.caption(
            &mut frame,
            "merkle root",
            (ROOT_CX, ROOT_CY - ROOT_H / 2.0 - 10.0),
            10.0,
            if self.verified { COL_CONFIRMED } else { COL_BRAND },
        );
        self.caption(
            &mut frame,
            "this value lives in the Bitcoin block header",
            (ROOT_CX, ROOT_CY - ROOT_H / 2.0 - 24.0),
            9.0,
            COL_INK_3,
        );

        // ── Mini legend ───────────────────────────────────────────
        // Three colored dots with their meanings on one row at the bottom.
        let legend_y = TREE_H - 8.0;
        let legend_dot_r = 3.5;
        let legend_spacing = 130.0;
        let legend_start_x = (TREE_W - legend_spacing * 2.0) / 2.0;

        let legend = [
            (COL_BRAND, "your file's path"),
            (COL_NETWORK_MARK, "sibling — from the .ots"),
            (Color::from_rgb(0.86, 0.86, 0.88), "other files in the bundle"),
        ];
        for (i, (dot_color, label)) in legend.iter().enumerate() {
            let cx = legend_start_x + i as f32 * legend_spacing;
            let dot = CanvasPath::new(|b| b.circle(IcedPoint::new(cx, legend_y), legend_dot_r));
            frame.fill(&dot, *dot_color);
            self.caption(
                &mut frame,
                label,
                (cx + 64.0, legend_y),
                9.0,
                COL_INK_3,
            );
        }

        vec![frame.into_geometry()]
    }
}

fn merkle_tree_canvas<'a>(verified: bool) -> Element<'a, Message> {
    Canvas::new(MerkleTree { verified })
        .width(Length::Fixed(TREE_W))
        .height(Length::Fixed(TREE_H))
        .into()
}

/// Render the actual proof-chain walk: a vertical sequence of cards,
/// Caption that sits just above the merkle-tree canvas — introduces
/// what the user is looking at in one terse sentence.
fn tree_intro<'a>() -> Element<'a, Message> {
    column![
        text("Your file's hash is one leaf in a tree of timestamped files.")
            .size(12)
            .color(COL_INK),
        text("The .ots records the sibling hashes on the path to the root.")
            .size(12)
            .color(COL_INK_2),
    ]
    .spacing(2)
    .into()
}

/// Anticipates the "couldn't someone fake this after the fact?"
/// question by explaining the security argument inline. SHA-256
/// preimage resistance is doing the heavy lifting; the user doesn't
/// have to understand the math, only that "reversing" the hash is
/// infeasible.
fn forgery_explainer<'a>() -> Element<'a, Message> {
    container(
        column![
            text("Why this can't be faked after the fact")
                .size(11)
                .color(COL_INK_3),
            Space::new().height(Length::Fixed(4.0)),
            text("To forge a new .ots claiming a different file was timestamped,")
                .size(11).color(COL_INK_2),
            text("you'd need to find a sequence of operations that turns that")
                .size(11).color(COL_INK_2),
            text("file's hash into the exact 32-byte value already stored in")
                .size(11).color(COL_INK_2),
            text("this block. SHA-256 is designed so that working backwards")
                .size(11).color(COL_INK_2),
            text("from a chosen output is computationally infeasible.")
                .size(11).color(COL_INK_2),
        ]
        .spacing(2),
    )
    .padding([10, 12])
    .style(|_| container::Style {
        background: Some(iced::Background::Color(Color {
            r: 0.96, g: 0.95, b: 0.92, a: 1.0,
        })),
        border: Border {
            color: COL_DIVIDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Rough estimate of subsequent blocks since `block_time` (Unix seconds).
///
/// Bitcoin averages 10-minute blocks; over a decade the long-run
/// average is close to that. We just take wall-clock seconds / 600.
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
        return format!("{years} years of mining work");
    }
    let days = secs / 86400;
    if days >= 1 {
        return format!("{days} days of mining work");
    }
    format!("{} hours of mining work", (secs / 3600).max(1))
}

// ── Static UI pieces ───────────────────────────────────────────────

/// Tiny in-flight indicator shown directly under the drop zones.
/// Used to bridge the moment between dropping the files and the
/// outcome panel appearing.
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

/// Toggle that opens/closes the verification-steps side panel.
///
/// Stays disabled until we actually have something to show — there's
/// no point opening the panel when no file has been dropped yet.
fn toggle_button<'a>(
    expanded: bool,
    side: ExpandSide,
    has_content: bool,
) -> Element<'a, Message> {
    let (chevron, label) = match (expanded, side) {
        (false, _) => ("▸", "Show verification steps"),
        (true, ExpandSide::Right) => ("◂", "Hide verification steps"),
        (true, ExpandSide::Left) => ("▸", "Hide verification steps"),
    };

    let inner = row![
        text(chevron).size(11).color(if has_content { COL_BRAND } else { COL_INK_3 }),
        text(label).size(11).color(if has_content { COL_INK } else { COL_INK_3 }),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center);

    let btn = iced::widget::button(inner)
        .padding([6, 8])
        .style(move |_, status| {
            use iced::widget::button;
            let bg = match status {
                button::Status::Hovered if has_content => COL_DIVIDER,
                _ => Color::TRANSPARENT,
            };
            button::Style {
                background: Some(iced::Background::Color(bg)),
                text_color: COL_INK,
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        });

    if has_content {
        btn.on_press(Message::ToggleExpand).into()
    } else {
        btn.into()
    }
}

fn header<'a>() -> Element<'a, Message> {
    column![
        text("zeitstempel").size(13).color(COL_TEXT),
        text("Drop a file and its .ots proof").size(11).color(COL_TEXT_DIM),
    ]
    .spacing(2)
    .into()
}

fn footer_note<'a>(reveal: f32) -> Element<'a, Message> {
    // Footnote, in the editorial tone — fades in once the flow appears.
    container(
        text("Your file stays on this device. Only the block height crosses to blockstream.info.")
            .size(11)
            .color(Color { a: reveal * 0.7, ..COL_INK_3 })
            .align_x(iced::alignment::Horizontal::Center),
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
        text(primary).size(13).color(COL_TEXT),
        text(secondary).size(10).color(COL_TEXT_DIM),
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
            let border_color = if filled { COL_BORDER_ACTIVE } else { COL_BORDER_DIM };
            container::Style {
                border: Border { color: border_color, width: 1.5, radius: 10.0.into() },
                background: Some(iced::Background::Color(COL_BG)),
                ..Default::default()
            }
        })
        .into()
}

// ── Flow-diagram primitives ────────────────────────────────────────

/// A single step row.
///
/// Three slots, left-to-right: the active marker rule (2px brand-color
/// strip, only visible when active), then the number + body column,
/// then the status glyph (small dot, pulsing when active; a check
/// when done; an empty ring when pending).
///
/// No backgrounds, no badges, no rounded boxes. The typography and
/// the brand-color left rule are doing all the structural work.
/// A horizontal dashed line of approximately `total_width` pixels.
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

fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

// ── Verification call ──────────────────────────────────────────────

async fn verify_async(file: PathBuf, ots: PathBuf) -> Outcome {
    let join = tokio::task::spawn_blocking(move || -> Result<(Vec<VerifyResult>, String), String> {
        let file_data = std::fs::read(&file).map_err(|e| format!("Read {}: {e}", file.display()))?;
        let ots_data = std::fs::read(&ots).map_err(|e| format!("Read {}: {e}", ots.display()))?;
        // Hash the file with whatever op the .ots specifies, so the
        // displayed digest matches the one feeding the proof chain.
        let parsed = zeitstempel::parser::parse_ots(&ots_data)
            .map_err(|e| format!("Parse .ots: {e}"))?;
        let file_hash_bytes = operations::hash_file_contents(&file_data, parsed.hash_op)
            .map_err(|e| format!("Hash file: {e}"))?;
        let file_hash_hex = bytes_to_hex(&file_hash_bytes);
        let results = verify::verify_file(&file_data, &ots_data)?;
        Ok((results, file_hash_hex))
    })
    .await;

    let (results, file_hash) = match join {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Outcome::Error { message: e },
        Err(e) => return Outcome::Error { message: format!("worker panicked: {e}") },
    };

    summarize(&results, file_hash)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn summarize(results: &[VerifyResult], file_hash: String) -> Outcome {
    for r in results {
        if let VerifyResult::BitcoinVerified { height, block_hash, merkle_root, timestamp } = r {
            return Outcome::Verified {
                block: *height,
                block_time: *timestamp,
                when: format_unix_utc(*timestamp),
                block_hash: block_hash.clone(),
                merkle_root: merkle_root.clone(),
                file_hash,
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
    Outcome::Error { message: "proof contains no attestations".into() }
}
