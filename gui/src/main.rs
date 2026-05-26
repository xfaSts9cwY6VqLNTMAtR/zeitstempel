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

use iced::widget::{Space, column, container, row, text};
use iced::{
    Border, Color, Element, Length, Subscription, Task, Theme,
    event::{self, Event},
    window,
};

use zeitstempel::format_unix_utc;
use zeitstempel::operations;
use zeitstempel::parser::{Attestation, Operation, OtsFile, Timestamp};
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


// ── Paced stage durations ──────────────────────────────────────────
//
// These artificially slow the visible animation so users can read each
// step. The local steps (hash, replay, compare) finish in microseconds
// in reality; the network step has its real duration plus the floor
// below.
const STAGE_HASH_MS: u128 = 320;
const STAGE_REPLAY_MS: u128 = 320;
const STAGE_COMPARE_MS: u128 = 260;

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
    stage: Stage,
    stage_started: Option<Instant>,
    pending_outcome: Option<Outcome>,
    outcome: Option<Outcome>,
    // Reveal animation for the result block (0→1 at Stage::Done).
    panel_reveal: f32,
    now: Option<Instant>,
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

/// Visible position in the verification pipeline.
///
/// The animation walks through Hashing → Replaying → Fetching → Comparing
/// → Done. Fetching is open-ended — it stays active until the real
/// verify result lands.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    #[default]
    Hidden,
    Hashing,
    Replaying,
    Fetching,
    Comparing,
    Done,
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
        /// Each step in the proof chain leading from `file_hash` to
        /// the Bitcoin attestation. `(operation_label, resulting_hash_hex)`.
        /// The last entry's hash is the calculated merkle root.
        proof_steps: Vec<(String, String)>,
    },
    Failed { block: u64 },
    Pending { host: String },
    Skipped { reason: String },
    Error { message: String },
}

impl Outcome {
    /// Did this outcome involve a real network call? If not, the UI
    /// should skip the Fetching stage rather than mislead the user.
    fn touched_network(&self) -> bool {
        matches!(
            self,
            Outcome::Verified { .. } | Outcome::Failed { .. } | Outcome::Pending { .. }
        )
    }
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
                self.pending_outcome = Some(outcome);
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
            // Begin a fresh run — even if a prior run already settled.
            self.stage = Stage::Hashing;
            let now = Instant::now();
            self.stage_started = Some(now);
            self.now = Some(now);
            self.last_tick = Some(now);
            self.pending_outcome = None;
            self.outcome = None;
            return Task::perform(verify_async(file, ots), Message::VerifyDone);
        }

        Task::none()
    }

    /// Single tick — advance stage transitions and the reveal animation.
    fn step(&mut self, now: Instant) {
        self.now = Some(now);
        self.advance_stage(now);

        let panel_target = match self.stage {
            Stage::Done => 1.0,
            _ => 0.0,
        };

        let dt = now.duration_since(self.last_tick.unwrap_or(now)).as_secs_f32();
        let speed = 1.0 / ANIM_DURATION_SECS;
        self.panel_reveal = step_toward(self.panel_reveal, panel_target, dt * speed);
        self.last_tick = Some(now);
    }

    fn advance_stage(&mut self, now: Instant) {
        let elapsed = self
            .stage_started
            .map(|t| now.duration_since(t).as_millis())
            .unwrap_or(0);

        // If a result arrived while we're still in the pre-network
        // stages and the outcome never actually touched the network
        // (e.g. digest mismatch fast-fails), skip ahead so the UI
        // doesn't claim a Fetching step that never happened.
        if matches!(self.stage, Stage::Hashing | Stage::Replaying)
            && self
                .pending_outcome
                .as_ref()
                .is_some_and(|o| !o.touched_network())
        {
            self.stage = Stage::Comparing;
            self.stage_started = Some(now);
            return;
        }

        match self.stage {
            Stage::Hashing if elapsed >= STAGE_HASH_MS => {
                self.stage = Stage::Replaying;
                self.stage_started = Some(now);
            }
            Stage::Replaying if elapsed >= STAGE_REPLAY_MS => {
                self.stage = Stage::Fetching;
                self.stage_started = Some(now);
            }
            Stage::Fetching if self.pending_outcome.is_some() => {
                self.stage = Stage::Comparing;
                self.stage_started = Some(now);
            }
            Stage::Comparing if elapsed >= STAGE_COMPARE_MS => {
                self.stage = Stage::Done;
                self.stage_started = None;
                self.outcome = self.pending_outcome.take();
            }
            _ => {}
        }
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

        let panel_target = if matches!(self.stage, Stage::Done) { 1.0 } else { 0.0 };
        let reveal_animating = (self.panel_reveal - panel_target).abs() > 0.001;
        let stage_animating = !matches!(self.stage, Stage::Hidden | Stage::Done);

        if reveal_animating || stage_animating {
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

        let toggle = toggle_button(self.expanded, self.expand_side, self.stage);

        let footer_alpha = if matches!(self.stage, Stage::Hidden) { 0.0 } else { 1.0 };

        column![
            header(),
            zones,
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

        let proof_steps: Vec<(String, String)> = match self.outcome.as_ref() {
            Some(Outcome::Verified { proof_steps, .. }) => proof_steps.clone(),
            _ => Vec::new(),
        };

        let mut content: Vec<Element<'_, Message>> = vec![
            data_card_label("Your file").into(),
            value_card(file_name, false, false),
            Space::new().height(Length::Fixed(10.0)).into(),
            connector("hashed with SHA-256 — produces a 32-byte fingerprint of the file").into(),
            Space::new().height(Length::Fixed(10.0)).into(),
            data_card_label("File hash").into(),
            value_card_optional(file_hash.clone(), 14, 12, true, false),
            Space::new().height(Length::Fixed(14.0)).into(),
            recipe_explainer().into(),
            Space::new().height(Length::Fixed(10.0)).into(),
        ];

        // The recipe, made literal: render the operation chain from the
        // .ots. Each step shows what was done and what hash resulted.
        // Long chains collapse to "first N + … + final" so the panel
        // stays readable for proofs with 20+ ops.
        if proof_steps.is_empty() {
            content.push(value_card_optional(merkle_root.clone(), 10, 8, true, verified));
        } else {
            content.extend(render_proof_walk(&proof_steps, verified));
        }

        content.extend(vec![
            Space::new().height(Length::Fixed(18.0)).into(),
            boundary_marker("your machine", "Bitcoin chain"),
            Space::new().height(Length::Fixed(14.0)).into(),
            self.block_artifact_card(merkle_root.clone(), verified),
            Space::new().height(Length::Fixed(18.0)).into(),
            self.proof_sentence(),
            Space::new().height(Length::Fixed(14.0)).into(),
            forgery_explainer().into(),
            Space::new().height(Length::Fixed(20.0)).into(),
            self.block_evidence(),
        ]);

        iced::widget::Column::with_children(content).into()
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
        if !matches!(self.stage, Stage::Done) {
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

/// Render the actual proof-chain walk: a vertical sequence of cards,
/// where each card shows the hash that resulted from applying one
/// of the .ots operations to the previous value. The user can see
/// their file's hash *transforming*, step by step, into the value
/// stored in the block.
///
/// For long chains (> 5 ops) we show the first three operations,
/// then a "…N more operations…" gap, then the final operation.
fn render_proof_walk<'a>(
    steps: &[(String, String)],
    verified: bool,
) -> Vec<Element<'a, Message>> {
    let mut out: Vec<Element<'a, Message>> = Vec::new();
    let total = steps.len();
    if total == 0 {
        return out;
    }

    let final_index = total - 1;
    let max_visible_intermediate = 3;
    let show_all = total <= max_visible_intermediate + 1;

    // Visible intermediate operations (everything but the final step).
    let visible_count = if show_all {
        final_index
    } else {
        max_visible_intermediate
    };

    for (i, (op_label, hex)) in steps.iter().take(visible_count).enumerate() {
        out.push(Space::new().height(Length::Fixed(6.0)).into());
        out.push(connector(format!("apply: {op_label}")));
        out.push(Space::new().height(Length::Fixed(6.0)).into());
        out.push(data_card_label(format!("after step {}", i + 1)));
        out.push(value_card(middle_truncate(hex, 14, 12), true, false));
    }

    if !show_all {
        let hidden = total - max_visible_intermediate - 1;
        out.push(Space::new().height(Length::Fixed(6.0)).into());
        out.push(connector(format!("… {hidden} more operations of the same shape …")));
    }

    // Final step → calculated merkle root.
    if let Some((op_label, hex)) = steps.last() {
        out.push(Space::new().height(Length::Fixed(6.0)).into());
        out.push(connector(format!("apply: {op_label}")));
        out.push(Space::new().height(Length::Fixed(6.0)).into());
        out.push(data_card_label("Calculated merkle root"));
        out.push(value_card(middle_truncate(hex, 10, 8), true, verified));
    }

    out
}

/// Plain-language explanation of what the .ots file actually does —
/// sits between the "File hash" card and the "Calculated merkle root"
/// card to replace the jargon "walk up the merkle tree" with a
/// concrete recipe metaphor.
fn recipe_explainer<'a>() -> Element<'a, Message> {
    container(
        column![
            text("When this file was timestamped, a calendar server bundled its")
                .size(12).color(COL_INK_2),
            text("hash together with thousands of other files' hashes by")
                .size(12).color(COL_INK_2),
            text("pair-hashing them — a small tree of SHA-256 operations.")
                .size(12).color(COL_INK_2),
            Space::new().height(Length::Fixed(6.0)),
            text("The .ots file is a recipe: it records exactly which sibling")
                .size(12).color(COL_INK),
            text("hashes yours was combined with, and in what order. Applying")
                .size(12).color(COL_INK),
            text("that recipe to your file's hash reproduces the bundled value.")
                .size(12).color(COL_INK),
        ]
        .spacing(3),
    )
    .padding(2)
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

/// Toggle that opens/closes the verification-steps side panel.
///
/// Stays disabled until we actually have something to show — there's
/// no point opening the panel when no file has been dropped yet.
fn toggle_button<'a>(
    expanded: bool,
    side: ExpandSide,
    stage: Stage,
) -> Element<'a, Message> {
    let has_content = !matches!(stage, Stage::Hidden);
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
    let join = tokio::task::spawn_blocking(move || -> Result<(Vec<VerifyResult>, String, Vec<(String, String)>), String> {
        let file_data = std::fs::read(&file).map_err(|e| format!("Read {}: {e}", file.display()))?;
        let ots_data = std::fs::read(&ots).map_err(|e| format!("Read {}: {e}", ots.display()))?;
        let parsed = zeitstempel::parser::parse_ots(&ots_data)
            .map_err(|e| format!("Parse .ots: {e}"))?;
        let file_hash_bytes = operations::hash_file_contents(&file_data, parsed.hash_op)
            .map_err(|e| format!("Hash file: {e}"))?;
        let file_hash_hex = bytes_to_hex(&file_hash_bytes);
        // Collect the operation chain leading from the file's hash up to
        // the first Bitcoin attestation — that becomes the visualized
        // recipe in the side panel.
        let proof_steps = collect_proof_walk(&parsed);
        let results = verify::verify_file(&file_data, &ots_data)?;
        Ok((results, file_hash_hex, proof_steps))
    })
    .await;

    let (results, file_hash, proof_steps) = match join {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Outcome::Error { message: e },
        Err(e) => return Outcome::Error { message: format!("worker panicked: {e}") },
    };

    summarize(&results, file_hash, proof_steps)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Walk the timestamp tree from the file's hash up to the first
/// Bitcoin attestation, recording each operation and the hash it
/// produces. The returned chain is exactly the recipe a verifier
/// applies; the last entry's hash is the calculated merkle root.
fn collect_proof_walk(ots: &OtsFile) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk_to_bitcoin(&ots.timestamp, ots.file_digest.clone(), &mut out);
    out
}

fn walk_to_bitcoin(
    ts: &Timestamp,
    msg: Vec<u8>,
    out: &mut Vec<(String, String)>,
) -> bool {
    for att in &ts.attestations {
        if matches!(att, Attestation::Bitcoin { .. }) {
            return true;
        }
    }
    for (op, child) in &ts.ops {
        let Ok(new_msg) = operations::apply(op, &msg) else {
            continue;
        };
        out.push((format_op(op), bytes_to_hex(&new_msg)));
        if walk_to_bitcoin(child, new_msg, out) {
            return true;
        }
        out.pop();
    }
    false
}

fn format_op(op: &Operation) -> String {
    match op {
        Operation::Append(d) => format!("append {}-byte sibling", d.len()),
        Operation::Prepend(d) => format!("prepend {}-byte sibling", d.len()),
        Operation::Sha256 => "SHA-256".to_string(),
        Operation::Sha1 => "SHA-1".to_string(),
        Operation::Ripemd160 => "RIPEMD-160".to_string(),
        Operation::Keccak256 => "Keccak-256".to_string(),
        Operation::Reverse => "reverse bytes".to_string(),
        Operation::Hexlify => "hexlify".to_string(),
    }
}

fn summarize(
    results: &[VerifyResult],
    file_hash: String,
    proof_steps: Vec<(String, String)>,
) -> Outcome {
    for r in results {
        if let VerifyResult::BitcoinVerified { height, block_hash, merkle_root, timestamp } = r {
            return Outcome::Verified {
                block: *height,
                block_time: *timestamp,
                when: format_unix_utc(*timestamp),
                block_hash: block_hash.clone(),
                merkle_root: merkle_root.clone(),
                file_hash,
                proof_steps,
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
