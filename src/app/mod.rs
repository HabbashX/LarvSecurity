use eframe::egui;

use crate::app::navigation::Tool;
use crate::app::state::AppState;
use crate::app::theme::{apply_theme, ThemeMode};
use crate::utils::i18n::t;

pub mod navigation;
pub mod state;
pub mod theme;

pub struct ToolkitApp {
    pub state: AppState,
}

impl ToolkitApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut state = AppState::default();
        // Load portable workspace (appearance, favorites, presets — never secrets).
        if let Ok(ws) = crate::utils::config::load_from(&crate::utils::config::config_path()) {
            state.apply_workspace(&ws);
            state.set_status(true, "Workspace settings loaded.");
        }
        cc.egui_ctx.set_pixels_per_point(state.ui_scale);
        apply_theme(
            &cc.egui_ctx,
            state.theme,
            state.accent,
            state.base_size,
            state.mono_ui,
            state.corner,
        );
        Self { state }
    }

    fn handle_global_keys(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::K)) {
            self.state.palette_open = !self.state.palette_open;
            self.state.palette_query.clear();
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.state.palette_open = false;
        }
    }

    fn reapply_appearance(&self, ctx: &egui::Context) {
        let s = &self.state;
        ctx.set_pixels_per_point(s.ui_scale);
        apply_theme(ctx, s.theme, s.accent, s.base_size, s.mono_ui, s.corner);
    }

    /// Vault auto-lock + duress-safe session handling.
    fn poll_vault_lock(&mut self) {
        if self.state.vault_unlocked {
            if let Some(at) = self.state.vault_lock_at {
                if std::time::Instant::now() >= at {
                    crate::ui::vault::lock_vault(&mut self.state);
                    self.state.set_status(true, "Vault auto-locked.");
                }
            }
        }
    }
}

impl eframe::App for ToolkitApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_global_keys(ctx);
        self.poll_vault_lock();
        let lang = self.state.lang;

        // Ambient animated backdrop (beneath translucent panels).
        let dark = ctx.style().visuals.dark_mode;
        crate::ui::background::paint(ctx, dark, self.state.motion, self.state.accent);
        if self.state.motion {
            ctx.request_repaint();
        }

        // Top bar.
        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(t(lang, "Security Toolkit")).strong().size(14.0));
                crate::ui::components::chip(ui, t(lang, "LOCAL"), self.state.accent.bright());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_label("")
                        .selected_text(format!("Theme: {}", self.state.theme.label()))
                        .show_ui(ui, |ui| {
                            for m in ThemeMode::all() {
                                if ui
                                    .selectable_value(&mut self.state.theme, *m, m.label())
                                    .clicked()
                                {
                                    self.reapply_appearance(ctx);
                                }
                            }
                        });
                    ui.checkbox(&mut self.state.motion, "Motion");
                    let secs = self.state.session_start.elapsed().as_secs();
                    ui.weak(format!("{:02}:{:02}", secs / 60, secs % 60));
                    if ui.button(t(lang, "Tools (Ctrl+K)")).clicked() {
                        self.state.palette_open = true;
                        self.state.palette_query.clear();
                    }
                });
            });
        });

        // Status bar.
        egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(msg) = self.state.status.clone() {
                    let color = if self.state.status_is_error {
                        crate::app::theme::ERROR
                    } else {
                        crate::app::theme::SUCCESS
                    };
                    ui.colored_label(color, &msg);
                } else {
                    ui.weak(t(lang, "Ready."));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak("All operations run locally on this machine.");
                });
            });
        });

        // Sidebar.
        egui::SidePanel::left("sidebar")
            .resizable(true)
            .default_width(216.0)
            .width_range(180.0..=300.0)
            .show(ctx, |ui| {
                crate::ui::sidebar::show_sidebar(ui, &mut self.state);
            });

        // Main content, centered at a readable max width.
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::both().show(ui, |ui| {
                ui.horizontal(|ui| {
                    let avail = ui.available_width();
                    let width = avail.min(1100.0);
                    let pad = ((avail - width) / 2.0).max(0.0);
                    if pad > 1.0 {
                        ui.add_space(pad);
                    }
                    ui.vertical(|ui| {
                        ui.set_width(width);
                        let tool = self.state.tool;
                        match tool {
                            Tool::Password => crate::ui::password::show(ui, &mut self.state),
                            Tool::JwtGenerate | Tool::JwtDecode | Tool::JwtVerify => {
                                crate::ui::jwt::show(ui, &mut self.state)
                            }
                            Tool::Encrypt => crate::ui::encryption::show(ui, &mut self.state),
                            Tool::Hash => crate::ui::hashing::show(ui, &mut self.state),
                            Tool::Keys => crate::ui::keys::show(ui, &mut self.state),
                            Tool::Encoding => crate::ui::encoding::show(ui, &mut self.state),
                            Tool::Random => crate::ui::random::show(ui, &mut self.state),
                            Tool::Totp => crate::ui::totp::show(ui, &mut self.state),
                            Tool::Vault => crate::ui::vault::show(ui, &mut self.state),
                            Tool::Checksums => crate::ui::files::show_checksums(ui, &mut self.state),
                            Tool::Shredder => crate::ui::files::show_shredder(ui, &mut self.state),
                            Tool::JsonTools => crate::ui::devtools::show_json(ui, &mut self.state),
                            Tool::TimeCron => crate::ui::devtools::show_time(ui, &mut self.state),
                            Tool::RegexTester => crate::ui::devtools::show_regex(ui, &mut self.state),
                            Tool::DiffViewer => crate::ui::devtools::show_diff(ui, &mut self.state),
                            Tool::QrCodes => crate::ui::devtools::show_qr(ctx, ui, &mut self.state),
                            Tool::Signatures => crate::ui::signing::show_signatures(ui, &mut self.state),
                            Tool::Hmac => crate::ui::signing::show_hmac(ui, &mut self.state),
                            Tool::Certificates => crate::ui::certs::show(ui, &mut self.state),
                            Tool::SshKeys => crate::ui::ssh::show(ui, &mut self.state),
                            Tool::Activity => crate::ui::activity::show(ui, &mut self.state),
                            Tool::Appearance => {
                                crate::ui::appearance::show(ctx, ui, &mut self.state)
                            }
                            Tool::About => crate::ui::about::show(ctx, ui, &mut self.state),
                        }
                    });
                });
            });
        });

        // Command palette modal.
        if self.state.palette_open {
            crate::ui::components::show_command_palette(ctx, &mut self.state);
        }
    }
}
