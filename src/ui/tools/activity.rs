use eframe::egui;

use crate::app::state::AppState;
use crate::ui::components::{card, header, info_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Activity",
        "Audit trail of operations performed in this session. Actions only — never keys, passwords, or plaintext.",
    );
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(520.0);
            card(ui, "Audit log", |ui| {
                ui.set_width(ui.available_width());
                if state.history.is_empty() {
                    ui.weak("Nothing recorded yet. Use any tool — key actions land here.");
                } else {
                    egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                        egui::Grid::new("audit_grid").num_columns(3).striped(true).show(ui, |ui| {
                            ui.label(egui::RichText::new("Time").strong().small());
                            ui.label(egui::RichText::new("Tool").strong().small());
                            ui.label(egui::RichText::new("Action").strong().small());
                            ui.end_row();
                            for e in state.history.clone().iter().rev() {
                                ui.monospace(&e.ts);
                                ui.label(&e.tool);
                                ui.label(&e.action);
                                ui.end_row();
                            }
                        });
                    });
                }
                ui.horizontal(|ui| {
                    if ui.button("Clear log").clicked() {
                        state.history.clear();
                        state.set_status(true, "Audit log cleared.");
                    }
                    if ui.button("Export log").clicked() {
                        let text = state
                            .history
                            .iter()
                            .map(|e| format!("{} [{}] {}", e.ts, e.tool, e.action))
                            .collect::<Vec<_>>()
                            .join("\n");
                        if let Some(p) = rfd::FileDialog::new().set_file_name("larv-activity.log").save_file() {
                            match std::fs::write(&p, text.as_bytes()) {
                                Ok(()) => state.set_status(true, "Log exported."),
                                Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                            }
                        }
                    }
                });
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Pinned tools", |ui| {
                ui.set_width(ui.available_width());
                if state.favorites.is_empty() {
                    ui.weak("Right-click any sidebar entry → Pin to top.");
                } else {
                    for f in state.favorites.clone() {
                        ui.horizontal(|ui| {
                            ui.label(format!("★ {f}"));
                            if ui.small_button("Go").clicked() {
                                if let Some(t) = crate::app::navigation::Tool::from_title(&f) {
                                    state.switch_tool(t);
                                }
                            }
                        });
                    }
                }
            });
            ui.add_space(6.0);
            card(ui, "Session", |ui| {
                let secs = state.session_start.elapsed().as_secs();
                ui.monospace(format!("Uptime {:02}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60));
                ui.weak(format!("{} events recorded", state.history.len()));
            });
            info_box(ui, "The audit log lives in memory for this session. Export it before quitting if you need a record.");
        });
    });
}
