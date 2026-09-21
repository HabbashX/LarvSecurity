use eframe::egui;

use crate::app::navigation::{Tool, NAV};
use crate::app::state::AppState;
use crate::ui::components::chip;
use crate::utils::i18n::t;

pub fn show_sidebar(ui: &mut egui::Ui, state: &mut AppState) {
    let lang = state.lang;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(t(lang, "Security Toolkit")).strong().size(14.0));
    });
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("v0.1.0").small().weak());
        chip(ui, t(lang, "OFFLINE"), state.accent.bright());
    });
    ui.separator();
    ui.add_space(2.0);

    egui::ScrollArea::vertical().show(ui, |ui| {
        // Pinned favorites first.
        let favs: Vec<Tool> = state
            .favorites
            .iter()
            .filter_map(|s| Tool::from_title(s))
            .collect();
        if !favs.is_empty() {
            ui.label(
                egui::RichText::new(if lang == crate::utils::i18n::Language::Arabic {
                    "المفضلة"
                } else {
                    "PINNED"
                })
                .small()
                .strong()
                .color(state.accent.bright()),
            );
            for tool in favs {
                show_tool_button(ui, state, tool);
            }
            ui.separator();
        }
        for section in NAV {
            if let Some(h) = section.heading {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(t(lang, h))
                        .small()
                        .strong()
                        .color(ui.style().visuals.weak_text_color()),
                );
                ui.add_space(2.0);
            }
            for tool in section.tools {
                show_tool_button(ui, state, *tool);
            }
        }
    });

    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        ui.separator();
        if state.vault_unlocked && ui.small_button(t(lang, "Lock")).clicked() {
            crate::ui::vault::lock_vault(state);
        }
        ui.label(
            egui::RichText::new(t(lang, "No telemetry. No network calls."))
                .small()
                .weak(),
        );
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(t(lang, "Clipboard clear:")).small());
            let mut secs = state.clipboard.auto_clear_secs.to_string();
            ui.add(
                egui::TextEdit::singleline(&mut secs)
                    .desired_width(36.0)
                    .hint_text("30"),
            );
            if let Ok(v) = secs.trim().parse::<u64>() {
                state.clipboard.auto_clear_secs = v.clamp(5, 600);
            }
            ui.checkbox(&mut state.clipboard.auto_clear_enabled, "auto");
        });
    });
}

fn show_tool_button(ui: &mut egui::Ui, state: &mut AppState, tool: Tool) {
    let selected = state.tool == tool;
    let h = 30.0;
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());
    if resp.clicked() {
        state.switch_tool(tool);
    }
    // Right-click to pin/unpin.
    let pinned = state.favorites.iter().any(|f| f == tool.title());
    resp.context_menu(|ui| {
        if pinned {
            if ui.button("Unpin from top").clicked() {
                state.favorites.retain(|f| f != tool.title());
                ui.close_menu();
            }
        } else if ui.button("Pin to top").clicked() {
            state.favorites.push(tool.title().to_string());
            ui.close_menu();
        }
    });
    let painter = ui.painter().clone();
    let radius = egui::CornerRadius::same(state.corner.min(8));

    if selected {
        let a = state.accent.color();
        painter.rect_filled(
            rect,
            radius,
            egui::Color32::from_rgba_unmultiplied(a.r(), a.g(), a.b(), 34),
        );
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(rect.min.x + 3.0, rect.min.y + 6.0),
                egui::pos2(rect.min.x + 6.0, rect.max.y - 6.0),
            ),
            egui::CornerRadius::same(2),
            a,
        );
    } else if resp.hovered() {
        painter.rect_filled(rect, radius, ui.style().visuals.widgets.hovered.bg_fill);
    }

    let mut label = t(state.lang, tool.title()).to_string();
    if pinned {
        label.push_str("  ★");
    }
    painter.text(
        egui::pos2(rect.min.x + 16.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.5),
        if selected {
            ui.style().visuals.strong_text_color()
        } else {
            ui.style().visuals.text_color()
        },
    );
}
