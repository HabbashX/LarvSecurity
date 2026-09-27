use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::certs::inspect_cert;
use crate::ui::components::{card, header, info_box, primary_button, warn_box};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(
        ui,
        "Certificates",
        "Read-only X.509 inspection: subject, issuer, validity, SANs, algorithms, expiry warnings.",
    );
    info_box(ui, "Inspection never trusts. Expiry and chain validation belong in your TLS client, not here.");
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(460.0);
            card(ui, "Certificate", |ui| {
                egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.cert_input).code_editor().desired_rows(10).desired_width(f32::INFINITY).hint_text("-----BEGIN CERTIFICATE-----"));
                });
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Inspect").clicked() {
                        match inspect_cert(&state.cert_input) {
                            Ok(info) => {
                                let mut d = format!(
                                    "Subject: {}\nIssuer: {}\nSerial: {}\nValid from: {}\nValid until: {}\nPublic key: {}\nSignature: {}\n",
                                    info.subject, info.issuer, info.serial_hex,
                                    info.not_before, info.not_after,
                                    info.public_key_algo, info.signature_algo
                                );
                                if info.san_list.is_empty() {
                                    d.push_str("SANs: (none)\n");
                                } else {
                                    d.push_str(&format!("SANs:\n  {}\n", info.san_list.join("\n  ")));
                                }
                                state.cert_details = d;
                                state.cert_warnings = info.warnings.join("\n");
                                state.set_status(true, "Certificate parsed.");
                                state.log("Certificates", "certificate inspected");
                            }
                            Err(e) => {
                                state.cert_details.clear();
                                state.cert_warnings.clear();
                                state.set_status(false, format!("{e}"));
                            }
                        }
                    }
                    if ui.button("Load file").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            match std::fs::read_to_string(&p) {
                                Ok(t) => {
                                    state.cert_input = t;
                                    state.set_status(true, "Certificate file loaded.");
                                }
                                Err(e) => state.set_status(false, format!("File could not be read: {e}")),
                            }
                        }
                    }
                    if ui.button("Clear").clicked() {
                        state.cert_input.clear();
                        state.cert_details.clear();
                        state.cert_warnings.clear();
                    }
                });
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Details", |ui| {
                ui.set_width(ui.available_width());
                if state.cert_details.is_empty() {
                    ui.weak("Nothing inspected yet.");
                } else {
                    egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                        ui.monospace(&state.cert_details.clone());
                    });
                }
            });
            if !state.cert_warnings.is_empty() {
                let w = state.cert_warnings.clone();
                for line in w.lines() {
                    warn_box(ui, line);
                }
            }
        });
    });
}
