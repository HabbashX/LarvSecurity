use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::cron::{describe, next_runs, parse_cron};
use crate::crypto::diff::{diff_lines, DiffOp};
use crate::ui::components::{card, copy_button, header, info_box, primary_button};

fn sort_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<String> = m.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), sort_json(m[&k].clone()));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn show_json(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "JSON Tools", "Validate, pretty-print, minify, and sort JSON object keys.");
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(460.0);
            card(ui, "Input", |ui| {
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.json_input).code_editor().desired_rows(14).desired_width(f32::INFINITY));
                });
                ui.checkbox(&mut state.json_sort_keys, "Sort object keys");
                ui.horizontal(|ui| {
                    if primary_button(ui, state, "Pretty-print").clicked() {
                        fmt_json(state, false);
                    }
                    if ui.button("Minify").clicked() {
                        fmt_json(state, true);
                    }
                    if ui.button("Validate").clicked() {
                        match serde_json::from_str::<serde_json::Value>(&state.json_input) {
                            Ok(_) => state.set_status(true, "Valid JSON."),
                            Err(e) => state.set_status(false, format!("Invalid JSON: {e}")),
                        }
                    }
                });
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Output", |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.json_output).code_editor().desired_rows(14).desired_width(f32::INFINITY));
                });
                let o = state.json_output.clone();
                copy_button(ui, state, "JSON", &o);
            });
        });
    });
}

fn fmt_json(state: &mut AppState, minify: bool) {
    match serde_json::from_str::<serde_json::Value>(&state.json_input) {
        Ok(mut v) => {
            if state.json_sort_keys {
                v = sort_json(v);
            }
            state.json_output = if minify { v.to_string() } else { serde_json::to_string_pretty(&v).unwrap_or_default() };
            state.set_status(true, "Formatted.");
            state.log("JSON", if minify { "minified" } else { "pretty-printed" });
        }
        Err(e) => state.set_status(false, format!("Invalid JSON: {e}")),
    }
}

fn rel_time(target: i64, now: i64) -> String {
    let d = target - now;
    let (abs, suffix) = if d >= 0 { (d, "from now") } else { (-d, "ago") };
    let s = if abs < 60 {
        format!("{abs}s")
    } else if abs < 3600 {
        format!("{}m", abs / 60)
    } else if abs < 86400 {
        format!("{}h", abs / 3600)
    } else if abs < 86400 * 30 {
        format!("{}d", abs / 86400)
    } else if abs < 86400 * 365 {
        format!("{:.1}mo", abs as f64 / (86400.0 * 30.0))
    } else {
        format!("{:.1}y", abs as f64 / (86400.0 * 365.0))
    };
    format!("{s} {suffix}")
}

pub fn show_time(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "Time & Cron", "Unix timestamp conversion and cron schedule preview (local time).");
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(360.0);
            card(ui, "Timestamp converter", |ui| {
                let now = chrono::Local::now();
                ui.monospace(format!("Now: {}  ({})", now.to_rfc3339(), now.timestamp()));
                ui.label("Epoch seconds or datetime (RFC3339 / YYYY-MM-DD HH:MM:SS):");
                ui.text_edit_singleline(&mut state.ts_input);
                if primary_button(ui, state, "Convert").clicked() {
                    convert_ts(state);
                }
                if !state.ts_output.is_empty() {
                    ui.code(&state.ts_output.clone());
                }
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Cron", |ui| {
                ui.set_width(ui.available_width());
                ui.label("5 fields: minute hour day-of-month month day-of-week");
                ui.text_edit_singleline(&mut state.cron_expr);
                if primary_button(ui, state, "Preview schedule").clicked() {
                    match parse_cron(&state.cron_expr) {
                        Ok(c) => {
                            let mut out = format!("{}\n", describe(&c));
                            for r in next_runs(&c, 5) {
                                out.push_str(&format!("{}\n", r.format("%Y-%m-%d %H:%M (%a)")));
                            }
                            state.cron_output = out;
                            state.set_status(true, "Schedule computed.");
                            state.log("Cron", "schedule previewed");
                        }
                        Err(e) => state.set_status(false, format!("{e}")),
                    }
                }
                if !state.cron_output.is_empty() {
                    ui.code(&state.cron_output.clone());
                }
            });
        });
    });
}

fn convert_ts(state: &mut AppState) {
    use chrono::{Local, TimeZone};
    let t = state.ts_input.trim();
    let now = Local::now().timestamp();
    let out = if t.is_empty() {
        let n = Local::now();
        format!("epoch: {}\nRFC3339: {}\nUTC: {}", n.timestamp(), n.to_rfc3339(), n.to_utc().to_rfc3339())
    } else if let Ok(epoch) = t.parse::<i64>() {
        match Local.timestamp_opt(epoch, 0).single() {
            Some(dt) => format!("local: {}\nRFC3339: {}\nUTC: {}\nrelative: {}", dt.format("%Y-%m-%d %H:%M:%S"), dt.to_rfc3339(), dt.to_utc().to_rfc3339(), rel_time(epoch, now)),
            None => "Epoch out of range.".to_string(),
        }
    } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t) {
        let e = dt.timestamp();
        format!("epoch: {e}\nlocal: {}\nrelative: {}", dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S"), rel_time(e, now))
    } else if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S") {
        match Local.from_local_datetime(&naive).single() {
            Some(dt) => {
                let e = dt.timestamp();
                format!("epoch: {e}\nRFC3339: {}\nrelative: {}", dt.to_rfc3339(), rel_time(e, now))
            }
            None => "Ambiguous local time.".to_string(),
        }
    } else {
        "Could not parse. Try epoch seconds or 2026-09-21 10:30:00.".to_string()
    };
    state.ts_output = out;
    state.log("Time", "timestamp converted");
}

pub fn show_regex(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "Regex Tester", "Rust regex syntax. Matches highlight inline; groups listed below.");
    card(ui, "Pattern", |ui| {
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut state.rx_pattern);
            ui.checkbox(&mut state.rx_insensitive, "case-insensitive");
            if primary_button(ui, state, "Test").clicked() {
                test_regex(state);
            }
        });
    });
    ui.add_space(6.0);
    card(ui, "Text", |ui| {
        ui.add(egui::TextEdit::multiline(&mut state.rx_text).desired_rows(6).desired_width(f32::INFINITY));
    });
    if !state.rx_output.is_empty() {
        ui.add_space(6.0);
        card(ui, "Matches", |ui| {
            ui.monospace(&state.rx_output.clone());
        });
    }
}

fn test_regex(state: &mut AppState) {
    let pat = if state.rx_insensitive {
        format!("(?i){}", state.rx_pattern)
    } else {
        state.rx_pattern.clone()
    };
    match regex::Regex::new(&pat) {
        Ok(re) => {
            let mut out = String::new();
            let mut n = 0;
            for m in re.find_iter(&state.rx_text).take(200) {
                n += 1;
                out.push_str(&format!("#{n} [{}..{}]: {:?}\n", m.start(), m.end(), m.as_str()));
            }
            if n == 0 {
                out.push_str("No matches.\n");
            }
            // Capture groups of first match.
            if let Some(caps) = re.captures(&state.rx_text) {
                out.push_str("Groups (first match):\n");
                for (i, g) in caps.iter().enumerate().take(12) {
                    out.push_str(&format!("  ${i}: {:?}\n", g.map(|m| m.as_str())));
                }
            }
            state.rx_output = out;
            state.set_status(true, format!("{n} match(es)."));
            state.log("Regex", "pattern tested");
        }
        Err(e) => {
            state.rx_output.clear();
            state.set_status(false, format!("Invalid regex: {e}"));
        }
    }
}

pub fn show_diff(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "Diff Viewer", "Line diff of two texts. Additions green, deletions red.");
    ui.columns(2, |cols| {
        cols[0].label("Original (A)");
        cols[0].add(egui::TextEdit::multiline(&mut state.diff_a).code_editor().desired_rows(12).desired_width(f32::INFINITY));
        cols[1].label("Modified (B)");
        cols[1].add(egui::TextEdit::multiline(&mut state.diff_b).code_editor().desired_rows(12).desired_width(f32::INFINITY));
    });
    if primary_button(ui, state, "Compare").clicked() {
        state.log("Diff", "texts compared");
        state.set_status(true, "Compared.");
    }
    let ops = diff_lines(&state.diff_a, &state.diff_b);
    if ops.is_empty() {
        return;
    }
    card(ui, "Result", |ui| {
        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
            for op in ops {
                let (prefix, text, color) = match &op {
                    DiffOp::Same(s) => ("  ", s.clone(), ui.style().visuals.weak_text_color()),
                    DiffOp::Del(s) => ("− ", s.clone(), crate::app::theme::ERROR),
                    DiffOp::Add(s) => ("+ ", s.clone(), crate::app::theme::SUCCESS),
                };
                ui.monospace(egui::RichText::new(format!("{prefix}{text}")).color(color));
            }
        });
    });
    info_box(ui, "Capped at 2000 lines per side to keep the comparison instant.");
}

fn wifi_uri(ssid: &str, pass: &str, enc: &str) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace(';', "\\;").replace(',', "\\,").replace(':', "\\:")
    }
    if enc.eq_ignore_ascii_case("nopass") || pass.is_empty() {
        format!("WIFI:T:nopass;S:{};;", esc(ssid))
    } else {
        let t = if enc.eq_ignore_ascii_case("wep") { "WEP" } else { "WPA" };
        format!("WIFI:T:{t};S:{};P:{};;", esc(ssid), esc(pass))
    }
}

pub fn show_qr(_ctx: &egui::Context, ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "QR Codes", "Text, URLs, Wi-Fi credentials, otpauth URIs → scannable QR (unicode preview + SVG export).");
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(380.0);
            card(ui, "Content", |ui| {
                egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut state.qr_text).desired_rows(4).desired_width(f32::INFINITY));
                });
                if primary_button(ui, state, "Render QR").clicked() {
                    render_qr(state);
                }
                ui.horizontal(|ui| {
                    if ui.button("Save SVG").clicked() {
                        if state.qr_svg.is_empty() {
                            state.set_status(false, "Render a QR first.");
                        } else if let Some(p) = rfd::FileDialog::new().set_file_name("qr.svg").save_file() {
                            match std::fs::write(&p, state.qr_svg.as_bytes()) {
                                Ok(()) => state.set_status(true, "SVG saved."),
                                Err(e) => state.set_status(false, format!("File could not be written: {e}")),
                            }
                        }
                    }
                    let svg = state.qr_svg.clone();
                    copy_button(ui, state, "SVG", &svg);
                })
            });
            ui.add_space(6.0);
            card(ui, "Wi-Fi helper", |ui| {
                ui.label("SSID");
                ui.text_edit_singleline(&mut state.wifi_ssid);
                ui.label("Password");
                ui.text_edit_singleline(&mut state.wifi_pass);
                egui::ComboBox::from_label("Security")
                    .selected_text(&state.wifi_enc)
                    .show_ui(ui, |ui| {
                        for e in ["WPA", "WEP", "nopass"] {
                            ui.selectable_value(&mut state.wifi_enc, e.to_string(), e);
                        }
                    });
                if ui.button("Use Wi-Fi URI").clicked() {
                    state.qr_text = wifi_uri(&state.wifi_ssid.clone(), &state.wifi_pass.clone(), &state.wifi_enc.clone());
                    render_qr(state);
                }
            });
        });
        ui.add_space(8.0);
        ui.vertical(|ui| {
            card(ui, "Preview", |ui| {
                ui.set_width(ui.available_width());
                if state.qr_unicode.is_empty() {
                    ui.weak("Nothing rendered yet.");
                } else {
                    egui::ScrollArea::both().max_height(420.0).show(ui, |ui| {
                        ui.monospace(&state.qr_unicode.clone());
                    });
                }
            });
            info_box(ui, "QR encodes data visibly — anyone scanning it reads the content. Never encode secrets you wouldn't print.");
        });
    });
}

fn render_qr(state: &mut AppState) {
    if state.qr_text.trim().is_empty() {
        state.set_status(false, "Enter content first.");
        return;
    }
    if state.qr_text.len() > 2000 {
        state.set_status(false, "Content too long for a reliable QR (max 2000 chars).");
        return;
    }
    match qrcode::QrCode::new(state.qr_text.as_bytes()) {
        Ok(code) => {
            state.qr_unicode = code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(false).build();
            state.qr_svg = code.render::<qrcode::render::svg::Color>().build();
            state.set_status(true, "QR rendered.");
            state.log("QR", "code rendered");
        }
        Err(e) => {
            state.qr_unicode.clear();
            state.qr_svg.clear();
            state.set_status(false, format!("QR failed: {e}"));
        }
    }
}
