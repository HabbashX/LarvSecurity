use eframe::egui;

use crate::app::state::AppState;
use crate::crypto::encoding::*;
use crate::ui::components::{copy_button, danger_button, header, info_box, primary_button};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    B64Enc,
    B64Dec,
    B64UrlEnc,
    B64UrlDec,
    HexEnc,
    HexDec,
    UrlEnc,
    UrlDec,
}

impl Op {
    fn label(self) -> &'static str {
        match self {
            Op::B64Enc => "Base64 encode",
            Op::B64Dec => "Base64 decode",
            Op::B64UrlEnc => "Base64URL encode",
            Op::B64UrlDec => "Base64URL decode",
            Op::HexEnc => "Hex encode",
            Op::HexDec => "Hex decode",
            Op::UrlEnc => "URL encode",
            Op::UrlDec => "URL decode",
        }
    }
}

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    header(ui, "Encoding", "Text codecs for transport and inspection — encoding is not encryption.");
    info_box(ui, "Base64 / hex / URL-encoding provide zero confidentiality. Anyone can reverse them.");

    // Operation kept in a local static via egui memory to avoid widening AppState.
    let op_id = egui::Id::new("encoding_op");
    let mut op: Op = ctx_op(ui, op_id);
    egui::ComboBox::from_label("Operation")
        .selected_text(op.label())
        .show_ui(ui, |ui| {
            for o in [Op::B64Enc, Op::B64Dec, Op::B64UrlEnc, Op::B64UrlDec, Op::HexEnc, Op::HexDec, Op::UrlEnc, Op::UrlDec] {
                ui.selectable_value(&mut op, o, o.label());
            }
        });
    ui.ctx().data_mut(|d| d.insert_temp(op_id, op));

    ui.label("Input:");
    ui.add(
        egui::TextEdit::multiline(&mut state.enc_text_input)
            .code_editor()
            .desired_rows(6)
            .desired_width(f32::INFINITY),
    );
    ui.horizontal(|ui| {
        if primary_button(ui, state, "Convert").clicked() {
            state.enc_text_output = convert(op, &state.enc_text_input);
            if state.enc_text_output.starts_with("Error:") {
                state.set_status(false, state.enc_text_output.clone());
            } else {
                state.set_status(true, "Converted.");
            }
        }
        if ui.button("Swap").clicked() {
            std::mem::swap(&mut state.enc_text_input, &mut state.enc_text_output);
        }
        if danger_button(ui, "Clear").clicked() {
            state.enc_text_input.clear();
            state.enc_text_output.clear();
        }
    });
    ui.label("Output:");
    ui.add(
        egui::TextEdit::multiline(&mut state.enc_text_output)
            .code_editor()
            .desired_rows(6)
            .desired_width(f32::INFINITY),
    );
    let out = state.enc_text_output.clone();
    copy_button(ui, state, "encoded text", &out);
}

fn ctx_op(ui: &egui::Ui, id: egui::Id) -> Op {
    ui.ctx().data(|d| d.get_temp::<Op>(id)).unwrap_or(Op::B64Enc)
}

fn convert(op: Op, input: &str) -> String {
    match op {
        Op::B64Enc => base64_encode(input.as_bytes()),
        Op::B64Dec => match base64_decode(input) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => format!("Error: {e}"),
        },
        Op::B64UrlEnc => base64url_encode(input.as_bytes()),
        Op::B64UrlDec => match base64url_decode(input) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => format!("Error: {e}"),
        },
        Op::HexEnc => hex_encode(input.as_bytes()),
        Op::HexDec => match hex_decode(input) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => format!("Error: {e}"),
        },
        Op::UrlEnc => url_encode(input),
        Op::UrlDec => match url_decode(input) {
            Ok(s) => s,
            Err(e) => format!("Error: {e}"),
        },
    }
}
