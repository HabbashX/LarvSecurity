//! Precision-instrument theme: neutral zinc surfaces, hairline borders,
//! ONE user-chosen accent, typography-led hierarchy. No gradients on
//! chrome, no glyph soup, no glow spam.

use egui::style::WidgetVisuals;
use egui::{Color32, Stroke, Visuals};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    #[default]
    Dark,
    Light,
    System,
}

impl ThemeMode {
    pub fn label(self) -> &'static str {
        match self {
            ThemeMode::Dark => "Dark",
            ThemeMode::Light => "Light",
            ThemeMode::System => "System",
        }
    }
    pub fn all() -> &'static [ThemeMode] {
        &[ThemeMode::Dark, ThemeMode::Light, ThemeMode::System]
    }
}

/// User-selectable accent. Everything else stays monochrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccentChoice {
    #[default]
    Sage,
    Indigo,
    Cyan,
    Emerald,
    Amber,
    Rose,
    Violet,
}

impl AccentChoice {
    pub fn label(self) -> &'static str {
        match self {
            AccentChoice::Sage => "Sage",
            AccentChoice::Indigo => "Indigo",
            AccentChoice::Cyan => "Cyan",
            AccentChoice::Emerald => "Emerald",
            AccentChoice::Amber => "Amber",
            AccentChoice::Rose => "Rose",
            AccentChoice::Violet => "Violet",
        }
    }
    pub fn all() -> &'static [AccentChoice] {
        &[
            AccentChoice::Sage,
            AccentChoice::Indigo,
            AccentChoice::Cyan,
            AccentChoice::Emerald,
            AccentChoice::Amber,
            AccentChoice::Rose,
            AccentChoice::Violet,
        ]
    }
    pub fn color(self) -> Color32 {
        match self {
            AccentChoice::Sage => Color32::from_rgb(0xAF, 0xCA, 0x78),
            AccentChoice::Indigo => Color32::from_rgb(99, 102, 241),
            AccentChoice::Cyan => Color32::from_rgb(6, 182, 212),
            AccentChoice::Emerald => Color32::from_rgb(16, 185, 129),
            AccentChoice::Amber => Color32::from_rgb(245, 158, 11),
            AccentChoice::Rose => Color32::from_rgb(244, 63, 94),
            AccentChoice::Violet => Color32::from_rgb(139, 92, 246),
        }
    }
    /// Readable variant of the accent for text on dark surfaces.
    pub fn bright(self) -> Color32 {
        match self {
            AccentChoice::Sage => Color32::from_rgb(0xC9, 0xE0, 0x9E),
            AccentChoice::Indigo => Color32::from_rgb(129, 140, 248),
            AccentChoice::Cyan => Color32::from_rgb(34, 211, 238),
            AccentChoice::Emerald => Color32::from_rgb(52, 211, 153),
            AccentChoice::Amber => Color32::from_rgb(251, 191, 36),
            AccentChoice::Rose => Color32::from_rgb(251, 113, 133),
            AccentChoice::Violet => Color32::from_rgb(167, 139, 250),
        }
    }
    /// Darker shade used for pressed states.
    pub fn deep(self) -> Color32 {
        match self {
            AccentChoice::Sage => Color32::from_rgb(0x6E, 0x87, 0x46),
            AccentChoice::Indigo => Color32::from_rgb(67, 56, 202),
            AccentChoice::Cyan => Color32::from_rgb(14, 116, 144),
            AccentChoice::Emerald => Color32::from_rgb(4, 120, 87),
            AccentChoice::Amber => Color32::from_rgb(180, 83, 9),
            AccentChoice::Rose => Color32::from_rgb(190, 18, 60),
            AccentChoice::Violet => Color32::from_rgb(109, 40, 217),
        }
    }
}

// Status colors (fixed; not part of the accent system).
pub const SUCCESS: Color32 = Color32::from_rgb(52, 211, 153);
pub const WARNING: Color32 = Color32::from_rgb(251, 191, 36);
pub const ERROR: Color32 = Color32::from_rgb(248, 113, 113);
pub const INFO: Color32 = Color32::from_rgb(56, 189, 248);

fn widget(fill: Color32, stroke: Color32, fg: Color32, radius: u8) -> WidgetVisuals {
    WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, stroke),
        fg_stroke: Stroke::new(1.0, fg),
        corner_radius: egui::CornerRadius::same(radius),
        expansion: 0.0,
    }
}

/// Full appearance bundle applied from `AppearanceSettings`.
pub fn apply_theme(
    ctx: &egui::Context,
    mode: ThemeMode,
    accent: AccentChoice,
    base_size: f32,
    mono_ui: bool,
    radius: u8,
) {
    let dark = match mode {
        ThemeMode::Dark => true,
        ThemeMode::Light => false,
        ThemeMode::System => ctx.style().visuals.dark_mode,
    };
    let mut visuals = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let a = accent.color();
    let ab = accent.bright();
    let ad = accent.deep();

    if dark {
        // Zinc-tinted charcoal. Translucent enough for the ambient
        // backdrop to read through; opaque enough for text contrast.
        visuals.panel_fill = Color32::from_rgba_unmultiplied(15, 18, 26, 190);
        visuals.window_fill = Color32::from_rgba_unmultiplied(18, 22, 32, 202);
        visuals.extreme_bg_color = Color32::from_rgb(8, 10, 16);
        visuals.code_bg_color = Color32::from_rgb(21, 26, 38);
        visuals.faint_bg_color = Color32::from_rgb(21, 26, 38);
        visuals.widgets.noninteractive.bg_stroke =
            Stroke::new(1.0, Color32::from_rgb(44, 51, 70));
        visuals.widgets.inactive = widget(
            Color32::from_rgb(26, 32, 46),
            Color32::from_rgb(58, 66, 90),
            Color32::from_rgb(226, 232, 240),
            radius,
        );
        visuals.widgets.hovered = widget(Color32::from_rgb(34, 41, 59), ab, Color32::WHITE, radius);
        visuals.widgets.active = widget(ad, ab, Color32::WHITE, radius);
        visuals.widgets.open =
            widget(Color32::from_rgb(30, 37, 54), a, Color32::from_rgb(226, 232, 240), radius);
        visuals.selection.bg_fill = a;
        visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
        visuals.hyperlink_color = ab;
        visuals.collapsing_header_frame = true;
        visuals.indent_has_left_vline = true;
    } else {
        visuals.panel_fill = Color32::from_rgba_unmultiplied(246, 248, 252, 198);
        visuals.window_fill = Color32::from_rgba_unmultiplied(252, 253, 255, 210);
        visuals.extreme_bg_color = Color32::from_rgb(229, 233, 242);
        visuals.code_bg_color = Color32::from_rgb(236, 240, 248);
        visuals.faint_bg_color = Color32::from_rgb(236, 240, 248);
        visuals.widgets.noninteractive.bg_stroke =
            Stroke::new(1.0, Color32::from_rgb(205, 214, 230));
        visuals.widgets.inactive = widget(
            Color32::WHITE,
            Color32::from_rgb(180, 192, 214),
            Color32::from_rgb(30, 41, 59),
            radius,
        );
        visuals.widgets.hovered =
            widget(Color32::from_rgb(232, 237, 250), a, Color32::from_rgb(30, 41, 59), radius);
        visuals.widgets.active = widget(a, ad, Color32::WHITE, radius);
        visuals.selection.bg_fill = a;
        visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
        visuals.hyperlink_color = ad;
        visuals.collapsing_header_frame = true;
        visuals.indent_has_left_vline = true;
    }
    ctx.set_visuals(visuals);

    let ui_font = if mono_ui {
        egui::FontFamily::Monospace
    } else {
        egui::FontFamily::Proportional
    };
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(14.0, 7.0);
    style.spacing.indent = 18.0;
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(base_size + 5.5, ui_font.clone()),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(base_size, ui_font.clone()),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(base_size - 0.5, egui::FontFamily::Monospace),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(base_size - 0.5, ui_font.clone()),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::new((base_size - 2.0).max(9.0), ui_font),
    );
    ctx.set_style(style);
}

/// Install a user-supplied font file as an additional family.
pub fn install_custom_font(ctx: &egui::Context, name: &str, bytes: &[u8]) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        name.to_owned(),
        egui::FontData::from_owned(bytes.to_vec()).into(),
    );
    if let Some(proportional) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        proportional.insert(0, name.to_owned());
    }
    ctx.set_fonts(fonts);
}
