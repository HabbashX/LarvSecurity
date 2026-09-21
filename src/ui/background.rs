//! Ambient workspace backdrop: large wireframe geometries floating in
//! space — rotating cubes, diamonds, pyramids, hexagons — over a faint
//! dot grid with soft aurora washes. Painted on the background layer;
//! panels are translucent so the motion reads through.
//!
//! Deterministic layout (seeded PRNG) — stable across repaints.

use eframe::egui;
use egui::{Color32, Pos2};

use crate::app::theme::AccentChoice;

#[derive(Clone, Copy)]
enum Kind {
    Cube,
    Diamond,
    Pyramid,
    Triangle,
    Hex,
    Cross,
}

#[derive(Clone, Copy)]
struct Floater {
    kind: Kind,
    fx: f32,
    fy: f32,
    size: f32,
    drift_amp: f32,
    drift_speed: f32,
    phase: f32,
    spin: f32,
    color_idx: usize,
    alpha: u8,
}

fn mulberry(seed: &mut u32) -> f32 {
    *seed = seed.wrapping_add(0x6D2B_79F5);
    let mut t = *seed;
    t = t.wrapping_mul(t ^ (*seed >> 15)).wrapping_add(0x6D2B_79F5);
    t ^= t.wrapping_add(t.wrapping_mul(t ^ 7) ^ (*seed >> 8));
    (t as f32) / (u32::MAX as f32)
}

fn floaters() -> Vec<Floater> {
    let mut seed = 0x60E17C_u32;
    let mut out = Vec::new();
    // 13 large shapes spread across the content area (skip the sidebar).
    for i in 0..13 {
        let kind = match i % 6 {
            0 => Kind::Cube,
            1 => Kind::Diamond,
            2 => Kind::Pyramid,
            3 => Kind::Triangle,
            4 => Kind::Hex,
            _ => Kind::Cross,
        };
        let fx = 0.20 + mulberry(&mut seed) * 0.76;
        let fy = 0.08 + mulberry(&mut seed) * 0.86;
        out.push(Floater {
            kind,
            fx: fx.min(0.98),
            fy: fy.min(0.98),
            size: 48.0 + mulberry(&mut seed) * 82.0,
            drift_amp: 20.0 + mulberry(&mut seed) * 42.0,
            drift_speed: 0.12 + mulberry(&mut seed) * 0.22,
            phase: mulberry(&mut seed) * std::f32::consts::TAU,
            spin: 0.15 + mulberry(&mut seed) * 0.35,
            color_idx: i % 3,
            alpha: 95 + (mulberry(&mut seed) * 45.0) as u8,
        });
    }
    out
}

fn poly_points(c: Pos2, radius: f32, sides: usize, rot: f32) -> Vec<Pos2> {
    (0..sides)
        .map(|i| {
            let a = rot + i as f32 * std::f32::consts::TAU / sides as f32;
            Pos2::new(c.x + radius * a.cos(), c.y + radius * a.sin())
        })
        .collect()
}

fn stroke_poly(painter: &egui::Painter, pts: &[Pos2], stroke: egui::Stroke) {
    painter.add(egui::Shape::convex_polygon(
        pts.to_vec(),
        Color32::TRANSPARENT,
        stroke,
    ));
}

fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

/// One soft blurred blob: many nested discs with a smooth
/// (1-t²)² falloff so no banding edges remain visible.
fn paint_blurred_blob(
    painter: &egui::Painter,
    center: Pos2,
    radius: f32,
    color: Color32,
    peak_alpha: u8,
) {
    const LAYERS: usize = 20;
    for i in (1..=LAYERS).rev() {
        let t = i as f32 / LAYERS as f32; // 1.0 at edge → ~0 at core
        let rr = radius * t;
        let falloff = (1.0 - t * t).powi(2);
        let a = (peak_alpha as f32 * falloff).clamp(0.0, 255.0) as u8;
        if a == 0 {
            continue;
        }
        painter.circle_filled(center, rr, tint(color, a));
    }
}

/// Full-window vertical gradient whose light band slowly rises and falls.
fn paint_animated_gradient(
    painter: &egui::Painter,
    rect: egui::Rect,
    accent: AccentChoice,
    dark: bool,
    time: f32,
) {
    const SLICES: usize = 64;
    let h = rect.height();
    if h <= 0.0 {
        return;
    }
    // Two light bands drifting at different speeds = flowing gradient.
    let band1 = 0.5 + 0.38 * (time * 0.10).sin();
    let band2 = 0.5 + 0.42 * (time * 0.063 + 2.1).cos();
    let (base, glow) = if dark {
        (
            Color32::from_rgb(8, 10, 16),
            accent.color(),
        )
    } else {
        (
            Color32::from_rgb(238, 241, 247),
            accent.color(),
        )
    };
    for i in 0..SLICES {
        let t = i as f32 / SLICES as f32;
        let g1 = (-((t - band1) * (t - band1)) / 0.045).exp();
        let g2 = (-((t - band2) * (t - band2)) / 0.09).exp();
        let strength = if dark {
            0.05 + 0.30 * g1 + 0.16 * g2
        } else {
            0.04 + 0.20 * g1 + 0.12 * g2
        };
        let s = strength.clamp(0.0, 0.42);
        let r = (base.r() as f32 + (glow.r() as f32 - base.r() as f32) * s) as u8;
        let g = (base.g() as f32 + (glow.g() as f32 - base.g() as f32) * s) as u8;
        let b = (base.b() as f32 + (glow.b() as f32 - base.b() as f32) * s) as u8;
        let y0 = rect.min.y + h * t;
        let y1 = rect.min.y + h * (i as f32 + 1.05) / SLICES as f32;
        painter.rect_filled(
            egui::Rect::from_min_max(egui::pos2(rect.min.x, y0), egui::pos2(rect.max.x, y1)),
            egui::CornerRadius::ZERO,
            Color32::from_rgb(r, g, b),
        );
    }
}

/// Paint the ambient backdrop. Call once per frame before panels.
/// When `motion` is false a single static frame is painted.
pub fn paint(ctx: &egui::Context, dark: bool, motion: bool, accent: AccentChoice) {
    let t = ctx.input(|i| i.time) as f32;
    let time = if motion { t } else { 0.0 };
    let painter = ctx.layer_painter(egui::LayerId::background());
    let rect = ctx.screen_rect();
    if rect.width() <= 0.0 {
        return;
    }

    let palette = [accent.color(), accent.bright(), accent.deep()];
    let vis = |a: u8| if dark { a } else { a.saturating_add(20) };

    // Animated gradient foundation: light bands flowing vertically.
    paint_animated_gradient(&painter, rect, accent, dark, time);

    // Blurred gradient blobs riding the gradient (slow Lissajous drift).
    // Big, soft, out-of-focus washes — the dominant backdrop element.
    let breathe = 1.0 + 0.05 * (time * 0.35).sin();
    let orbit_r = rect.width().min(rect.height()) * 0.28;
    let blobs = [
        // (cx, cy, radius, palette idx, peak alpha, x-speed, y-speed, phase)
        (0.50, 0.40, 460.0, 0usize, 34u8, 0.10, 0.13, 0.0),
        (0.54, 0.58, 420.0, 1usize, 30u8, 0.08, 0.10, 2.4),
        (0.46, 0.62, 340.0, 2usize, 36u8, 0.12, 0.08, 4.4),
        (0.50, 0.46, 560.0, 0usize, 18u8, 0.05, 0.06, 1.2),
    ];
    for (cx, cy, r, ci, peak, sx, sy, ph) in blobs {
        let c = Pos2::new(
            rect.min.x + rect.width() * cx + orbit_r * (time * sx + ph).cos(),
            rect.min.y + rect.height() * cy + orbit_r * 0.7 * (time * sy + ph * 1.3).sin(),
        );
        let rr = r * breathe;
        paint_blurred_blob(&painter, c, rr, palette[ci], vis(peak));
    }

    // Faint dot grid with travelling shimmer.
    let step = 44.0;
    let grid_col = if dark {
        Color32::from_rgb(148, 163, 184)
    } else {
        Color32::from_rgb(100, 116, 139)
    };
    let mut y = rect.min.y + 16.0;
    while y < rect.max.y {
        let mut x = rect.min.x + 16.0;
        while x < rect.max.x {
            let wave = (0.5 + 0.5 * ((x * 0.02 + y * 0.017 + time * 0.5).sin())) as f32;
            let a = vis((14.0 + wave * 22.0) as u8);
            painter.circle_filled(Pos2::new(x, y), 1.2, tint(grid_col, a));
            x += step;
        }
        y += step;
    }

    // Floating wireframe geometries.
    for f in floaters() {
        let cx = rect.min.x + rect.width() * f.fx
            + (time * f.drift_speed + f.phase).sin() * f.drift_amp;
        let cy = rect.min.y + rect.height() * f.fy
            + (time * f.drift_speed * 0.8 + f.phase * 1.7).cos() * f.drift_amp;
        let pulse = 0.92 + 0.08 * (time * 0.6 + f.phase).sin();
        let c = Pos2::new(cx, cy);
        let r = f.size * pulse;
        let dir = if f.phase > std::f32::consts::PI { 1.0 } else { -1.0 };
        let rot = f.phase + time * f.spin * dir;
        let col = tint(palette[f.color_idx], vis(f.alpha));
        let dim = tint(
            palette[f.color_idx],
            vis((f.alpha as f32 * 0.45) as u8),
        );
        let ghost = tint(
            palette[f.color_idx],
            vis((f.alpha as f32 * 0.18) as u8),
        );
        let stroke = egui::Stroke::new(1.75, col);
        let thin = egui::Stroke::new(1.25, dim);
        match f.kind {
            Kind::Cube => {
                // Wireframe cube: front face, offset back face, struts.
                let front = poly_points(c, r, 4, rot);
                let depth = r * 0.34;
                let back_c = Pos2::new(
                    c.x + depth * (time * 0.4 + f.phase).cos(),
                    c.y + depth * (time * 0.4 + f.phase).sin(),
                );
                let back = poly_points(back_c, r * 0.62, 4, rot + 0.35);
                for i in 0..4 {
                    painter.line_segment([front[i], back[i]], thin);
                }
                stroke_poly(&painter, &back, thin);
                stroke_poly(&painter, &front, stroke);
                painter.circle_filled(c, 2.5, col);
            }
            Kind::Diamond => {
                let outer = poly_points(c, r, 4, rot + std::f32::consts::FRAC_PI_4);
                let inner = poly_points(c, r * 0.62, 4, rot + std::f32::consts::FRAC_PI_4);
                stroke_poly(&painter, &inner, thin);
                for i in 0..4 {
                    painter.line_segment([outer[i], inner[i]], thin);
                }
                stroke_poly(&painter, &outer, stroke);
                painter.circle_filled(c, 2.5, col);
            }
            Kind::Pyramid => {
                // Triangle with apex struts to the base.
                let apex = Pos2::new(c.x + r * 0.9 * rot.cos(), c.y + r * 0.9 * rot.sin());
                let b1 = Pos2::new(c.x - r * 0.8 * rot.cos() - r * 0.5 * rot.sin(), c.y - r * 0.8 * rot.sin() + r * 0.5 * rot.cos());
                let b2 = Pos2::new(c.x - r * 0.8 * rot.cos() + r * 0.5 * rot.sin(), c.y - r * 0.8 * rot.sin() - r * 0.5 * rot.cos());
                let mid = Pos2::new((b1.x + b2.x) * 0.5, (b1.y + b2.y) * 0.5);
                painter.line_segment([apex, b1], stroke);
                painter.line_segment([apex, b2], stroke);
                painter.line_segment([b1, b2], stroke);
                painter.line_segment([apex, mid], thin);
                painter.circle_filled(apex, 3.0, col);
                painter.circle_filled(b1, 2.0, dim);
                painter.circle_filled(b2, 2.0, dim);
                // Faint echo triangle.
                let echo = poly_points(c, r * 1.25, 3, rot + 0.5);
                painter.add(egui::Shape::convex_polygon(echo, Color32::TRANSPARENT, egui::Stroke::new(1.0, ghost)));
            }
            Kind::Triangle => {
                let outer = poly_points(c, r, 3, rot);
                let inner = poly_points(c, r * 0.6, 3, rot);
                stroke_poly(&painter, &inner, thin);
                for i in 0..3 {
                    painter.line_segment([outer[i], inner[i]], thin);
                }
                stroke_poly(&painter, &outer, stroke);
            }
            Kind::Hex => {
                let outer = poly_points(c, r, 6, rot);
                let inner = poly_points(c, r * 0.63, 6, rot + 0.26);
                stroke_poly(&painter, &inner, thin);
                for i in 0..6 {
                    painter.line_segment([outer[i], inner[i]], thin);
                }
                stroke_poly(&painter, &outer, stroke);
                painter.circle_filled(c, 2.5, col);
            }
            Kind::Cross => {
                // Gyroscope: two rings + axis.
                let ring_r = r * 0.8;
                painter.circle_stroke(c, ring_r, egui::Stroke::new(1.0, dim));
                let (s, co) = (rot.sin(), rot.cos());
                let tip = Pos2::new(c.x + ring_r * co, c.y + ring_r * s);
                let tail = Pos2::new(c.x - ring_r * co, c.y - ring_r * s);
                painter.line_segment([tail, tip], stroke);
                painter.circle_filled(tip, 3.5, col);
                painter.circle_filled(tail, 3.5, col);
                painter.circle_stroke(c, 4.0, thin);
            }
        }
    }
}
