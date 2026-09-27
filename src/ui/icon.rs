//! Application icon: procedural raster replica of `assets/icon.svg`
//! (navy rounded square, light padlock body, shackle, keyhole).
//! Drawn per-pixel at startup — no image decoding dependencies.

const NAVY: [u8; 3] = [0x0C, 0x22, 0x3B];
const LIGHT: [u8; 3] = [0xE6, 0xF1, 0xFB];

/// Render the icon at `size`×`size` RGBA pixels.
pub fn render_rgba(size: u32) -> Vec<u8> {
    let s = size as f32 / 522.0; // SVG viewBox units → pixels
    let px = |x: f32, y: f32| (x * s, y * s);

    // Shackle centerline: left bar, top arc, right bar.
    let mut spine: Vec<(f32, f32)> = Vec::new();
    let (x0, y0) = px(196.0, 240.0);
    let (x1, y1) = px(196.0, 190.0);
    let (x2, y2) = px(316.0, 190.0);
    let (x3, y3) = px(316.0, 240.0);
    let mut t = 0.0;
    while t <= 1.0 {
        spine.push((x0 + (x1 - x0) * t, y0 + (y1 - y0) * t));
        t += 1.0 / 60.0;
    }
    // Top arc: half-ellipse centered ((196+316)/2, 190), rx=60, ry=72.
    let (ccx, ccy) = px(256.0, 190.0);
    let (rx, ry) = (60.0 * s, 72.0 * s);
    let mut a = std::f32::consts::PI;
    while a >= 0.0 {
        spine.push((ccx + rx * a.cos(), ccy - ry * a.sin()));
        a -= std::f32::consts::PI / 90.0;
    }
    let mut t = 0.0;
    while t <= 1.0 {
        spine.push((x2 + (x3 - x2) * t, y2 + (y3 - y2) * t));
        t += 1.0 / 60.0;
    }
    let shackle_r = 13.0 * s;

    let (bx, by, bw, bh, br) = (176.0 * s, 240.0 * s, 160.0 * s, 130.0 * s, 20.0 * s);
    let (kx, ky, kr) = (256.0 * s, 295.0 * s, 18.0 * s);
    let (sx, sy, sw, sh, sr) = (246.0 * s, 300.0 * s, 20.0 * s, 40.0 * s, 8.0 * s);
    let bg_r = 100.0 * s;

    let mut out = vec![0u8; (size * size * 4) as usize];
    for py in 0..size {
        for px_ in 0..size {
            let fx = px_ as f32 + 0.5;
            let fy = py as f32 + 0.5;
            // Base: navy rounded square.
            let mut col = NAVY;
            // Shackle (under body, over background).
            let mut on_shackle = false;
            for (sx_, sy_) in &spine {
                let dx = fx - sx_;
                let dy = fy - sy_;
                if dx * dx + dy * dy <= shackle_r * shackle_r {
                    on_shackle = true;
                    break;
                }
            }
            if on_shackle {
                col = LIGHT;
            }
            // Padlock body.
            if in_rounded_rect(fx, fy, bx, by, bw, bh, br) {
                col = LIGHT;
            }
            // Keyhole (circle + stem) punched in navy.
            let kdx = fx - kx;
            let kdy = fy - ky;
            if kdx * kdx + kdy * kdy <= kr * kr
                || in_rounded_rect(fx, fy, sx, sy, sw, sh, sr)
            {
                col = NAVY;
            }
            // Clip everything to the outer rounded square.
            if !in_rounded_rect(fx, fy, 0.0, 0.0, size as f32, size as f32, bg_r) {
                col = NAVY;
            }
            let o = ((py * size + px_) * 4) as usize;
            out[o] = col[0];
            out[o + 1] = col[1];
            out[o + 2] = col[2];
            out[o + 3] = 255;
        }
    }
    out
}

fn in_rounded_rect(x: f32, y: f32, rx: f32, ry: f32, w: f32, h: f32, r: f32) -> bool {
    if x < rx || x > rx + w || y < ry || y > ry + h {
        return false;
    }
    let cx = (x - rx).min(rx + w - x).min(r);
    let cy = (y - ry).min(ry + h - y).min(r);
    if cx >= r || cy >= r {
        return true;
    }
    let dx = r - cx;
    let dy = r - cy;
    dx * dx + dy * dy <= r * r
}

/// Window/taskbar icon for eframe.
pub fn window_icon() -> egui::IconData {
    const SIZE: u32 = 256;
    egui::IconData {
        rgba: render_rgba(SIZE),
        width: SIZE,
        height: SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_buffer_shape_and_colors() {
        let px = render_rgba(256);
        assert_eq!(px.len(), 256 * 256 * 4);
        // Opaque everywhere.
        assert!(px.chunks_exact(4).all(|p| p[3] == 255));
        let at = |x: u32, y: u32| -> [u8; 3] {
            let o = ((y * 256 + x) * 4) as usize;
            [px[o], px[o + 1], px[o + 2]]
        };
        // Corner background is navy.
        assert_eq!(at(128, 10), NAVY);
        // Padlock body (left of the keyhole) is light.
        assert_eq!(at(100, 140), LIGHT);
        // Keyhole is navy.
        assert_eq!(at(128, 145), NAVY);
    }
}

/// Paint a mini padlock (same artwork) into a painter rect, e.g. About page.
pub fn paint_padlock(painter: &egui::Painter, rect: egui::Rect) {
    let navy = egui::Color32::from_rgb(0x0C, 0x22, 0x3B);
    let light = egui::Color32::from_rgb(0xE6, 0xF1, 0xFB);
    painter.rect_filled(rect, egui::CornerRadius::same((rect.width() * 0.19) as u8), navy);
    let u = rect.width() / 522.0;
    let pt = |x: f32, y: f32| egui::pos2(rect.min.x + x * u, rect.min.y + y * u);
    // Shackle: squared-U out of three bars, tucked behind the body.
    let w = 26.0 * u;
    let leg_y0 = 190.0 * u + rect.min.y;
    let leg_y1 = 248.0 * u + rect.min.y;
    let lx = 196.0 * u + rect.min.x;
    let rx = 316.0 * u + rect.min.x;
    painter.line_segment([egui::pos2(lx, leg_y1), egui::pos2(lx, leg_y0)], egui::Stroke::new(w, light));
    painter.line_segment([egui::pos2(rx, leg_y1), egui::pos2(rx, leg_y0)], egui::Stroke::new(w, light));
    painter.line_segment([egui::pos2(lx, leg_y0), egui::pos2(rx, leg_y0)], egui::Stroke::new(w, light));
    // Body.
    painter.rect_filled(
        egui::Rect::from_min_max(pt(176.0, 240.0), pt(336.0, 370.0)),
        egui::CornerRadius::same((20.0 * u) as u8),
        light,
    );
    // Keyhole.
    painter.circle_filled(pt(256.0, 295.0), 18.0 * u, navy);
    painter.rect_filled(
        egui::Rect::from_min_max(pt(246.0, 300.0), pt(266.0, 340.0)),
        egui::CornerRadius::same((8.0 * u) as u8),
        navy,
    );
}
