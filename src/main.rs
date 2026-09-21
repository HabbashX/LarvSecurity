mod app;
mod crypto;
mod models;
mod ui;
mod utils;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Security Toolkit"),
        ..Default::default()
    };
    eframe::run_native(
        "Security Toolkit",
        options,
        Box::new(|cc| Ok(Box::new(app::ToolkitApp::new(cc)))),
    )
}
