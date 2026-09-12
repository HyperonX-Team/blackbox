//! BLACKBOX GUI - Project manager, YAML editor, and package builder
//
// Do not open a console window on Windows in release builds: this is a GUI app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use blackbox_runtime::gui::app::BlackboxApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(load_icon()),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "BLACKBOX - Portable Computational Appliances",
        options,
        Box::new(|cc| Ok(Box::new(BlackboxApp::new(cc)))),
    )
}

fn load_icon() -> egui::IconData {
    // Simple fallback icon - in production you'd load from assets
    let size = 32;
    let mut pixels = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let i = (y * size + x) * 4;
            let cx = x as f32 - size as f32 / 2.0;
            let cy = y as f32 - size as f32 / 2.0;
            let dist = (cx * cx + cy * cy).sqrt();
            if dist < size as f32 / 2.5 {
                pixels[i] = 0x1a;     // R
                pixels[i + 1] = 0x1a; // G
                pixels[i + 2] = 0x2e; // B
                pixels[i + 3] = 0xff; // A
            } else if dist < size as f32 / 2.0 {
                pixels[i] = 0x00;     // R
                pixels[i + 1] = 0xd4; // G
                pixels[i + 2] = 0xff; // B
                pixels[i + 3] = 0xff; // A
            }
        }
    }
    egui::IconData { rgba: pixels, width: size as u32, height: size as u32 }
}