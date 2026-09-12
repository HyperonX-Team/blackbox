//! Pack dialog

use egui::{RichText, Id};
use std::path::PathBuf;

#[derive(Default)]
pub struct PackDialog {
    pub show: bool,
    pub pack_requested: bool,
    pub output_path: Option<String>,
    pub target: Option<String>,
    pub thin: bool,
    pub watch: bool,
    pub run_after: bool,
}

impl PackDialog {
    pub fn new() -> Self { Self::default() }

    /// Draw the dialog. Manages its own `show` state.
    pub fn draw(&mut self, ctx: &egui::Context, project_path: &Option<PathBuf>) {
        if !self.show {
            return;
        }
        let mut open = self.show;
        let mut close_requested = false;

        egui::Window::new("Pack Package")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(500.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("Build .blackbox package").strong());
                    ui.add_space(10.0);

                    // Output path
                    ui.horizontal(|ui| {
                        ui.label("Output:");
                        ui.text_edit_singleline(self.output_path.get_or_insert_with(String::new));
                        if ui.button("Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Save package as")
                                .add_filter("BLACKBOX", &["blackbox"])
                                .set_file_name(project_path.as_ref()
                                    .and_then(|p| p.file_name())
                                    .map(|n| format!("{}.blackbox", n.to_string_lossy()))
                                    .unwrap_or_else(|| "package.blackbox".to_string()))
                                .save_file() {
                                self.output_path = Some(path.display().to_string());
                            }
                        }
                    });

                    ui.add_space(8.0);

                    // Target
                    ui.horizontal(|ui| {
                        ui.label("Target:");
                        let current = crate::platform::current_triple();
                        let mut target = self.target.clone().unwrap_or(current.clone());
                        egui::ComboBox::new(Id::new("pack_target"), "")
                            .selected_text(&target)
                            .show_ui(ui, |ui| {
                                for t in crate::platform::SUPPORTED_TARGETS {
                                    ui.selectable_value(&mut target, t.0.to_string(), format!("{} ({}/{})", t.0, t.1.os, t.1.arch));
                                }
                                ui.selectable_value(&mut target, current.clone(), format!("{} (current)", current));
                            });
                        self.target = Some(target);
                    });

                    ui.add_space(8.0);

                    // Options
                    ui.checkbox(&mut self.thin, "Thin package (no layer blobs, fetch from mirrors)");
                    ui.checkbox(&mut self.watch, "Watch mode (re-pack on file changes)");
                    if self.watch {
                        ui.checkbox(&mut self.run_after, "Run after each re-pack");
                    }

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close_requested = true;
                        }
                        if ui.button("Pack").clicked() {
                            self.pack_requested = true;
                            close_requested = true;
                        }
                    });
                });
            });

        self.show = open && !close_requested;
    }
}
