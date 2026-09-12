//! Run dialog

use crate as bb;
use egui::{RichText, Color32, Id};
use std::path::PathBuf;

#[derive(Default)]
pub struct RunDialog {
    pub show: bool,
    pub run_requested: bool,
    pub running: bool,
    pub work_dir: Option<String>,
    pub input_files: Vec<String>,
    pub yes: bool,
    pub data: bool,
    pub log: bool,
    pub entry: Option<String>,
    pub app_args: String,
}

impl RunDialog {
    pub fn new() -> Self { Self::default() }

    /// Draw the dialog. Manages its own `show` state.
    pub fn draw(&mut self, ctx: &egui::Context, package_path: &Option<PathBuf>) {
        if !self.show {
            return;
        }

        // Load entrypoints from package if available
        let mut entrypoints = vec!["main".to_string()];
        if let Some(path) = package_path {
            if let Ok(pkg) = bb::packaging::open_package(path) {
                entrypoints.extend(pkg.manifest.entrypoints.keys().cloned());
            }
        }

        let mut open = self.show;
        let mut close_requested = false;

        egui::Window::new("Run Package")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(500.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    if self.running {
                        ui.label(RichText::new("Running...").color(Color32::YELLOW).strong());
                        ui.add_space(10.0);
                        return;
                    }

                    ui.label(RichText::new("Execute .blackbox package").strong());
                    ui.add_space(10.0);

                    // Work directory
                    ui.horizontal(|ui| {
                        ui.label("Work dir:");
                        ui.text_edit_singleline(self.work_dir.get_or_insert_with(String::new));
                        if ui.button("Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.work_dir = Some(path.display().to_string());
                            }
                        }
                    });

                    ui.add_space(8.0);

                    // Input files
                    ui.label("Input files:");
                    ui.horizontal(|ui| {
                        let mut remove_idx: Option<usize> = None;
                        for (i, file) in self.input_files.iter().enumerate() {
                            ui.label(file);
                            if ui.small_button("x").clicked() {
                                remove_idx = Some(i);
                            }
                        }
                        if let Some(i) = remove_idx {
                            self.input_files.remove(i);
                        }
                        if ui.button("Add").clicked() {
                            if let Some(files) = rfd::FileDialog::new().pick_files() {
                                for f in files {
                                    self.input_files.push(f.display().to_string());
                                }
                            }
                        }
                    });

                    ui.add_space(8.0);

                    // Options
                    ui.checkbox(&mut self.yes, "Skip permission prompt (--yes)");
                    ui.checkbox(&mut self.data, "Persistent data directory (--data)");
                    ui.checkbox(&mut self.log, "Log output to ~/.blackbox/logs/ (--log)");

                    ui.add_space(8.0);

                    // Entrypoint
                    ui.horizontal(|ui| {
                        ui.label("Entrypoint:");
                        let mut entry = self.entry.clone().unwrap_or_else(|| "main".to_string());
                        egui::ComboBox::new(Id::new("run_entrypoint"), "")
                            .selected_text(&entry)
                            .show_ui(ui, |ui| {
                                for e in &entrypoints {
                                    ui.selectable_value(&mut entry, e.clone(), e);
                                }
                            });
                        self.entry = if entry == "main" { None } else { Some(entry) };
                    });

                    ui.add_space(8.0);

                    // App arguments
                    ui.label("App arguments:");
                    ui.text_edit_singleline(&mut self.app_args);

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            close_requested = true;
                        }
                        if ui.button("Run").clicked() {
                            self.run_requested = true;
                            close_requested = true;
                        }
                    });
                });
            });

        self.show = open && !close_requested;
    }
}
