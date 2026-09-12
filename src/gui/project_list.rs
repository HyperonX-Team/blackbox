//! Project list sidebar

use egui::{ScrollArea, Ui, RichText, Color32};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Default)]
pub struct ProjectList {
    filter: String,
}

impl ProjectList {
    pub fn new() -> Self { Self::default() }

    pub fn show(
        &mut self,
        ui: &mut Ui,
        projects: &mut BTreeMap<String, super::app::ProjectState>,
        selected: &mut Option<String>,
        show_new_project: &mut bool,
    ) {
        ui.vertical(|ui| {
            // Header
            ui.horizontal(|ui| {
                ui.heading("Projects");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("+").on_hover_text("New project").clicked() {
                        *show_new_project = true;
                    }
                });
            });
            ui.separator();

            // Filter
            ui.text_edit_singleline(&mut self.filter)
                .on_hover_text("Filter projects");

            ui.add_space(8.0);

            // Project list
            ScrollArea::vertical().show(ui, |ui| {
                let mut to_remove = None;
                for (name, entry) in projects.iter_mut() {
                    if !self.filter.is_empty() &&
                        !name.to_lowercase().contains(&self.filter.to_lowercase()) {
                        continue;
                    }

                    let is_selected = selected.as_ref() == Some(name);
                    let has_package = entry.last_packed.is_some();
                    let has_manifest = entry.manifest.is_some();

                    let response = ui.selectable_label(
                        is_selected,
                        RichText::new(name)
                            .color(if has_package { Color32::LIGHT_GREEN } else { Color32::WHITE })
                            .strong(),
                    );

                    // Status indicators
                    if response.hovered() || is_selected {
                        let mut status = Vec::new();
                        if has_manifest { status.push("✓ manifest"); }
                        if has_package { status.push("📦 packed"); }
                        if entry.manifest_modified { status.push("✏ modified"); }
                        if !status.is_empty() {
                            ui.label(RichText::new(status.join(" · ")).small().color(Color32::GRAY));
                        }
                    }

                    if response.clicked() {
                        *selected = Some(name.clone());
                    }

                    // Context menu
                    response.context_menu(|ui| {
                        if ui.button("Pack").clicked() {
                            ui.close_menu();
                        }
                        if ui.button("Run").clicked() {
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Open Folder").clicked() {
                            let _ = opener::open(&entry.path);
                            ui.close_menu();
                        }
                        if ui.button("Open in Terminal").clicked() {
                            open_terminal(&entry.path);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Remove from List").clicked() {
                            to_remove = Some(name.clone());
                            ui.close_menu();
                        }
                        if ui.button("Delete Project").clicked() {
                            if let Err(e) = std::fs::remove_dir_all(&entry.path) {
                                eprintln!("Failed to delete: {}", e);
                            } else {
                                to_remove = Some(name.clone());
                            }
                            ui.close_menu();
                        }
                    });
                }
                if let Some(name) = to_remove {
                    projects.remove(&name);
                    if selected.as_ref() == Some(&name) {
                        *selected = None;
                    }
                }

                if projects.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(50.0);
                        ui.label(RichText::new("No projects yet").color(Color32::GRAY));
                        ui.label(RichText::new("Click '+' to create one").small().color(Color32::GRAY));
                    });
                }
            });
        });
    }
}

fn open_terminal(path: &PathBuf) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", "cmd", "/k", "cd", &path.to_string_lossy()])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!("tell application \"Terminal\" to do script \"cd '{}'\"", path.display());
        let _ = std::process::Command::new("osascript").arg("-e").arg(&script).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let terminals = ["gnome-terminal", "konsole", "xterm", "alacritty", "kitty", "terminator"];
        for term in terminals {
            if std::process::Command::new("which").arg(term).output().map(|o| o.status.success()).unwrap_or(false) {
                let _ = std::process::Command::new(term)
                    .args(["--working-directory", &path.to_string_lossy()])
                    .spawn();
                break;
            }
        }
    }
}