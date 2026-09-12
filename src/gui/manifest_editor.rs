//! Manifest YAML editor with validation

use crate as bb;
use egui::{Ui, ScrollArea, RichText, Color32, FontId, TextEdit, Id};
use std::path::PathBuf;

pub struct ManifestEditor {
    text: String,
    error: Option<String>,
    project_path: Option<PathBuf>,
    show_raw: bool,
}

impl Default for ManifestEditor {
    fn default() -> Self {
        Self {
            text: String::new(),
            error: None,
            project_path: None,
            show_raw: false,
        }
    }
}

impl ManifestEditor {
    pub fn new() -> Self { Self::default() }

    pub fn load(&mut self, text: &str, path: &PathBuf) {
        self.text = text.to_string();
        self.project_path = Some(path.clone());
        self.validate();
    }

    fn validate(&mut self) {
        self.error = bb::manifest::load_manifest(&self.text).err().map(|e| e.to_string());
    }

    pub fn show(&mut self, ui: &mut Ui, project: &mut super::app::ProjectState, status: &mut String) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("blackbox.yaml").monospace().strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(if self.show_raw { "Visual Editor" } else { "Raw YAML" }).clicked() {
                    self.show_raw = !self.show_raw;
                }
                if ui.button("Validate").clicked() {
                    self.validate();
                    if self.error.is_none() {
                        *status = "Manifest is valid".to_string();
                    }
                }
                if ui.button("Save").clicked() {
                    self.save(project, status);
                }
            });
        });

        if let Some(err) = &self.error {
            ui.colored_label(Color32::RED, format!("⚠ {}", err));
        }

        ui.separator();

        if self.show_raw {
            self.show_raw_editor(ui, project, status);
        } else {
            self.show_visual_editor(ui, project, status);
        }
    }

    fn show_raw_editor(&mut self, ui: &mut Ui, project: &mut super::app::ProjectState, status: &mut String) {
        let response = ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                TextEdit::multiline(&mut self.text)
                    .font(FontId::monospace(13.0))
                    .desired_width(f32::INFINITY)
                    .desired_rows(30)
                    .code_editor()
            )
        }).inner;

        if response.changed() {
            project.manifest_modified = true;
            project.manifest_text = self.text.clone();
            self.validate();
        }

        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::S) && i.modifiers.ctrl) {
            self.save(project, status);
        }
    }

    fn show_visual_editor(&mut self, ui: &mut Ui, project: &mut super::app::ProjectState, _status: &mut String) {
        // Parse current manifest for visual editing
        let mut manifest: bb::manifest::Manifest = match bb::manifest::load_manifest(&self.text) {
            Ok(m) => m,
            Err(_) => {
                ui.label(RichText::new("Cannot parse manifest - switch to Raw YAML to fix").color(Color32::RED));
                return;
            }
        };

        let mut changed = false;

        egui::Grid::new("manifest_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
            // Basic fields
            ui.label("Name:"); changed |= ui.text_edit_singleline(&mut manifest.name).changed(); ui.end_row();
            ui.label("Version:"); changed |= ui.text_edit_singleline(&mut manifest.version).changed(); ui.end_row();
            ui.label("Description:"); changed |= ui.text_edit_multiline(&mut manifest.description).changed(); ui.end_row();
            ui.label("Publisher:"); changed |= ui.text_edit_singleline(&mut manifest.publisher).changed(); ui.end_row();

            ui.separator(); ui.end_row();

            // Runtime
            ui.label(RichText::new("Runtime").strong()); ui.end_row();
            ui.label("Type:"); {
                let mut rt = manifest.runtime.rtype.clone();
                egui::ComboBox::new(Id::new("manifest_runtime_type"), "")
                    .selected_text(&rt)
                    .show_ui(ui, |ui| {
                        for t in ["python", "node", "native", "wasm", "rust"] {
                            ui.selectable_value(&mut rt, t.to_string(), t);
                        }
                    });
                changed |= rt != manifest.runtime.rtype;
                manifest.runtime.rtype = rt;
            } ui.end_row();

            ui.label("Version:"); changed |= ui.text_edit_singleline(&mut manifest.runtime.version).changed(); ui.end_row();
            ui.label("Target:"); changed |= ui.text_edit_singleline(&mut manifest.runtime.target).changed(); ui.end_row();

            ui.separator(); ui.end_row();

            // Entrypoint
            ui.label(RichText::new("Entrypoint").strong()); ui.end_row();
            ui.label("Command:"); changed |= ui.text_edit_singleline(&mut manifest.entrypoint.command).changed(); ui.end_row();
            ui.label("Args:"); {
                let args = manifest.entrypoint.args.join(" ");
                let mut args_str = args;
                changed |= ui.text_edit_singleline(&mut args_str).changed();
                manifest.entrypoint.args = args_str.split_whitespace().map(|s| s.to_string()).collect();
            } ui.end_row();

            ui.separator(); ui.end_row();

            // Interface
            ui.label(RichText::new("Interface").strong()); ui.end_row();
            ui.label("Type:"); {
                let mut it = manifest.interface.itype.clone();
                egui::ComboBox::new(Id::new("manifest_interface_type"), "")
                    .selected_text(&it)
                    .show_ui(ui, |ui| {
                        for t in ["cli", "web", "gui"] {
                            ui.selectable_value(&mut it, t.to_string(), t);
                        }
                    });
                changed |= it != manifest.interface.itype;
                manifest.interface.itype = it;
            } ui.end_row();
            if manifest.interface.itype == "web" {
                let mut port = manifest.interface.port.unwrap_or(8765);
                changed |= ui.add(egui::DragValue::new(&mut port)).changed();
                manifest.interface.port = Some(port);
            } ui.end_row();

            ui.separator(); ui.end_row();

            // Permissions
            ui.label(RichText::new("Permissions").strong()); ui.end_row();

            ui.label("FS Read:"); {
                let mut read = manifest.permissions.filesystem.read.join("\n");
                changed |= ui.text_edit_multiline(&mut read).changed();
                manifest.permissions.filesystem.read = read.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            } ui.end_row();

            ui.label("FS Write:"); {
                let mut write = manifest.permissions.filesystem.write.join("\n");
                changed |= ui.text_edit_multiline(&mut write).changed();
                manifest.permissions.filesystem.write = write.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            } ui.end_row();

            ui.label("Network:"); {
                let mut enabled = manifest.permissions.network.enabled;
                changed |= ui.checkbox(&mut enabled, "Enabled").changed();
                manifest.permissions.network.enabled = enabled;
            } ui.end_row();

            if manifest.permissions.network.enabled {
                ui.label("Allow hosts:"); {
                    let mut allow = manifest.permissions.network.allow.join("\n");
                    changed |= ui.text_edit_multiline(&mut allow).changed();
                    manifest.permissions.network.allow = allow.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                } ui.end_row();
            }

            ui.label("Process spawn:"); {
                let mut spawn = manifest.permissions.process.spawn;
                changed |= ui.checkbox(&mut spawn, "Allowed").changed();
                manifest.permissions.process.spawn = spawn;
            } ui.end_row();

            ui.separator(); ui.end_row();

            // Limits
            ui.label(RichText::new("Limits").strong()); ui.end_row();
            if let Some(mem) = manifest.limits.get_mut("memory_mb") {
                ui.label("Memory (MB):"); changed |= ui.add(egui::DragValue::new(mem)).changed(); ui.end_row();
            }
            if let Some(cpu) = manifest.limits.get_mut("cpu_percent") {
                ui.label("CPU %:"); changed |= ui.add(egui::DragValue::new(cpu).range(1..=99)).changed(); ui.end_row();
            }
            if let Some(procs) = manifest.limits.get_mut("max_processes") {
                ui.label("Max processes:"); changed |= ui.add(egui::DragValue::new(procs)).changed(); ui.end_row();
            }

            ui.separator(); ui.end_row();

            // Environment
            ui.label(RichText::new("Environment").strong()); ui.end_row();
            let mut env_text = manifest.environment.variables.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n");
            changed |= ui.text_edit_multiline(&mut env_text).changed();
            manifest.environment.variables = env_text.lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();

            ui.end_row();
        });

        // Requirements
        ui.separator();
        ui.label("Requirements file:");
        changed |= ui.text_edit_singleline(&mut manifest.requirements).changed();

        if changed {
            // Serialize back to YAML
            let value = serde_json::to_value(&manifest).unwrap();
            let yaml = serde_yaml::to_string(&value).unwrap_or_default();
            self.text = yaml;
            project.manifest_text = self.text.clone();
            project.manifest_modified = true;
            project.manifest = Some(manifest);
            self.validate();
        }
    }

    fn save(&mut self, project: &mut super::app::ProjectState, status: &mut String) {
        if let Some(path) = &self.project_path {
            let manifest_path = path.join("blackbox.yaml");
            match std::fs::write(&manifest_path, &self.text) {
                Ok(_) => {
                    project.manifest_modified = false;
                    project.manifest_text = self.text.clone();
                    project.manifest = bb::manifest::load_manifest(&self.text).ok();
                    *status = "Manifest saved".to_string();
                }
                Err(e) => {
                    *status = format!("Save failed: {}", e);
                }
            }
        }
    }
}