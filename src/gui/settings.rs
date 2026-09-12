//! Settings management

use egui::{Context, RichText, Color32, Id};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub projects_dir: Option<PathBuf>,
    #[serde(with = "theme_serde", default = "theme_serde::default_theme")]
    pub theme: egui::Theme,
    pub auto_save_manifest: bool,
    pub show_welcome: bool,
    pub default_target: Option<String>,
    pub mirror_urls: String,
}

mod theme_serde {
    use egui::Theme;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(theme: &Theme, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match theme {
            Theme::Light => "Light",
            Theme::Dark => "Dark",
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Theme, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Light" => Ok(Theme::Light),
            _ => Ok(Theme::Dark),
        }
    }

    pub fn default_theme() -> Theme {
        Theme::Dark
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            projects_dir: None,
            theme: egui::Theme::Dark,
            auto_save_manifest: false,
            show_welcome: true,
            default_target: None,
            mirror_urls: String::new(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let config_dir = dirs::config_dir().unwrap_or_else(|| dirs::home_dir().unwrap()).join("blackbox");
        let config_path = config_dir.join("settings.json");
        if config_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&config_path) {
                if let Ok(settings) = serde_json::from_str(&text) {
                    return settings;
                }
            }
        }
        Self::default()
    }

    pub fn save(&self) {
        let config_dir = dirs::config_dir().unwrap_or_else(|| dirs::home_dir().unwrap()).join("blackbox");
        let _ = std::fs::create_dir_all(&config_dir);
        let config_path = config_dir.join("settings.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(config_path, json);
        }
    }

    pub fn show(&mut self, ctx: &Context, open: &mut bool, projects_dir: &mut PathBuf) {
        let mut open_val = *open;
        let mut close_requested = false;
        egui::Window::new("Settings")
            .open(&mut open_val)
            .collapsible(false)
            .resizable(false)
            .default_width(500.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.heading("Settings");
                    ui.add_space(10.0);

                    // Projects directory
                    ui.group(|ui| {
                        ui.label(RichText::new("Projects Directory").strong());
                        ui.horizontal(|ui| {
                            ui.label(projects_dir.display().to_string());
                            if ui.button("Change").clicked() {
                                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                    *projects_dir = path;
                                    self.projects_dir = Some(projects_dir.clone());
                                    self.save();
                                }
                            }
                        });
                    });

                    ui.add_space(10.0);

                    // Theme
                    ui.group(|ui| {
                        ui.label(RichText::new("Theme").strong());
                        let mut theme = self.theme;
                        egui::ComboBox::new(Id::new("theme_combo"), "")
                            .selected_text(match theme {
                                egui::Theme::Light => "Light",
                                egui::Theme::Dark => "Dark",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut theme, egui::Theme::Light, "Light");
                                ui.selectable_value(&mut theme, egui::Theme::Dark, "Dark");
                            });
                        if theme != self.theme {
                            self.theme = theme;
                            ctx.set_theme(theme);
                            self.save();
                        }
                    });

                    ui.add_space(10.0);

                    // Behavior
                    ui.group(|ui| {
                        ui.label(RichText::new("Behavior").strong());
                        ui.checkbox(&mut self.auto_save_manifest, "Auto-save manifest on change");
                        ui.checkbox(&mut self.show_welcome, "Show welcome screen on startup");
                    });

                    ui.add_space(10.0);

                    // Default target
                    ui.group(|ui| {
                        ui.label(RichText::new("Default Target Platform").strong());
                        let current = crate::platform::current_triple();
                        let mut target = self.default_target.clone().unwrap_or(current.clone());
                        egui::ComboBox::new(Id::new("target_combo"), "")
                            .selected_text(&target)
                            .show_ui(ui, |ui| {
                                for t in crate::platform::SUPPORTED_TARGETS {
                                    ui.selectable_value(&mut target, t.0.to_string(), format!("{} ({}/{})", t.0, t.1.os, t.1.arch));
                                }
                                ui.selectable_value(&mut target, current.clone(), format!("{} (current)", current));
                            });
                        self.default_target = Some(target);
                    });

                    ui.add_space(10.0);

                    // Mirror URLs
                    ui.group(|ui| {
                        ui.label(RichText::new("Object Mirror URLs (comma-separated)").strong());
                        ui.add_sized([ui.available_width(), 80.0], egui::TextEdit::multiline(&mut self.mirror_urls)
                            .hint_text("https://mirror.example.com/objects/"));
                        ui.label(RichText::new("Used by thin packages for fetching layers").small().color(Color32::GRAY));
                    });

                    ui.add_space(20.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Close").clicked() {
                            self.save();
                            close_requested = true;
                        }
                    });
                });
            });
        *open = open_val && !close_requested;
    }
}