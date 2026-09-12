//! Log view panel

use egui::{Ui, RichText, Color32, ScrollArea, Id};

#[derive(Clone, Copy, PartialEq)]
enum LogLevel { All, Info, Warn, Error }

impl Default for LogLevel {
    fn default() -> Self { LogLevel::All }
}

#[derive(Default)]
pub struct LogView {
    pub log_text: String,
    auto_scroll: bool,
    filter: String,
    level_filter: LogLevel,
}

impl LogView {
    pub fn new() -> Self {
        Self {
            log_text: String::new(),
            auto_scroll: true,
            filter: String::new(),
            level_filter: LogLevel::All,
        }
    }

    pub fn set_log(&mut self, text: &str) {
        self.log_text = text.to_string();
    }

    pub fn append_log(&mut self, text: &str) {
        self.log_text.push_str(text);
        self.log_text.push('\n');
    }

    pub fn clear(&mut self) {
        self.log_text.clear();
    }

    pub fn show(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Output Log").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.checkbox(&mut self.auto_scroll, "Auto-scroll");
                egui::ComboBox::new(Id::new("log_level_combo"), "")
                    .selected_text(match self.level_filter {
                        LogLevel::All => "All",
                        LogLevel::Info => "Info",
                        LogLevel::Warn => "Warn",
                        LogLevel::Error => "Error",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.level_filter, LogLevel::All, "All");
                        ui.selectable_value(&mut self.level_filter, LogLevel::Info, "Info");
                        ui.selectable_value(&mut self.level_filter, LogLevel::Warn, "Warn");
                        ui.selectable_value(&mut self.level_filter, LogLevel::Error, "Error");
                    });
                ui.add(egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(150.0)
                    .hint_text("Filter..."));
                if ui.button("Clear").clicked() {
                    self.clear();
                }
            });
        });

        ui.separator();

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.auto_scroll)
            .show(ui, |ui| {
                let filtered: Vec<&str> = self.log_text.lines()
                    .filter(|line| {
                        if !self.filter.is_empty() &&
                            !line.to_lowercase().contains(&self.filter.to_lowercase()) {
                            return false;
                        }
                        match self.level_filter {
                            LogLevel::All => true,
                            LogLevel::Info => line.contains("INFO") || line.contains("BLACKBOX:"),
                            LogLevel::Warn => line.contains("WARN") || line.contains("warning"),
                            LogLevel::Error => line.contains("ERROR") || line.contains("Error"),
                        }
                    })
                    .collect();

                for line in filtered {
                    let color = if line.contains("ERROR") || line.contains("Error") {
                        Color32::RED
                    } else if line.contains("WARN") || line.contains("warning") {
                        Color32::YELLOW
                    } else if line.contains("BLACKBOX:") || line.contains("INFO") {
                        Color32::LIGHT_GREEN
                    } else {
                        Color32::WHITE
                    };
                    ui.label(RichText::new(line).monospace().color(color).size(12.0));
                }
            });
    }
}