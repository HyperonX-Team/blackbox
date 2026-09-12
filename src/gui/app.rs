//! Main application state and event loop

use crate as bb;
use super::manifest_editor::ManifestEditor;
use super::project_list::ProjectList;
use super::pack_dialog::PackDialog;
use super::run_dialog::RunDialog;
use super::log_view::LogView;
use super::settings::Settings;
use eframe::egui;
use egui::{CentralPanel, Context, Id, SidePanel, TopBottomPanel, ViewportCommand};
use notify::{Event, EventKind, RecommendedWatcher, Watcher};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

pub struct BlackboxApp {
    // Project management
    projects: BTreeMap<String, ProjectState>,
    selected_project: Option<String>,
    projects_dir: PathBuf,

    // UI components
    project_list: ProjectList,
    manifest_editor: ManifestEditor,
    pack_dialog: PackDialog,
    run_dialog: RunDialog,
    log_view: LogView,
    settings: Settings,
    new_project: NewProjectDialog,
    picker: FolderPicker,

    // File watching
    #[allow(dead_code)]
    watcher: Option<RecommendedWatcher>,
    watch_rx: Option<Receiver<notify::Result<Event>>>,
    #[allow(dead_code)]
    watch_tx: Option<Sender<notify::Result<Event>>>,

    // Background tasks
    pack_receiver: Option<Receiver<PackResult>>,
    run_receiver: Option<Receiver<RunResult>>,

    // UI state
    show_settings: bool,
    status_message: String,
    status_timer: Option<std::time::Instant>,
}

#[derive(Clone, Debug)]
pub struct ProjectState {
    pub path: PathBuf,
    pub manifest: Option<bb::manifest::Manifest>,
    pub manifest_text: String,
    pub manifest_modified: bool,
    pub last_packed: Option<PathBuf>,
    pub last_run_log: String,
    pub is_watching: bool,
}

#[derive(Clone, Debug)]
enum PackResult {
    Success { output_path: PathBuf, bytes: u64 },
    Error(String),
}

#[derive(Clone, Debug)]
enum RunResult {
    Output(String),
    Finished(i32),
    Error(String),
}

// -------------------------------------------------------------- new project

/// Persistent state for the "New Project" dialog.
///
/// IMPORTANT: the input fields live here (not as locals in `draw`) so that
/// typed text survives across frames. Immediate-mode UIs redraw every frame;
/// a local `String` would be reset on every repaint.
pub struct NewProjectDialog {
    pub open: bool,
    pub name: String,
    pub template: String,
    pub python_version: String,
}

impl Default for NewProjectDialog {
    fn default() -> Self {
        Self {
            open: false,
            name: String::new(),
            template: "hello".to_string(),
            python_version: "3.12".to_string(),
        }
    }
}

impl NewProjectDialog {
    fn open_fresh(&mut self) {
        self.open = true;
        self.name.clear();
        self.template = "hello".to_string();
        self.python_version = "3.12".to_string();
    }

    /// Returns Some((name, template, python_version)) when the user hits Create.
    fn draw(&mut self, ctx: &Context) -> Option<(String, String, String)> {
        if !self.open {
            return None;
        }
        let mut open = self.open;
        let mut create = false;
        let mut cancel = false;

        egui::Window::new("New Project")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.label("Project name:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name)
                            .desired_width(f32::INFINITY)
                            .hint_text("my-app"),
                    );

                    ui.add_space(10.0);
                    ui.label("Template:");
                    egui::ComboBox::new(Id::new("new_project_template"), "")
                        .selected_text(&self.template)
                        .show_ui(ui, |ui| {
                            for t in ["hello", "datasift", "research-repro", "node"] {
                                ui.selectable_value(&mut self.template, t.to_string(), t);
                            }
                        });

                    ui.add_space(10.0);
                    ui.label("Python version (for python templates):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.python_version)
                            .desired_width(f32::INFINITY),
                    );

                    ui.add_space(20.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                        let valid = !self.name.trim().is_empty();
                        if ui.add_enabled(valid, egui::Button::new("Create")).clicked() {
                            create = true;
                        }
                        if !valid {
                            ui.label(egui::RichText::new("name required").small().color(egui::Color32::GRAY));
                        }
                    });
                });
            });

        self.open = open && !cancel;

        if create && !self.name.trim().is_empty() {
            let out = (
                self.name.trim().to_string(),
                self.template.clone(),
                self.python_version.clone(),
            );
            self.open = false;
            return Some(out);
        }
        None
    }
}

// ------------------------------------------------------------- folder picker

#[derive(Clone, Copy, PartialEq, Debug)]
enum PickPurpose {
    /// Open a single existing project (folder containing blackbox.yaml)
    OpenProject,
    /// Choose the parent directory that holds many projects
    OpenProjectsDir,
}

/// Runs native folder pickers on a worker thread and reports the result via a
/// channel. Calling a blocking native dialog from inside the egui/winit event
/// loop can fail to show or deadlock, so we never do that.
pub struct FolderPicker {
    rx: Option<Receiver<Option<PathBuf>>>,
    purpose: Option<PickPurpose>,
}

impl Default for FolderPicker {
    fn default() -> Self {
        Self { rx: None, purpose: None }
    }
}

impl FolderPicker {
    fn is_busy(&self) -> bool {
        self.rx.is_some()
    }

    fn start(&mut self, purpose: PickPurpose, title: &str) {
        if self.is_busy() {
            return;
        }
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.purpose = Some(purpose);
        let title = title.to_string();
        thread::spawn(move || {
            let picked = rfd::FileDialog::new().set_title(title).pick_folder();
            let _ = tx.send(picked);
        });
    }

    fn poll(&mut self) -> Option<(PickPurpose, PathBuf)> {
        let (Some(rx), Some(purpose)) = (&self.rx, self.purpose) else {
            return None;
        };
        match rx.try_recv() {
            Ok(res) => {
                self.rx = None;
                self.purpose = None;
                res.map(|p| (purpose, p))
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.rx = None;
                self.purpose = None;
                None
            }
        }
    }
}

impl BlackboxApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load settings
        let settings = Settings::load();
        let projects_dir = settings.projects_dir.clone()
            .unwrap_or_else(|| dirs::home_dir().unwrap().join("blackbox-projects"));

        // Setup file watcher
        let (watch_tx, watch_rx) = channel();
        let mut watcher: Option<RecommendedWatcher> = None;
        if let Ok(w) = RecommendedWatcher::new(watch_tx.clone(), notify::Config::default()) {
            watcher = Some(w);
        }

        // Apply theme
        cc.egui_ctx.set_theme(settings.theme);

        // Load existing projects
        let projects = load_projects(&projects_dir);

        let mut app = Self {
            projects,
            selected_project: None,
            projects_dir,
            project_list: ProjectList::new(),
            manifest_editor: ManifestEditor::new(),
            pack_dialog: PackDialog::new(),
            run_dialog: RunDialog::new(),
            log_view: LogView::new(),
            settings,
            new_project: NewProjectDialog::default(),
            picker: FolderPicker::default(),
            watcher,
            watch_rx: Some(watch_rx),
            watch_tx: Some(watch_tx),
            pack_receiver: None,
            run_receiver: None,
            show_settings: false,
            status_message: String::new(),
            status_timer: None,
        };

        // Select first project if any
        if let Some(first) = app.projects.keys().next().cloned() {
            app.select_project(first);
        }

        app
    }

    fn select_project(&mut self, name: String) {
        self.selected_project = Some(name.clone());
        if let Some(project) = self.projects.get(&name) {
            self.manifest_editor.load(&project.manifest_text, &project.path);
            self.log_view.set_log(&project.last_run_log);
        }
    }

    fn set_status(&mut self, msg: String) {
        self.status_message = msg;
        self.status_timer = Some(std::time::Instant::now());
    }

    fn new_project(&mut self, name: String, template: String, python_version: String) {
        let project_path = self.projects_dir.join(&name);
        if project_path.exists() {
            self.set_status(format!("Project '{}' already exists", name));
            return;
        }

        // Create project using the bundled templates
        let files = match bb::templates::template_files(&template) {
            Ok(f) => f,
            Err(e) => {
                self.set_status(format!("Failed to load template: {}", e));
                return;
            }
        };

        if let Err(e) = std::fs::create_dir_all(&project_path) {
            self.set_status(format!("Could not create project dir: {}", e));
            return;
        }

        for (rel, content) in files {
            let p = project_path.join(&rel);
            if p.is_dir() {
                continue;
            }
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut text = content.replace("blackbox-template", &name.to_lowercase().replace(' ', "-"));
            text = text.replace("version: \"3.12\"", &format!("version: \"{}\"", python_version));
            if let Err(e) = std::fs::write(&p, text) {
                self.set_status(format!("Could not write template file: {}", e));
                return;
            }
        }

        // Load the created project
        let manifest_path = project_path.join("blackbox.yaml");
        let manifest_text = std::fs::read_to_string(&manifest_path).unwrap_or_default();
        let manifest = bb::manifest::load_manifest(&manifest_text).ok();

        let state = ProjectState {
            path: project_path.clone(),
            manifest,
            manifest_text,
            manifest_modified: false,
            last_packed: None,
            last_run_log: String::new(),
            is_watching: false,
        };

        self.projects.insert(name.clone(), state);
        self.select_project(name);
        self.set_status("Project created successfully".to_string());
    }

    /// Open a folder the user picked. If it is itself a project (contains
    /// blackbox.yaml) open just that; otherwise treat it as a projects dir.
    fn open_picked_folder(&mut self, path: PathBuf) {
        let path = if path.is_file() {
            path.parent().map(|p| p.to_path_buf()).unwrap_or(path)
        } else {
            path
        };

        if path.join("blackbox.yaml").is_file() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "project".to_string());
            match load_project_state(&path) {
                Ok(state) => {
                    self.projects.insert(name.clone(), state);
                    self.select_project(name);
                    self.set_status("Project opened".to_string());
                }
                Err(e) => self.set_status(format!("Could not open project: {}", e)),
            }
            return;
        }

        // Not a project itself: try to load it as a directory of projects.
        let found = load_projects(&path);
        if found.is_empty() {
            self.set_status(format!(
                "No blackbox.yaml in '{}'. Pick the folder that contains your project.",
                path.display()
            ));
            return;
        }
        self.projects_dir = path.clone();
        self.settings.projects_dir = Some(path);
        self.settings.save();
        self.projects = found;
        self.selected_project = None;
        if let Some(first) = self.projects.keys().next().cloned() {
            self.select_project(first);
        }
        self.set_status(format!("Loaded {} project(s)", self.projects.len()));
    }

    fn set_projects_dir(&mut self, path: PathBuf) {
        self.projects_dir = path.clone();
        self.settings.projects_dir = Some(path);
        self.settings.save();
        self.projects = load_projects(&self.projects_dir);
        self.selected_project = None;
        if let Some(first) = self.projects.keys().next().cloned() {
            self.select_project(first);
        }
        if self.projects.is_empty() {
            self.set_status("That folder has no BLACKBOX projects.".to_string());
        } else {
            self.set_status(format!("Loaded {} project(s)", self.projects.len()));
        }
    }

    fn pack_project(&mut self) {
        let Some(name) = self.selected_project.clone() else { return };
        let Some(project) = self.projects.get(&name).cloned() else { return };

        // Save manifest first if modified
        if project.manifest_modified {
            if let Err(e) = std::fs::write(project.path.join("blackbox.yaml"), &project.manifest_text) {
                self.set_status(format!("Failed to save manifest: {}", e));
                return;
            }
            if let Some(p) = self.projects.get_mut(&name) {
                p.manifest_modified = false;
            }
        }

        let (tx, rx) = channel();
        self.pack_receiver = Some(rx);

        let project_path = project.path.clone();
        let output_path = self.pack_dialog.output_path.clone();
        let target = self.pack_dialog.target.clone();
        let thin = self.pack_dialog.thin;

        thread::spawn(move || {
            let opts = bb::packaging::PackOptions {
                output: output_path.map(PathBuf::from),
                target,
                thin,
                progress: Some(String::new()),
            };

            match bb::packaging::pack(&project_path, &opts) {
                Ok(out) => {
                    let _ = tx.send(PackResult::Success { output_path: out.path, bytes: out.bytes });
                }
                Err(e) => {
                    let _ = tx.send(PackResult::Error(bb::error::render_error(&e)));
                }
            }
        });
        self.set_status("Packing...".to_string());
    }

    fn run_project(&mut self) {
        let Some(name) = self.selected_project.clone() else { return };
        let Some(project) = self.projects.get(&name).cloned() else { return };
        let Some(pack_path) = project.last_packed.clone() else {
            self.set_status("No package found. Pack first.".to_string());
            return;
        };

        let (tx, rx) = channel();
        self.run_receiver = Some(rx);

        let work_dir = self.run_dialog.work_dir.clone().map(PathBuf::from);
        let inputs = self.run_dialog.input_files.clone();
        let yes = self.run_dialog.yes;
        let data = self.run_dialog.data;
        let log = self.run_dialog.log;
        let entry = self.run_dialog.entry.clone();
        let app_args = self.run_dialog.app_args.clone();
        self.run_dialog.running = true;

        thread::spawn(move || {
            let pkg_path = Path::new(&pack_path);
            let pkg = match bb::packaging::open_package(pkg_path) {
                Ok(p) => p,
                Err(e) => {
                    let _ = tx.send(RunResult::Error(bb::error::render_error(&e)));
                    return;
                }
            };

            let home = bb::storage::ensure_home();
            let work_dir = work_dir.unwrap_or_else(|| home.packages.join(format!("{}-work", pkg.manifest.name)));

            let input_dir = work_dir.join("input");
            let _ = std::fs::create_dir_all(&input_dir);
            for f in inputs {
                let src = Path::new(&f);
                let dest = input_dir.join(src.file_name().unwrap_or_default());
                let _ = std::fs::copy(src, dest);
            }

            let data_dir = data.then(|| home.packages.join(pkg.manifest.name.clone()).join("data"));

            let mut ctx = match bb::packaging::prepare_run(&pkg, &work_dir, data_dir.as_deref()) {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(RunResult::Error(bb::error::render_error(&e)));
                    return;
                }
            };
            ctx.entry = entry;
            if log {
                ctx.log_file = Some(home.logs.join(format!("{}.log", pkg.manifest.name)));
            }
            let _ = yes;

            match bb::runtime::execute_capture(&ctx, Some(&app_args_vec(app_args))) {
                Ok((stdout, stderr, code)) => {
                    let mut log_text = String::new();
                    if !stdout.is_empty() { log_text.push_str(&stdout); }
                    if !stderr.is_empty() { log_text.push_str(&stderr); }
                    let _ = tx.send(RunResult::Output(log_text));
                    let _ = tx.send(RunResult::Finished(code));
                }
                Err(e) => {
                    let _ = tx.send(RunResult::Error(bb::error::render_error(&e)));
                }
            }
        });
    }

    fn open_project_dir(&mut self) {
        if let Some(name) = &self.selected_project {
            if let Some(project) = self.projects.get(name) {
                let _ = opener::open(&project.path);
            }
        }
    }

    fn open_package_dir(&mut self) {
        if let Some(name) = &self.selected_project {
            if let Some(project) = self.projects.get(name) {
                if let Some(pack) = &project.last_packed {
                    if let Some(parent) = pack.parent() {
                        let _ = opener::open(parent);
                    }
                }
            }
        }
    }

    fn handle_watch_events(&mut self) {
        let mut changed_manifest: Option<String> = None;
        if let Some(rx) = &self.watch_rx {
            while let Ok(event) = rx.try_recv() {
                if let Ok(event) = event {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        if let Some(name) = &self.selected_project {
                            if let Some(project) = self.projects.get(name) {
                                let manifest_path = project.path.join("blackbox.yaml");
                                for path in &event.paths {
                                    if path == &manifest_path {
                                        changed_manifest = Some(name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(name) = changed_manifest {
            let manifest_path = self.projects.get(&name).map(|p| p.path.join("blackbox.yaml"));
            if let Some(mp) = manifest_path {
                if let Ok(text) = std::fs::read_to_string(&mp) {
                    if let Some(project) = self.projects.get_mut(&name) {
                        project.manifest_text = text.clone();
                        project.manifest_modified = true;
                    }
                    if self.selected_project.as_deref() == Some(name.as_str()) {
                        let path = self.projects.get(&name).map(|p| p.path.clone()).unwrap_or_default();
                        self.manifest_editor.load(&text, &path);
                    }
                }
            }
        }
    }

    fn handle_pack_result(&mut self) {
        let mut result = None;
        if let Some(rx) = &self.pack_receiver {
            if let Ok(r) = rx.try_recv() {
                result = Some(r);
            }
        }
        if let Some(result) = result {
            self.pack_receiver = None;
            match result {
                PackResult::Success { output_path, bytes } => {
                    if let Some(name) = &self.selected_project {
                        if let Some(project) = self.projects.get_mut(name) {
                            project.last_packed = Some(output_path.clone());
                        }
                    }
                    let size = bb::deterministic::human_size(bytes);
                    self.set_status(format!("Packed {} ({})", output_path.display(), size));
                }
                PackResult::Error(e) => {
                    self.set_status("Pack failed".to_string());
                    self.log_view.set_log(&e);
                }
            }
        }
    }

    fn handle_run_result(&mut self) {
        let mut results = Vec::new();
        if let Some(rx) = &self.run_receiver {
            while let Ok(result) = rx.try_recv() {
                results.push(result);
            }
        }
        for result in results {
            match result {
                RunResult::Output(log) => {
                    self.log_view.append_log(&log);
                    let text = self.log_view.log_text.clone();
                    if let Some(name) = &self.selected_project {
                        if let Some(project) = self.projects.get_mut(name) {
                            project.last_run_log = text;
                        }
                    }
                }
                RunResult::Finished(code) => {
                    self.run_dialog.running = false;
                    self.set_status(format!("Run finished with exit code {}", code));
                }
                RunResult::Error(e) => {
                    self.run_dialog.running = false;
                    self.set_status(format!("Run error: {}", e));
                    self.log_view.set_log(&e);
                }
            }
        }
    }
}

fn app_args_vec(s: String) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

impl eframe::App for BlackboxApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Handle background events
        self.handle_watch_events();
        self.handle_pack_result();
        self.handle_run_result();

        // Folder picker result
        if let Some((purpose, path)) = self.picker.poll() {
            match purpose {
                PickPurpose::OpenProject => self.open_picked_folder(path),
                PickPurpose::OpenProjectsDir => self.set_projects_dir(path),
            }
        }

        // Status message timeout
        if let Some(timer) = self.status_timer {
            if timer.elapsed() > Duration::from_secs(5) {
                self.status_message.clear();
                self.status_timer = None;
            }
        }

        // Collected actions (applied after the UI so egui closures never
        // need to borrow all of `self`).
        let mut act_new_project = false;
        let mut act_open_project = false;
        let mut act_open_projects_dir = false;
        let mut act_open_settings = false;
        let mut act_quit = false;
        let mut act_pack = false;
        let mut act_run = false;
        let mut act_open_project_dir = false;
        let mut act_open_package_dir = false;
        let mut act_clear_log = false;
        let mut act_docs = false;
        let mut act_github = false;
        let mut act_about = false;

        let picker_busy = self.picker.is_busy();

        // Top menu bar
        TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open Project...").clicked() {
                        act_open_project = true;
                        ui.close_menu();
                    }
                    if ui.button("Open Projects Folder...").clicked() {
                        act_open_projects_dir = true;
                        ui.close_menu();
                    }
                    if ui.button("New Project...").clicked() {
                        act_new_project = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Settings...").clicked() {
                        act_open_settings = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        act_quit = true;
                    }
                });

                ui.menu_button("Project", |ui| {
                    if ui.button("Pack").clicked() { act_pack = true; ui.close_menu(); }
                    if ui.button("Run").clicked() { act_run = true; ui.close_menu(); }
                    if ui.button("Open Project Folder").clicked() { act_open_project_dir = true; ui.close_menu(); }
                    if ui.button("Open Package Folder").clicked() { act_open_package_dir = true; ui.close_menu(); }
                });

                ui.menu_button("View", |ui| {
                    if ui.button("Clear Log").clicked() { act_clear_log = true; ui.close_menu(); }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("Documentation").clicked() { act_docs = true; ui.close_menu(); }
                    if ui.button("GitHub Repository").clicked() { act_github = true; ui.close_menu(); }
                    ui.separator();
                    if ui.button("About").clicked() { act_about = true; ui.close_menu(); }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if picker_busy {
                        ui.spinner();
                        ui.label(egui::RichText::new("waiting for folder picker...").small().color(egui::Color32::YELLOW));
                    } else if !self.status_message.is_empty() {
                        ui.label(egui::RichText::new(&self.status_message).small().color(egui::Color32::GRAY));
                    }
                });
            });
        });

        // Side panel - Project list
        SidePanel::left("project_list")
            .default_width(280.0)
            .min_width(200.0)
            .max_width(400.0)
            .show(ctx, |ui| {
                self.project_list.show(ui, &mut self.projects, &mut self.selected_project, &mut self.new_project.open);
            });

        // Main content area
        let selected = self.selected_project.clone();
        CentralPanel::default().show(ctx, |ui| {
            if let Some(name) = selected.clone() {
                if self.projects.contains_key(&name) {
                    egui::TopBottomPanel::top("project_header")
                        .show_inside(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.heading(name.as_str());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("Pack").clicked() { act_pack = true; }
                                    if ui.button("Run").clicked() { act_run = true; }
                                    if ui.button("Open Folder").clicked() { act_open_project_dir = true; }
                                });
                            });
                            ui.separator();
                        });

                    egui::CentralPanel::default().show_inside(ui, |ui| {
                        if let Some(project) = self.projects.get_mut(&name) {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                self.manifest_editor.show(ui, project, &mut self.status_message);
                            });
                        }
                    });
                }
            } else {
                // Welcome screen
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.heading("BLACKBOX");
                    ui.label("Portable, reproducible computational appliances");
                    ui.add_space(20.0);
                    if ui.button("Create New Project").clicked() {
                        act_new_project = true;
                    }
                    ui.add_space(10.0);
                    if ui.add_enabled(!picker_busy, egui::Button::new("Open Existing Project")).clicked() {
                        act_open_project = true;
                    }
                    ui.add_space(10.0);
                    if ui.add_enabled(!picker_busy, egui::Button::new("Open Projects Folder")).clicked() {
                        act_open_projects_dir = true;
                    }
                });
            }
        });

        // Bottom panel - Log view
        TopBottomPanel::bottom("log_view")
            .default_height(200.0)
            .min_height(100.0)
            .max_height(400.0)
            .resizable(true)
            .show(ctx, |ui| {
                self.log_view.show(ui);
            });

        // ---- apply collected actions
        if act_new_project { self.new_project.open_fresh(); }
        if act_open_project { self.picker.start(PickPurpose::OpenProject, "Open a BLACKBOX project folder (contains blackbox.yaml)"); }
        if act_open_projects_dir { self.picker.start(PickPurpose::OpenProjectsDir, "Open the folder that contains your projects"); }
        if act_open_settings { self.show_settings = true; }
        if act_quit { ctx.send_viewport_cmd(ViewportCommand::Close); }
        if act_pack { self.pack_dialog.show = true; }
        if act_run { self.run_dialog.show = true; }
        if act_open_project_dir { self.open_project_dir(); }
        if act_open_package_dir { self.open_package_dir(); }
        if act_clear_log { self.log_view.clear(); }
        if act_docs { let _ = opener::open("https://hyperonx-team.github.io/blackbox/"); }
        if act_github { let _ = opener::open("https://github.com/blackbox-project/blackbox"); }
        if act_about { self.set_status(format!("BLACKBOX v{} - Download a machine", bb::VERSION)); }

        // New project modal (persistent input state)
        if let Some((name, template, python_version)) = self.new_project.draw(ctx) {
            self.new_project(name, template, python_version);
        }

        // Settings modal
        if self.show_settings {
            self.settings.show(ctx, &mut self.show_settings, &mut self.projects_dir);
        }

        // Pack / Run dialogs
        let selected = self.selected_project.clone();
        let project_path = selected.as_ref().and_then(|n| self.projects.get(n)).map(|p| p.path.clone());
        let package_path = selected.as_ref().and_then(|n| self.projects.get(n)).and_then(|p| p.last_packed.clone());
        self.pack_dialog.draw(ctx, &project_path);
        self.run_dialog.draw(ctx, &package_path);

        if self.pack_dialog.pack_requested {
            self.pack_dialog.pack_requested = false;
            self.pack_project();
        }
        if self.run_dialog.run_requested {
            self.run_dialog.run_requested = false;
            self.run_project();
        }

        // Keep animating while a picker is open so the spinner spins.
        if self.picker.is_busy() {
            ctx.request_repaint();
        }
    }
}

fn load_projects(dir: &Path) -> BTreeMap<String, ProjectState> {
    let mut projects = BTreeMap::new();
    if !dir.exists() {
        return projects;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                if let Ok(state) = load_project_state(&path) {
                    projects.insert(name, state);
                }
            }
        }
    }
    projects
}

fn load_project_state(path: &Path) -> Result<ProjectState, Box<dyn std::error::Error>> {
    let manifest_path = path.join("blackbox.yaml");
    let manifest_text = std::fs::read_to_string(&manifest_path)?;
    let manifest = bb::manifest::load_manifest(&manifest_text).ok();

    // Check for an existing package
    let last_packed = std::fs::read_dir(path)
        .ok()
        .and_then(|entries| entries.flatten().find_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".blackbox") {
                Some(e.path())
            } else {
                None
            }
        }));

    Ok(ProjectState {
        path: path.to_path_buf(),
        manifest,
        manifest_text,
        manifest_modified: false,
        last_packed,
        last_run_log: String::new(),
        is_watching: false,
    })
}
