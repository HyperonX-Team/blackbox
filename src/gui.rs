//! BLACKBOX GUI module (feature-gated)

#[cfg(feature = "gui")]
pub mod app;

#[cfg(feature = "gui")]
pub mod manifest_editor;

#[cfg(feature = "gui")]
pub mod project_list;

#[cfg(feature = "gui")]
pub mod pack_dialog;

#[cfg(feature = "gui")]
pub mod run_dialog;

#[cfg(feature = "gui")]
pub mod log_view;

#[cfg(feature = "gui")]
pub mod settings;