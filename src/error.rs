//! BLACKBOX error types and human-readable error rendering.

use std::fmt;

/// Base error. Messages are written for humans, not debuggers.
#[derive(Debug, Clone)]
pub struct BlackboxError {
    pub summary: String,
    pub detail: Option<String>,
    pub try_hint: Option<String>,
    pub changes_made: bool,
}

impl BlackboxError {
    pub fn new(summary: impl Into<String>) -> Self {
        BlackboxError {
            summary: summary.into(),
            detail: None,
            try_hint: None,
            changes_made: false,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_try(mut self, try_hint: impl Into<String>) -> Self {
        self.try_hint = Some(try_hint.into());
        self
    }

    pub fn with_changes(mut self, changes: bool) -> Self {
        self.changes_made = changes;
        self
    }
}

impl fmt::Display for BlackboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary)
    }
}

impl std::error::Error for BlackboxError {}

/// Manifest field validation errors.
#[derive(Debug, Clone)]
pub struct ManifestError(BlackboxError);

impl ManifestError {
    pub fn new(summary: impl Into<String>) -> Self {
        ManifestError(BlackboxError::new(summary))
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.0 = self.0.with_detail(detail);
        self
    }
    pub fn with_try(mut self, t: impl Into<String>) -> Self {
        self.0 = self.0.with_try(t);
        self
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for ManifestError {}
impl From<ManifestError> for BlackboxError {
    fn from(e: ManifestError) -> Self {
        e.0
    }
}

/// Package format errors (unreadable / malformed .blackbox files).
#[derive(Debug, Clone)]
pub struct PackageFormatError(BlackboxError);

impl PackageFormatError {
    pub fn new(summary: impl Into<String>) -> Self {
        PackageFormatError(BlackboxError::new(summary))
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.0 = self.0.with_detail(detail);
        self
    }
    pub fn with_try(mut self, t: impl Into<String>) -> Self {
        self.0 = self.0.with_try(t);
        self
    }
}

impl fmt::Display for PackageFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for PackageFormatError {}
impl From<PackageFormatError> for BlackboxError {
    fn from(e: PackageFormatError) -> Self {
        e.0
    }
}

/// Integrity errors (hash mismatches, missing cached objects).
#[derive(Debug, Clone)]
pub struct IntegrityError(BlackboxError);

impl IntegrityError {
    pub fn new(summary: impl Into<String>) -> Self {
        IntegrityError(BlackboxError::new(summary))
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.0 = self.0.with_detail(detail);
        self
    }
    pub fn with_try(mut self, t: impl Into<String>) -> Self {
        self.0 = self.0.with_try(t);
        self
    }
}

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for IntegrityError {}
impl From<IntegrityError> for BlackboxError {
    fn from(e: IntegrityError) -> Self {
        e.0
    }
}

/// Runtime provisioning errors.
#[derive(Debug, Clone)]
pub struct RuntimeMissingError(BlackboxError);

impl RuntimeMissingError {
    pub fn new(summary: impl Into<String>) -> Self {
        RuntimeMissingError(BlackboxError::new(summary))
    }
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.0 = self.0.with_detail(detail);
        self
    }
    pub fn with_try(mut self, t: impl Into<String>) -> Self {
        self.0 = self.0.with_try(t);
        self
    }
}

impl fmt::Display for RuntimeMissingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for RuntimeMissingError {}
impl From<RuntimeMissingError> for BlackboxError {
    fn from(e: RuntimeMissingError) -> Self {
        e.0
    }
}

/// Sandbox enforcement violations.
#[derive(Debug, Clone)]
pub struct SandboxViolation(BlackboxError);

impl SandboxViolation {
    pub fn new(summary: impl Into<String>) -> Self {
        SandboxViolation(BlackboxError::new(summary))
    }
}

impl fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for SandboxViolation {}
impl From<SandboxViolation> for BlackboxError {
    fn from(e: SandboxViolation) -> Self {
        e.0
    }
}

/// Render an error in the standard BLACKBOX format.
pub fn render_error(err: &(dyn std::error::Error + 'static)) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("\nBLACKBOX ERROR\n"));
    if let Some(be) = err.downcast_ref::<BlackboxError>() {
        lines.push(be.summary.clone());
        if let Some(detail) = &be.detail {
            lines.push("".into());
            for ln in detail.trim().lines() {
                lines.push(format!("  {}", ln));
            }
        }
        if let Some(try_hint) = &be.try_hint {
            lines.push("".into());
            lines.push("Try:".into());
            for ln in try_hint.trim().lines() {
                lines.push(format!("  {}", ln));
            }
        }
        if !be.changes_made {
            lines.push("".into());
            lines.push("No changes were made to the host system.".into());
        }
    } else if let Some(me) = err.downcast_ref::<ManifestError>() {
        let be: BlackboxError = me.clone().into();
        return render_error(&be);
    } else if let Some(pc) = err.downcast_ref::<PackageFormatError>() {
        let be: BlackboxError = pc.clone().into();
        return render_error(&be);
    } else if let Some(ie) = err.downcast_ref::<IntegrityError>() {
        let be: BlackboxError = ie.clone().into();
        return render_error(&be);
    } else if let Some(rm) = err.downcast_ref::<RuntimeMissingError>() {
        let be: BlackboxError = rm.clone().into();
        return render_error(&be);
    } else {
        lines.push(format!("Unexpected internal error: {:?}", err));
        lines.push("".into());
        lines.push("Try:".into());
        lines.push("  blackbox doctor".into());
    }
    lines.join("\n")
}

/// Render a plain error string in BLACKBOX format (non-BlackboxError path).
pub fn render_error_str(msg: &str) -> String {
    format!("\nBLACKBOX ERROR\n\n{}\n\nTry:\n  blackbox doctor", msg)
}
