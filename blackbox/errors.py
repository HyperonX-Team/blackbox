"""BLACKBOX error types and human-readable error rendering."""


class BlackboxError(Exception):
    """Base error. Messages are written for humans, not debuggers."""

    def __init__(self, summary, *, detail=None, try_hint=None, changes_made=False):
        super().__init__(summary)
        self.summary = summary
        self.detail = detail
        self.try_hint = try_hint
        self.changes_made = changes_made


class ManifestError(BlackboxError):
    pass


class PackageFormatError(BlackboxError):
    pass


class IntegrityError(BlackboxError):
    pass


class RuntimeMissingError(BlackboxError):
    pass


class SandboxViolation(BlackboxError):
    pass


def _as_text(v):
    if isinstance(v, (list, tuple)):
        return "\n".join(str(x) for x in v)
    return str(v)


def render_error(err: BaseException) -> str:
    """Render an error in the standard BLACKBOX format."""
    lines = ["", "BLACKBOX ERROR", ""]
    if isinstance(err, BlackboxError):
        lines.append(err.summary)
        if err.detail:
            lines.append("")
            for ln in _as_text(err.detail).strip().splitlines():
                lines.append("  " + ln)
        if err.try_hint:
            lines.append("")
            lines.append("Try:")
            for ln in _as_text(err.try_hint).strip().splitlines():
                lines.append("  " + ln)
        if not err.changes_made:
            lines.append("")
            lines.append("No changes were made to the host system.")
    else:
        lines.append(f"Unexpected internal error: {err!r}")
        lines.append("")
        lines.append("Try:")
        lines.append("  blackbox doctor")
    return "\n".join(lines)
