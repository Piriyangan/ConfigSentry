"""HTML, JSON and terminal output for audit results."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .engine import AuditResult

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=select_autoescape(["html", "j2"]))


def to_html(result: AuditResult, masked: bool = True) -> str:
    return _env.get_template("report.html.j2").render(r=result, masked=masked)


def to_json(result: AuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
_RESET = "\033[0m"


def to_text(result: AuditResult, color: bool = True) -> str:
    def c(sev, text):
        return f"{_COLORS.get(sev, '')}{text}{_RESET}" if color else text

    lines = [
        f"ConfigSentry v{result.tool_version} - {result.platform_name}",
        f"Host: {result.hostname or 'unknown'}   Source: {result.source}",
        f"Score: {result.score}/100 (grade {result.grade})   "
        f"High: {result.count('high')}  Medium: {result.count('medium')}  "
        f"Low: {result.count('low')}  Passed: {len(result.passed)}",
        "-" * 78,
    ]
    for f in result.failed:
        lines.append(c(f.severity, f"[{f.severity.upper():6}] {f.id}  {f.title}"))
        for e in f.evidence[:5]:
            lines.append(f"           {e}")
        if len(f.evidence) > 5:
            lines.append(f"           ... and {len(f.evidence) - 5} more")
    if not result.failed:
        lines.append("No issues found by the current rule set.")
    return "\n".join(lines)
