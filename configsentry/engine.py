"""ConfigSentry rule engine.

Rules live in YAML files under ``configsentry/rules``. Each rule has a ``type``
that tells the engine how to evaluate it:

Cisco IOS / IOS-XE
  line_present   - fail if no line matches ``pattern``
  line_absent    - fail if any line matches ``pattern``
  block          - for every block whose parent matches ``parent``:
                   ``require`` a child pattern and/or ``forbid`` a child pattern

FortiGate
  fgt_setting    - compare settings in a section against bad values / limits,
                   using the FortiOS default when the setting is not shown

Any platform
  python         - call a custom check function from ``checks.py``
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from . import __version__
from .checks import CUSTOM_CHECKS
from .masking import mask_line
from .parsers import PARSERS, detect_platform

RULES_DIR = Path(__file__).parent / "rules"

PASS, FAIL, NA = "PASS", "FAIL", "N/A"
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_WEIGHT = {"high": 10, "medium": 5, "low": 2, "info": 0}

PLATFORMS: Dict[str, Dict[str, Any]] = {
    # ---- switches and routers ---- #
    "cisco_ios": {"name": "Cisco IOS / IOS-XE", "kind": "Switch / Router",
                  "rules": "cisco_ios.yaml", "command": "show running-config"},
    "cisco_nxos": {"name": "Cisco NX-OS (Nexus)", "kind": "Switch",
                   "rules": "cisco_nxos.yaml", "command": "show running-config"},
    "huawei_vrp": {"name": "Huawei VRP (S / CE switches, AR routers)", "kind": "Switch / Router",
                   "rules": "huawei_vrp.yaml", "command": "display current-configuration"},
    "junos": {"name": "Juniper Junos (EX / QFX / MX / SRX)", "kind": "Switch / Router / Firewall",
              "rules": "junos.yaml", "command": "show configuration | display set"},
    "mikrotik": {"name": "MikroTik RouterOS", "kind": "Router / Switch",
                 "rules": "mikrotik.yaml", "command": "/export"},
    # ---- firewalls ---- #
    "cisco_asa": {"name": "Cisco ASA", "kind": "Firewall",
                  "rules": "cisco_asa.yaml", "command": "show running-config"},
    "fortigate": {"name": "FortiGate (FortiOS)", "kind": "Firewall",
                  "rules": "fortigate.yaml", "command": "show"},
    "paloalto": {"name": "Palo Alto PAN-OS", "kind": "Firewall",
                 "rules": "paloalto.yaml",
                 "command": "XML export, or 'show config running' (set or default format)"},
    "checkpoint_gaia": {"name": "Check Point Gaia (OS hardening)", "kind": "Firewall",
                        "rules": "checkpoint_gaia.yaml", "command": "show configuration (clish)"},
    "sophos": {"name": "Sophos Firewall (SFOS) - beta", "kind": "Firewall",
               "rules": "sophos.yaml", "command": "Entities.xml or the .tar from Backup & firmware > Import export"},
}

REQUIRED_FIELDS = ("id", "title", "severity", "category", "type", "description", "remediation")


@dataclass
class RuleResult:
    id: str
    title: str
    severity: str
    category: str
    status: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class AuditResult:
    platform: str
    platform_name: str
    hostname: Optional[str]
    source: str
    generated_at: str
    tool_version: str
    results: List[RuleResult]
    detected_platform: Optional[str] = None

    @property
    def failed(self) -> List[RuleResult]:
        out = [r for r in self.results if r.status == FAIL]
        return sorted(out, key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), r.id))

    @property
    def passed(self) -> List[RuleResult]:
        return [r for r in self.results if r.status == PASS]

    @property
    def not_applicable(self) -> List[RuleResult]:
        return [r for r in self.results if r.status == NA]

    def count(self, severity: str) -> int:
        return sum(1 for r in self.failed if r.severity == severity)

    @property
    def score(self) -> int:
        """Weighted % of applicable checks that passed (0-100)."""
        applicable = [r for r in self.results if r.status != NA]
        total = sum(SEVERITY_WEIGHT.get(r.severity, 0) for r in applicable)
        if not total:
            return 100
        ok = sum(SEVERITY_WEIGHT.get(r.severity, 0) for r in applicable if r.status == PASS)
        return round(100 * ok / total)

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "ConfigSentry",
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "platform": self.platform,
            "platform_name": self.platform_name,
            "hostname": self.hostname,
            "source": self.source,
            "score": self.score,
            "grade": self.grade,
            "summary": {
                "high": self.count("high"),
                "medium": self.count("medium"),
                "low": self.count("low"),
                "passed": len(self.passed),
                "not_applicable": len(self.not_applicable),
            },
            "results": [asdict(r) for r in self.results],
        }


# --------------------------------------------------------------------------- #
# Rule loading
# --------------------------------------------------------------------------- #
def load_rules(platform: str) -> List[Dict[str, Any]]:
    if platform not in PLATFORMS:
        raise ValueError(f"Unknown platform '{platform}'. Choose from: {', '.join(PLATFORMS)}")
    path = RULES_DIR / PLATFORMS[platform]["rules"]
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    rules = data.get("rules", [])
    seen = set()
    for rule in rules:
        missing = [f for f in REQUIRED_FIELDS if f not in rule]
        if missing:
            raise ValueError(f"Rule {rule.get('id', '?')} in {path.name} is missing: {missing}")
        if rule["id"] in seen:
            raise ValueError(f"Duplicate rule id {rule['id']} in {path.name}")
        if rule["severity"] not in SEVERITY_WEIGHT:
            raise ValueError(f"Rule {rule['id']} has invalid severity '{rule['severity']}'")
        seen.add(rule["id"])
    return rules


# --------------------------------------------------------------------------- #
# Evaluators
# --------------------------------------------------------------------------- #
def _fmt(lineno: int, text: str) -> str:
    return f"line {lineno}: {text}"


def _eval_line_present(cfg, rule):
    hits = cfg.find(rule["pattern"], rule.get("scope", "global"))
    if hits:
        return PASS, [_fmt(n, t) for n, t in hits[:5]]
    return FAIL, [rule.get("missing_message", "Required configuration line not found.")]


def _eval_line_absent(cfg, rule):
    hits = cfg.find(rule["pattern"], rule.get("scope", "global"))
    if hits:
        return FAIL, [_fmt(n, t) for n, t in hits]
    return PASS, []


def _eval_block(cfg, rule):
    blocks = cfg.blocks_matching(rule["parent"])
    if not blocks:
        return NA, [f"No section matching '{rule['parent']}' found."]
    evidence = []
    for b in blocks:
        if rule.get("forbid"):
            for n, t in b.child_matches(rule["forbid"]):
                evidence.append(f"{_fmt(b.lineno, b.text)}  ->  line {n}: {t}")
        if rule.get("require") and not b.child_matches(rule["require"]):
            evidence.append(f"{_fmt(b.lineno, b.text)}  ->  missing required setting")
    return (FAIL, evidence) if evidence else (PASS, [])


def _eval_fgt_setting(cfg, rule):
    sections = cfg.find_sections(rule["section"])
    if not sections:
        sections = [None]  # section not shown -> everything at default
    evidence = []
    for sec in sections:
        for chk in rule["settings"]:
            key, default = chk["key"], chk.get("default")
            value = sec.get(key) if sec else None
            shown = value is not None
            value = value if shown else default
            if value is None:
                continue
            where = f"line {sec.lineno_of(key)}: " if (sec and shown) else ""
            ctx = f"config {rule['section']} -> set {key} {value}"
            if not shown:
                ctx += "  (not shown, FortiOS default)"
            bad = False
            vals = str(value).lower().split()
            if "fail_values" in chk and any(v in [str(x).lower() for x in chk["fail_values"]] for v in vals):
                bad = True
            if "fail_if_contains" in chk and any(str(x).lower() in vals for x in chk["fail_if_contains"]):
                bad = True
            try:
                num = float(value)
                if "fail_if_greater" in chk and num > float(chk["fail_if_greater"]):
                    bad = True
                if "fail_if_less" in chk and num < float(chk["fail_if_less"]):
                    bad = True
            except (TypeError, ValueError):
                pass
            if bad:
                evidence.append(where + ctx)
    return (FAIL, evidence) if evidence else (PASS, [])


def _eval_line_value(cfg, rule):
    """Compare a value captured by ``pattern`` (group 1) against limits."""
    hits = cfg.find(rule["pattern"], rule.get("scope", "global"))
    rx = re.compile(rule["pattern"], re.IGNORECASE)
    values = []
    for n, t in hits:
        m = rx.search(t)
        if m and m.groups():
            values.append((n, t, m.group(1)))
    if not values:
        if "default" not in rule:
            return NA, ["Setting not found in the configuration."]
        values = [(None, None, str(rule["default"]))]
    evidence = []
    for n, t, raw in values:
        where = _fmt(n, t) if n else f"Not set, so the default ({raw}) applies."
        bad = False
        if "fail_values" in rule and raw.lower() in [str(v).lower() for v in rule["fail_values"]]:
            bad = True
        try:
            num = float(raw)
            if "fail_if_greater" in rule and num > float(rule["fail_if_greater"]):
                bad = True
            if "fail_if_less" in rule and num < float(rule["fail_if_less"]):
                bad = True
        except ValueError:
            pass
        if bad:
            evidence.append(where)
    return (FAIL, evidence) if evidence else (PASS, [])


def _eval_python(cfg, rule):
    func = CUSTOM_CHECKS.get(rule["function"])
    if func is None:
        raise ValueError(f"Rule {rule['id']}: unknown check function '{rule['function']}'")
    return func(cfg, rule)


EVALUATORS = {
    "line_present": _eval_line_present,
    "line_absent": _eval_line_absent,
    "block": _eval_block,
    "fgt_setting": _eval_fgt_setting,
    "line_value": _eval_line_value,
    "python": _eval_python,
}


def _applies(cfg, rule) -> bool:
    if "applies_if" in rule and not cfg.find(rule["applies_if"], "all"):
        return False
    if "skip_if" in rule and cfg.find(rule["skip_if"], "all"):
        return False
    return True


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def run_audit(
    text: str,
    platform: str,
    source: str = "pasted config",
    mask: bool = True,
) -> AuditResult:
    if not text or not text.strip():
        raise ValueError("The configuration is empty.")
    cfg = PARSERS[platform](text)
    results: List[RuleResult] = []

    for rule in load_rules(platform):
        applies = _applies(cfg, rule) if hasattr(cfg, "find") else True
        if not applies:
            status, evidence = NA, ["Not applicable to this configuration."]
        else:
            evaluator = EVALUATORS.get(rule["type"])
            if evaluator is None:
                raise ValueError(f"Rule {rule['id']}: unknown type '{rule['type']}'")
            status, evidence = evaluator(cfg, rule)

        if mask:
            evidence = [mask_line(e) for e in evidence]

        results.append(
            RuleResult(
                id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                category=rule["category"],
                status=status,
                description=rule["description"].strip(),
                remediation=rule["remediation"].strip(),
                references=list(rule.get("references", [])),
                evidence=evidence,
            )
        )

    return AuditResult(
        platform=platform,
        platform_name=PLATFORMS[platform]["name"],
        hostname=cfg.hostname,
        source=source,
        generated_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        tool_version=__version__,
        results=results,
        detected_platform=detect_platform(text),
    )
