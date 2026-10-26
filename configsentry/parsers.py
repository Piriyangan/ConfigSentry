"""Configuration parsers for ConfigSentry.

Two simple, dependency-free parsers:

* CiscoConfig    - indentation based (Cisco IOS / IOS-XE "show running-config")
* FortiConfig    - block based (FortiGate "show" / "show full-configuration")
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

Line = Tuple[int, str]  # (line number, text)


def _normalise(text: str) -> List[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


# --------------------------------------------------------------------------- #
# Cisco IOS / IOS-XE
# --------------------------------------------------------------------------- #
@dataclass
class CiscoBlock:
    """A top-level config line and its indented child lines."""

    lineno: int
    text: str
    children: List[Line] = field(default_factory=list)

    def child_matches(self, pattern: str) -> List[Line]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [(n, t) for n, t in self.children if rx.search(t)]


class CiscoConfig:
    """Indentation-based parser (Cisco IOS / IOS-XE). Huawei VRP reuses it."""

    platform = "cisco_ios"
    SEPARATOR = "!"
    HOSTNAME_RX = r"^hostname\s+\S+"

    _BANNER_RX = re.compile(r"^banner\s+\S+\s+(\^C|\S)(.*)$", re.IGNORECASE)

    def __init__(self, text: str):
        self.raw = text
        self.blocks: List[CiscoBlock] = []
        self._parse()

    def _banner(self, stripped: str):
        """Return (text to keep, closing delimiter or None) for a banner line."""
        m = self._BANNER_RX.match(stripped)
        if not m:
            return stripped, None
        delim, rest = m.group(1), m.group(2)
        keep = " ".join(stripped.split()[:2])
        return keep, (None if delim in rest else delim)

    def _parse(self) -> None:
        current: Optional[CiscoBlock] = None
        banner_delim: Optional[str] = None

        for lineno, line in enumerate(_normalise(self.raw), 1):
            # Skip banner bodies so banner text never triggers a rule.
            if banner_delim:
                if banner_delim in line:
                    banner_delim = None
                continue

            text = line.rstrip()
            stripped = text.strip()
            if not stripped:
                continue
            indented = text[:1] in (" ", "\t")

            if stripped == self.SEPARATOR:
                if not indented:
                    current = None
                continue

            if not indented or current is None:
                stripped, banner_delim = self._banner(stripped)
                current = CiscoBlock(lineno, stripped)
                self.blocks.append(current)
            else:
                current.children.append((lineno, stripped))

    # -- query helpers ----------------------------------------------------- #
    @property
    def global_lines(self) -> List[Line]:
        return [(b.lineno, b.text) for b in self.blocks]

    @property
    def all_lines(self) -> List[Line]:
        out: List[Line] = []
        for b in self.blocks:
            out.append((b.lineno, b.text))
            out.extend(b.children)
        return out

    def find(self, pattern: str, scope: str = "global") -> List[Line]:
        rx = re.compile(pattern, re.IGNORECASE)
        lines = self.global_lines if scope == "global" else self.all_lines
        return [(n, t) for n, t in lines if rx.search(t)]

    def blocks_matching(self, pattern: str) -> List[CiscoBlock]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [b for b in self.blocks if rx.search(b.text)]

    @property
    def hostname(self) -> Optional[str]:
        hits = self.find(self.HOSTNAME_RX)
        return hits[0][1].split(None, 1)[1] if hits else None


class HuaweiConfig(CiscoConfig):
    """Huawei VRP 'display current-configuration' (S-series, CE, AR)."""

    platform = "huawei_vrp"
    SEPARATOR = "#"
    HOSTNAME_RX = r"^sysname\s+\S+"

    _HEADER_RX = re.compile(r"^header\s+\S+(?:\s+information)?\s+(\S)(.*)$", re.IGNORECASE)

    def _banner(self, stripped: str):
        m = self._HEADER_RX.match(stripped)
        if not m:
            return stripped, None
        delim, rest = m.group(1), m.group(2)
        keep = " ".join(stripped.split()[:2])
        return keep, (None if delim in rest else delim)


class AsaConfig(CiscoConfig):
    """Cisco ASA 'show running-config'. ASA banners are one line each."""

    platform = "cisco_asa"

    def _banner(self, stripped: str):
        return stripped, None


class NxosConfig(CiscoConfig):
    """Cisco NX-OS 'show running-config'."""

    platform = "cisco_nxos"
    HOSTNAME_RX = r"^(hostname|switchname)\s+\S+"


# --------------------------------------------------------------------------- #
# Flat, line-per-setting formats (Junos set, PAN-OS set, Gaia, MikroTik)
# --------------------------------------------------------------------------- #
class FlatConfig:
    """Config as a flat list of (line number, setting) lines."""

    platform = ""
    HOSTNAME_RX: Optional[str] = None  # regex with the hostname in group 1
    COMMENT = "#"

    def __init__(self, text: str):
        self.raw = text
        self.lines: List[Line] = self._flatten(text)

    def _flatten(self, text: str) -> List[Line]:
        out = []
        for n, line in enumerate(_normalise(text), 1):
            s = line.strip()
            if s and not s.startswith(self.COMMENT):
                out.append((n, s))
        return out

    @property
    def global_lines(self) -> List[Line]:
        return self.lines

    all_lines = global_lines

    def find(self, pattern: str, scope: str = "global") -> List[Line]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [(n, t) for n, t in self.lines if rx.search(t)]

    def blocks_matching(self, pattern: str) -> list:
        return []

    @property
    def hostname(self) -> Optional[str]:
        if not self.HOSTNAME_RX:
            return None
        rx = re.compile(self.HOSTNAME_RX, re.IGNORECASE)
        for _, t in self.lines:
            m = rx.search(t)
            if m:
                return m.group(1).strip('"')
        return None


def _braces_to_set(text: str) -> List[Line]:
    """Convert Junos / PAN-OS hierarchical { } config into 'set ...' lines."""
    out: List[Line] = []
    path: List[str] = []
    stmt: list = []
    list_start: Optional[int] = None
    i, n, line = 0, len(text), 1

    def emit(tokens, lineno):
        if not tokens:
            return
        words = path + [t for t in tokens if not isinstance(t, tuple)]
        if any(w.startswith("inactive:") for w in " ".join(words).split()):
            return
        lists = [t for t in tokens if isinstance(t, tuple)]
        base = [t for t in tokens if not isinstance(t, tuple)]
        if lists:
            for item in lists[0][1]:
                out.append((lineno, "set " + " ".join(path + base + [item])))
        else:
            out.append((lineno, "set " + " ".join(path + base)))

    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif c == "#" and not stmt:
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            tok = text[i:j + 1]
            line += tok.count("\n")
            stmt.append(tok)
            i = j + 1
        elif c == "{":
            path.append(" ".join(t for t in stmt if not isinstance(t, tuple)))
            stmt = []
            i += 1
        elif c == "}":
            if stmt:
                emit(stmt, line)
                stmt = []
            if path:
                path.pop()
            i += 1
        elif c == ";":
            emit(stmt, line)
            stmt = []
            i += 1
        elif c == "[":
            list_start = len(stmt)
            i += 1
        elif c == "]":
            if list_start is not None:
                items = [t for t in stmt[list_start:] if not isinstance(t, tuple)]
                stmt = stmt[:list_start] + [("LIST", items)]
                list_start = None
            i += 1
        else:
            j = i
            while j < n and text[j] not in " \t\r\n{};[]\"":
                j += 1
            stmt.append(text[i:j])
            i = j
    return out


def _set_lines(text: str) -> List[Line]:
    return [(n, l.strip()) for n, l in enumerate(_normalise(text), 1) if l.strip().startswith("set ")]


def _looks_like_set_format(text: str) -> bool:
    lines = [l.strip() for l in _normalise(text) if l.strip() and not l.strip().startswith("#")]
    return bool(lines) and sum(l.startswith("set ") for l in lines) >= 0.5 * len(lines)


class JunosConfig(FlatConfig):
    """Juniper Junos: 'show configuration | display set' or the { } format."""

    platform = "junos"
    HOSTNAME_RX = r"^set (?:groups \S+ )?system host-name (\S+)"

    def _flatten(self, text: str) -> List[Line]:
        return _set_lines(text) if _looks_like_set_format(text) else _braces_to_set(text)


# ---- XML ------------------------------------------------------------------ #
@dataclass
class XmlNode:
    tag: str
    attrs: Dict[str, str]
    line: int
    text: str = ""
    children: List["XmlNode"] = field(default_factory=list)

    def find_all(self, tag: str) -> List["XmlNode"]:
        """All descendants with this tag (case-insensitive)."""
        tag = tag.lower()
        out = []
        stack = list(reversed(self.children))
        while stack:
            node = stack.pop()
            if node.tag.lower() == tag:
                out.append(node)
            stack.extend(reversed(node.children))
        return out

    def child(self, *path: str) -> Optional["XmlNode"]:
        node: Optional[XmlNode] = self
        for tag in path:
            if node is None:
                return None
            node = next((c for c in node.children if c.tag.lower() == tag.lower()), None)
        return node

    def value(self, *path: str, default: Optional[str] = None) -> Optional[str]:
        node = self.child(*path)
        return node.text.strip() if node is not None and node.text.strip() else default


def parse_xml(text: str) -> XmlNode:
    import xml.parsers.expat

    parser = xml.parsers.expat.ParserCreate()
    stack: List[XmlNode] = []
    holder: List[XmlNode] = []

    def start(tag, attrs):
        node = XmlNode(tag, dict(attrs), parser.CurrentLineNumber)
        if stack:
            stack[-1].children.append(node)
        else:
            holder.append(node)
        stack.append(node)

    def end(tag):
        stack.pop()

    def chars(data):
        if stack:
            stack[-1].text += data

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(text, True)
    except xml.parsers.expat.ExpatError as exc:
        raise ValueError(f"The XML file could not be read: {exc}") from exc
    if not holder:
        raise ValueError("The XML file is empty.")
    return holder[0]


def _q(value: str) -> str:
    return f'"{value}"' if (" " in value or not value) else value


def _xml_to_set(root: XmlNode) -> List[Line]:
    """PAN-OS XML -> 'set ...' lines (same shape as 'display set')."""
    out: List[Line] = []

    def walk(node: XmlNode, path: List[str]) -> None:
        if node.tag == "entry" and "name" in node.attrs:
            seg = [_q(node.attrs["name"])]
        elif node.tag == "member":
            out.append((node.line, "set " + " ".join(path + [_q(node.text.strip())])))
            return
        else:
            seg = [node.tag]
        here = path + seg
        if node.children:
            for ch in node.children:
                walk(ch, here)
        else:
            val = node.text.strip()
            out.append((node.line, "set " + " ".join(here + ([_q(val)] if val else []))))

    for ch in root.children:
        walk(ch, [])
    # Drop the device/vsys wrappers so lines match 'display set' output.
    cleaned = []
    for n, t in out:
        t = re.sub(r"^set devices localhost\.localdomain ", "set ", t)
        t = re.sub(r"^set vsys vsys1 ", "set ", t)
        cleaned.append((n, t))
    return cleaned


class PanosConfig(FlatConfig):
    """Palo Alto PAN-OS: XML export, 'set' format or { } format."""

    platform = "paloalto"
    HOSTNAME_RX = r"\bdeviceconfig system hostname (\S+)"

    def _flatten(self, text: str) -> List[Line]:
        if text.lstrip().startswith("<"):
            return _xml_to_set(parse_xml(text.strip()))
        return _set_lines(text) if _looks_like_set_format(text) else _braces_to_set(text)


class SophosConfig(FlatConfig):
    """Sophos Firewall (SFOS) Entities.xml from Backup & firmware > Import export."""

    platform = "sophos"

    def __init__(self, text: str):
        self.raw = text
        self.root = parse_xml(text.strip())
        self.lines = []

        def walk(node: XmlNode, path: str) -> None:
            here = f"{path}/{node.tag}" if path else node.tag
            if node.children:
                for ch in node.children:
                    walk(ch, here)
            elif node.text.strip():
                self.lines.append((node.line, f"{here} = {node.text.strip()}"))

        walk(self.root, "")

    @property
    def hostname(self) -> Optional[str]:
        for node in self.root.find_all("HostName"):
            if node.text.strip():
                return node.text.strip()
        return None


class GaiaConfig(FlatConfig):
    """Check Point Gaia clish 'show configuration'."""

    platform = "checkpoint_gaia"
    HOSTNAME_RX = r"^set hostname (\S+)"


class MikrotikConfig(FlatConfig):
    """MikroTik RouterOS '/export'. Lines become '/section command args'."""

    platform = "mikrotik"
    HOSTNAME_RX = r"^/system identity set name=(\"[^\"]+\"|\S+)"

    def _flatten(self, text: str) -> List[Line]:
        out: List[Line] = []
        section = ""
        buf, start = "", 0
        for n, raw in enumerate(_normalise(text), 1):
            line = raw.rstrip()
            if buf:
                buf += " " + line.strip()
            else:
                buf, start = line.strip(), n
            if buf.endswith("\\"):
                buf = buf[:-1].rstrip()
                continue
            s, buf = buf, ""
            if not s or s.startswith("#"):
                continue
            if s.startswith("/"):
                parts = s.split()
                cmd_at = next((k for k, w in enumerate(parts) if w in ("set", "add", "remove", "print", "enable", "disable")), None)
                if cmd_at is None:
                    section = s
                    continue
                out.append((start, s))
            else:
                out.append((start, f"{section} {s}"))
        return out


# --------------------------------------------------------------------------- #
# FortiGate (FortiOS)
# --------------------------------------------------------------------------- #
@dataclass
class Setting:
    tokens: List[str]
    lineno: int

    @property
    def value(self) -> str:
        return " ".join(self.tokens)


@dataclass
class FortiNode:
    name: str
    kind: str  # "root", "section" or "entry"
    path: str
    lineno: int = 0
    settings: Dict[str, Setting] = field(default_factory=dict)
    entries: Dict[str, "FortiNode"] = field(default_factory=dict)
    sections: Dict[str, "FortiNode"] = field(default_factory=dict)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        s = self.settings.get(key)
        return s.value if s else default

    def tokens(self, key: str) -> List[str]:
        s = self.settings.get(key)
        return s.tokens if s else []

    def lineno_of(self, key: str) -> int:
        s = self.settings.get(key)
        return s.lineno if s else self.lineno


def _unquoted_quotes(text: str) -> int:
    return len(re.findall(r'(?<!\\)"', text))


def _split_value(text: str) -> List[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return [t.strip('"') for t in text.split()]


class FortiConfig:
    platform = "fortigate"

    def __init__(self, text: str):
        self.raw = text
        self.root = FortiNode("root", "root", "")
        self._parse()

    def _parse(self) -> None:
        stack: List[FortiNode] = [self.root]
        pending: Optional[Tuple[int, str]] = None  # multi-line quoted value

        for lineno, line in enumerate(_normalise(self.raw), 1):
            if pending:
                start, buf = pending
                buf += "\n" + line
                if _unquoted_quotes(buf) % 2 == 0:
                    pending = None
                    self._apply_set(stack[-1], buf, start)
                else:
                    pending = (start, buf)
                continue

            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split(None, 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            parent = stack[-1]

            if cmd == "config":
                name = arg.strip()
                node = parent.sections.get(name)
                if node is None:
                    node = FortiNode(name, "section", f"{parent.path} > {name}".strip(" >"), lineno)
                    parent.sections[name] = node
                stack.append(node)
            elif cmd == "edit":
                name = _split_value(arg)[0] if arg else ""
                node = parent.entries.get(name)
                if node is None:
                    node = FortiNode(name, "entry", f'{parent.path} > "{name}"', lineno)
                    parent.entries[name] = node
                stack.append(node)
            elif cmd == "set":
                if _unquoted_quotes(s) % 2 == 1:
                    pending = (lineno, s)
                else:
                    self._apply_set(parent, s, lineno)
            elif cmd == "unset":
                parent.settings.pop(arg.strip(), None)
            elif cmd == "next":
                if stack[-1].kind == "entry":
                    stack.pop()
            elif cmd == "end":
                while len(stack) > 1 and stack[-1].kind == "entry":
                    stack.pop()
                if len(stack) > 1:
                    stack.pop()

    @staticmethod
    def _apply_set(node: FortiNode, text: str, lineno: int) -> None:
        body = text.strip()[3:].strip()  # drop "set"
        parts = body.split(None, 1)
        if not parts:
            return
        key = parts[0]
        value = _split_value(parts[1]) if len(parts) > 1 else []
        node.settings[key] = Setting(value, lineno)

    # -- query helpers ----------------------------------------------------- #
    def find_sections(self, name: str) -> List[FortiNode]:
        """Find every section with this name, at any depth (handles VDOMs)."""
        found: List[FortiNode] = []

        def walk(node: FortiNode) -> None:
            for sec_name, sec in node.sections.items():
                if sec_name == name:
                    found.append(sec)
                walk(sec)
            for entry in node.entries.values():
                walk(entry)

        walk(self.root)
        return found

    @property
    def hostname(self) -> Optional[str]:
        for sec in self.find_sections("system global"):
            if sec.get("hostname"):
                return sec.get("hostname")
        return None


PARSERS = {
    "cisco_ios": CiscoConfig,
    "cisco_nxos": NxosConfig,
    "huawei_vrp": HuaweiConfig,
    "junos": JunosConfig,
    "mikrotik": MikrotikConfig,
    "cisco_asa": AsaConfig,
    "fortigate": FortiConfig,
    "paloalto": PanosConfig,
    "checkpoint_gaia": GaiaConfig,
    "sophos": SophosConfig,
}


def detect_platform(text: str) -> Optional[str]:
    """Best-effort guess of the platform from the config text."""
    head = text[:30000]
    stripped = head.lstrip()
    if stripped.startswith("<"):
        if re.search(r"<Configuration\b[^>]*APIVersion", head, re.I) or "<FirewallRule" in head:
            return "sophos"
        if re.search(r"<config\b[^>]*(urldb|version)", head) or "<deviceconfig>" in head:
            return "paloalto"
        return None
    if re.search(r"^#config-version=F", head, re.M) or re.search(
        r"^\s*config system (global|interface)\s*$", head, re.M
    ):
        return "fortigate"
    if re.search(r"by RouterOS", head) or re.search(r"^/(ip service|system identity|interface bridge)\b", head, re.M):
        return "mikrotik"
    if re.search(r"^# Language version", head, re.M) or re.search(r"^set (password-controls|net-access|web ssl-port)\b", head, re.M):
        return "checkpoint_gaia"
    if re.search(r"\bdeviceconfig\b", head) and re.search(r"(^set (deviceconfig|mgt-config|rulebase)|deviceconfig \{)", head, re.M):
        return "paloalto"
    if re.search(r"^set (system|interfaces|protocols|security|snmp) ", head, re.M) or re.search(
        r"^(## Last commit|version \d+\.\d+R|system \{)", head, re.M
    ):
        return "junos"
    if re.search(r"^sysname \S+", head, re.M) or re.search(r"^\s*(return|user-interface vty .*)$", head, re.M):
        return "huawei_vrp"
    if re.search(r"^ASA Version ", head, re.M) or re.search(r"^\s*nameif \S+", head, re.M):
        return "cisco_asa"
    if re.search(r"^!Command: show running-config", head, re.M) or re.search(r"^(feature \S+|switchname \S+)$", head, re.M):
        return "cisco_nxos"
    if re.search(r"^(hostname \S+|interface \S+|version \d+\.\d+|line vty )", head, re.M):
        return "cisco_ios"
    return None


def read_upload(name: str, data: bytes) -> str:
    """Return config text from an uploaded file (plain, .tar/.tgz, .zip or .gz)."""
    import gzip
    import io
    import tarfile
    import zipfile

    limit = 50 * 1024 * 1024
    preferred = ("entities.xml", ".xml", ".conf", ".cfg", ".txt", ".rsc", ".set")

    def pick(names):
        for suffix in preferred:
            for nm in names:
                if nm.lower().endswith(suffix):
                    return nm
        return names[0] if names else None

    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = [m for m in tf.getmembers() if m.isfile() and m.size <= limit]
            chosen = pick([m.name for m in members])
            if chosen:
                data = tf.extractfile(chosen).read()
    except (tarfile.ReadError, EOFError, OSError):
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir() and i.file_size <= limit]
                chosen = pick([i.filename for i in infos])
                if chosen:
                    data = zf.read(chosen)
        elif data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)[:limit]

    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")
