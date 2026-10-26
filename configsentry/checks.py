"""Custom checks that are too complex for a single regex or setting.

Each function takes (config, rule) and returns (status, evidence_list).
Register new functions in CUSTOM_CHECKS at the bottom of this file.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

PASS, FAIL, NA = "PASS", "FAIL", "N/A"
Result = Tuple[str, List[str]]


# --------------------------------------------------------------------------- #
# Cisco IOS / IOS-XE
# --------------------------------------------------------------------------- #
def _access_ports(cfg):
    """Active access ports that are likely edge ports.

    Port-channels and their member ports are skipped: they normally connect
    switches, servers or firewalls, where BPDU Guard may not be wanted.
    """
    ports = []
    for b in cfg.blocks_matching(r"^interface\s+\S+"):
        if re.match(r"^interface\s+port-channel", b.text, re.I):
            continue
        if b.child_matches(r"^channel-group\s+\d+"):
            continue
        if b.child_matches(r"^switchport mode access$") and not b.child_matches(r"^shutdown$"):
            ports.append(b)
    return ports


def _describe(block) -> str:
    desc = block.child_matches(r"^description\s+")
    label = f"line {block.lineno}: {block.text}"
    if desc:
        label += f"  (description: {desc[0][1].split(None, 1)[1]})"
    return label


def ios_access_ports_bpduguard(cfg, rule) -> Result:
    ports = _access_ports(cfg)
    if not ports:
        return NA, ["No active access ports found (port-channels are skipped)."]
    if cfg.find(r"^spanning-tree portfast (edge )?bpduguard default"):
        return PASS, ["BPDU Guard is enabled globally for PortFast ports."]
    bad = [_describe(b) for b in ports if not b.child_matches(r"^spanning-tree bpduguard enable")]
    return (FAIL, bad) if bad else (PASS, [])


def ios_dhcp_snooping(cfg, rule) -> Result:
    if not _access_ports(cfg):
        return NA, ["No active access ports found."]
    if cfg.find(r"^ip dhcp snooping$") and cfg.find(r"^ip dhcp snooping vlan "):
        return PASS, []
    return FAIL, ["Access ports exist but 'ip dhcp snooping' and 'ip dhcp snooping vlan <list>' are not both configured."]


def ios_ospf_authentication(cfg, rule) -> Result:
    ospf = cfg.blocks_matching(r"^router ospf\s+\S+")
    if not ospf:
        return NA, ["OSPF is not configured."]
    if any(b.child_matches(r"^area \S+ authentication") for b in ospf):
        return PASS, []
    for b in cfg.blocks_matching(r"^interface\s+\S+"):
        if b.child_matches(r"^ip ospf authentication"):
            return PASS, []
    return FAIL, [f"line {b.lineno}: {b.text}  ->  no area or interface authentication" for b in ospf]


# --------------------------------------------------------------------------- #
# FortiGate
# --------------------------------------------------------------------------- #
def _interfaces(cfg):
    for sec in cfg.find_sections("system interface"):
        for name, intf in sec.entries.items():
            yield name, intf


def _is_wan(name: str, intf) -> bool:
    return (intf.get("role") or "").lower() == "wan" or bool(re.match(r"^wan\d*$", name, re.I))


def fgt_insecure_admin_protocols(cfg, rule) -> Result:
    found = False
    bad = []
    for name, intf in _interfaces(cfg):
        found = True
        access = [a.lower() for a in intf.tokens("allowaccess")]
        weak = [a for a in access if a in ("http", "telnet")]
        if weak:
            bad.append(f'line {intf.lineno_of("allowaccess")}: interface "{name}" allowaccess includes {", ".join(weak)}')
    if not found:
        return NA, ["No 'config system interface' section found."]
    return (FAIL, bad) if bad else (PASS, [])


def fgt_wan_admin_access(cfg, rule) -> Result:
    risky = {"http", "https", "ssh", "telnet", "snmp"}
    wan_found = False
    bad = []
    for name, intf in _interfaces(cfg):
        if not _is_wan(name, intf):
            continue
        wan_found = True
        access = [a.lower() for a in intf.tokens("allowaccess")]
        hits = [a for a in access if a in risky]
        if hits:
            bad.append(f'line {intf.lineno_of("allowaccess")}: WAN interface "{name}" allows {", ".join(hits)}')
    if not wan_found:
        return NA, ["No WAN interface found (role wan or name wanX)."]
    return (FAIL, bad) if bad else (PASS, [])


def _admins(cfg):
    for sec in cfg.find_sections("system admin"):
        for name, adm in sec.entries.items():
            yield name, adm


def fgt_admin_trusted_hosts(cfg, rule) -> Result:
    found = False
    bad = []
    for name, adm in _admins(cfg):
        found = True
        hosts = [
            adm.get(k) for k in adm.settings
            if k.startswith("trusthost") or k.startswith("ip6-trusthost")
        ]
        restricted = [h for h in hosts if h and h not in ("0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0")]
        if not restricted:
            bad.append(f'line {adm.lineno}: admin "{name}" has no trusted hosts (can log in from any IP)')
    if not found:
        return NA, ["No 'config system admin' section found."]
    return (FAIL, bad) if bad else (PASS, [])


def fgt_default_admin_name(cfg, rule) -> Result:
    found = False
    for name, adm in _admins(cfg):
        found = True
        if name.lower() == "admin":
            return FAIL, [f'line {adm.lineno}: default administrator account "admin" is still in use']
    return (PASS, []) if found else (NA, ["No 'config system admin' section found."])


def _policies(cfg):
    for sec in cfg.find_sections("firewall policy"):
        for pid, pol in sec.entries.items():
            if (pol.get("action") or "deny").lower() == "accept" and (pol.get("status") or "enable") == "enable":
                yield pid, pol


def _lower(tokens):
    return [t.lower() for t in tokens]


def fgt_policy_any_any(cfg, rule) -> Result:
    bad = []
    for pid, pol in _policies(cfg):
        if (
            "all" in _lower(pol.tokens("srcaddr"))
            and "all" in _lower(pol.tokens("dstaddr"))
            and "all" in _lower(pol.tokens("service"))
        ):
            label = pol.get("name") or ""
            bad.append(f'line {pol.lineno}: policy {pid} {label!r} accepts all sources, destinations and services')
    return (FAIL, bad) if bad else (PASS, [])


def fgt_policy_service_all(cfg, rule) -> Result:
    bad = []
    for pid, pol in _policies(cfg):
        any_any = "all" in _lower(pol.tokens("srcaddr")) and "all" in _lower(pol.tokens("dstaddr"))
        if "all" in _lower(pol.tokens("service")) and not any_any:
            label = pol.get("name") or ""
            bad.append(f'line {pol.lineno}: policy {pid} {label!r} allows service ALL')
    return (FAIL, bad) if bad else (PASS, [])


def fgt_policy_logging(cfg, rule) -> Result:
    bad = []
    for pid, pol in _policies(cfg):
        if (pol.get("logtraffic") or "utm").lower() == "disable":
            label = pol.get("name") or ""
            bad.append(f'line {pol.lineno_of("logtraffic")}: policy {pid} {label!r} has logtraffic disable')
    return (FAIL, bad) if bad else (PASS, [])


def fgt_snmp_default_community(cfg, rule) -> Result:
    bad = []
    for sec in cfg.find_sections("system snmp community"):
        for cid, com in sec.entries.items():
            if (com.get("name") or "").lower() in ("public", "private"):
                bad.append(f'line {com.lineno_of("name")}: SNMP entry {cid} uses public/private as its community')
    return (FAIL, bad) if bad else (PASS, [])


def fgt_remote_logging(cfg, rule) -> Result:
    targets = ["log syslogd setting", "log fortianalyzer setting", "log fortianalyzer-cloud setting"]
    for t in targets:
        for sec in cfg.find_sections(t):
            if (sec.get("status") or "disable").lower() == "enable":
                return PASS, [f"line {sec.lineno_of('status')}: config {t} -> status enable"]
    return FAIL, ["No remote log destination (syslog or FortiAnalyzer) is enabled."]


# --------------------------------------------------------------------------- #
# Huawei VRP
# --------------------------------------------------------------------------- #
def _vrp_access_ports(cfg):
    """Active access ports, skipping Eth-Trunks and their member ports."""
    ports = []
    for b in cfg.blocks_matching(r"^interface\s+\S+"):
        if re.match(r"^interface\s+eth-trunk", b.text, re.I):
            continue
        if b.child_matches(r"^eth-trunk\s+\d+"):
            continue
        if b.child_matches(r"^port link-type access$") and not b.child_matches(r"^shutdown$"):
            ports.append(b)
    return ports


def vrp_bpdu_protection(cfg, rule) -> Result:
    ports = _vrp_access_ports(cfg)
    if not ports:
        return NA, ["No active access ports found (Eth-Trunks are skipped)."]
    if cfg.find(r"^stp bpdu-protection$"):
        return PASS, ["BPDU protection is enabled globally."]
    return FAIL, ["'stp bpdu-protection' is not enabled. Access ports without it:"] + [_describe(b) for b in ports]


def vrp_dhcp_snooping(cfg, rule) -> Result:
    if not _vrp_access_ports(cfg):
        return NA, ["No active access ports found."]
    if cfg.find(r"^dhcp snooping enable"):
        return PASS, []
    return FAIL, ["Access ports exist but 'dhcp snooping enable' is not configured."]


def vrp_ospf_authentication(cfg, rule) -> Result:
    ospf = cfg.blocks_matching(r"^ospf(\s+\d+)?(\s|$)")
    if not ospf:
        return NA, ["OSPF is not configured."]
    if any(b.child_matches(r"^authentication-mode\s+") for b in ospf):
        return PASS, []
    for b in cfg.blocks_matching(r"^interface\s+\S+"):
        if b.child_matches(r"^ospf authentication-mode\s+"):
            return PASS, []
    return FAIL, [f"line {b.lineno}: {b.text}  ->  no area or interface authentication" for b in ospf]


# --------------------------------------------------------------------------- #
# Cisco NX-OS
# --------------------------------------------------------------------------- #
def nxos_edge_bpduguard(cfg, rule) -> Result:
    if cfg.find(r"^spanning-tree port type edge bpduguard default$"):
        return PASS, ["BPDU Guard is enabled by default on edge ports."]
    edge = []
    for b in cfg.blocks_matching(r"^interface\s+\S+"):
        if re.match(r"^interface\s+port-channel", b.text, re.I) or b.child_matches(r"^channel-group\s+\d+"):
            continue
        if b.child_matches(r"^spanning-tree port type edge( trunk)?$") and not b.child_matches(r"^shutdown$"):
            edge.append(b)
    if not edge:
        return NA, ["No edge ports found (spanning-tree port type edge)."]
    bad = [_describe(b) for b in edge if not b.child_matches(r"^spanning-tree bpduguard enable$")]
    return (FAIL, bad) if bad else (PASS, [])


def nxos_snmp_acl(cfg, rule) -> Result:
    names = {}
    for n, t in cfg.find(r"^snmp-server community \S+ (group|ro|rw)\b"):
        names.setdefault(t.split()[2], (n, t))
    if not names:
        return NA, ["No SNMP communities configured."]
    with_acl = {t.split()[2] for _, t in cfg.find(r"^snmp-server community \S+ use-(ipv4|ipv6)?acl \S+")}
    bad = [f"line {n}: {t}" for name, (n, t) in names.items() if name not in with_acl]
    return (FAIL, bad) if bad else (PASS, [])


# --------------------------------------------------------------------------- #
# Juniper Junos
# --------------------------------------------------------------------------- #
def junos_snmp_clients(cfg, rule) -> Result:
    names = {}
    for n, t in cfg.find(r"^set snmp community \S+"):
        names.setdefault(t.split()[3], (n, t))
    if not names:
        return NA, ["No SNMP communities configured."]
    restricted = {t.split()[3] for _, t in cfg.find(r"^set snmp community \S+ (clients|client-list-name) ")}
    bad = [f"line {n}: {t}" for name, (n, t) in names.items() if name not in restricted]
    return (FAIL, bad) if bad else (PASS, [])


def _junos_policies(cfg):
    rx = re.compile(r"^set (?:logical-systems \S+ )?security policies (from-zone \S+ to-zone \S+|global) policy (\S+) (.*)$", re.I)
    pols: Dict[tuple, dict] = {}
    for n, t in cfg.lines:
        m = rx.match(t)
        if not m:
            continue
        key = (m.group(1), m.group(2))
        p = pols.setdefault(key, {"line": n, "src": [], "dst": [], "app": [], "then": []})
        rest = m.group(3).split()
        if rest[:2] == ["match", "source-address"]:
            p["src"] += rest[2:]
        elif rest[:2] == ["match", "destination-address"]:
            p["dst"] += rest[2:]
        elif rest[:2] == ["match", "application"]:
            p["app"] += rest[2:]
        elif rest[:1] == ["then"]:
            p["then"].append(" ".join(rest[1:]))
    return pols


def _junos_permit(p) -> bool:
    return any(t.startswith("permit") for t in p["then"])


def junos_policy_any_any(cfg, rule) -> Result:
    pols = _junos_policies(cfg)
    if not pols:
        return NA, ["No security policies (SRX) found."]
    bad = [
        f"line {p['line']}: policy {name} ({ctx}) permits any source, destination and application"
        for (ctx, name), p in pols.items()
        if _junos_permit(p) and "any" in p["src"] and "any" in p["dst"] and "any" in p["app"]
    ]
    return (FAIL, bad) if bad else (PASS, [])


def junos_policy_logging(cfg, rule) -> Result:
    pols = _junos_policies(cfg)
    if not pols:
        return NA, ["No security policies (SRX) found."]
    bad = [
        f"line {p['line']}: policy {name} ({ctx}) has no session logging"
        for (ctx, name), p in pols.items()
        if _junos_permit(p) and not any(t.startswith("log ") or t == "log" for t in p["then"])
    ]
    return (FAIL, bad) if bad else (PASS, [])


def junos_ospf_auth(cfg, rule) -> Result:
    ospf = cfg.find(r"^set (?:routing-instances \S+ )?protocols ospf3? ")
    if not ospf:
        return NA, ["OSPF is not configured."]
    if any(" authentication " in f" {t} " for _, t in ospf):
        return PASS, []
    return FAIL, [f"line {ospf[0][0]}: OSPF is configured without authentication on any interface"]


# --------------------------------------------------------------------------- #
# MikroTik RouterOS
# --------------------------------------------------------------------------- #
_MT_DEFAULT_ENABLED = {"telnet", "ftp", "www", "ssh", "api", "winbox", "api-ssl"}
_MT_ALL = _MT_DEFAULT_ENABLED | {"www-ssl"}


def _mt_services(cfg):
    """Return {service: {"enabled": bool, "address": str|None, "line": n}}."""
    svc = {name: {"enabled": name in _MT_DEFAULT_ENABLED, "address": None, "line": 0, "shown": False} for name in _MT_ALL}
    for n, t in cfg.find(r"^/ip service set "):
        rest = t[len("/ip service set "):]
        m = re.match(r"\[\s*find\s+(?:where\s+)?name=\"?([\w-]+)\"?\s*\]\s*(.*)$", rest) or re.match(r"([\w-]+)\s*(.*)$", rest)
        if not m:
            continue
        name, args = m.group(1), m.group(2)
        entry = svc.setdefault(name, {"enabled": True, "address": None, "line": n, "shown": False})
        entry["line"], entry["shown"] = n, True
        d = re.search(r"\bdisabled=(yes|no)\b", args)
        if d:
            entry["enabled"] = d.group(1) == "no"
        a = re.search(r"\baddress=(\S+)", args)
        if a and a.group(1) not in ('""', "0.0.0.0/0"):
            entry["address"] = a.group(1)
    return svc


def mt_insecure_services(cfg, rule) -> Result:
    svc = _mt_services(cfg)
    bad = []
    for name in ("telnet", "ftp", "www", "api"):
        e = svc[name]
        if e["enabled"]:
            where = f"line {e['line']}: " if e["shown"] else ""
            note = "" if e["shown"] else " (not disabled - enabled by default)"
            bad.append(f"{where}/ip service {name} is enabled{note}")
    return (FAIL, bad) if bad else (PASS, [])


def mt_service_address(cfg, rule) -> Result:
    svc = _mt_services(cfg)
    bad = [
        f"{'line ' + str(e['line']) + ': ' if e['shown'] else ''}/ip service {name} is enabled with no address= restriction"
        for name, e in sorted(svc.items()) if e["enabled"] and not e["address"]
    ]
    return (FAIL, bad) if bad else (PASS, [])


def mt_snmp_default(cfg, rule) -> Result:
    enabled = cfg.find(r"^/snmp set .*\benabled=yes\b")
    if not enabled:
        return NA, ["SNMP is not enabled."]
    bad = [f"line {n}: {t}" for n, t in cfg.find(r"^/snmp community (add|set) .*\bname=\"?(public|private)\"?(\s|$)")]
    renamed = cfg.find(r"^/snmp community set \[\s*find\s+default=yes\s*\] .*\bname=")
    if not renamed:
        bad.append("The default community is still named 'public' (no '/snmp community set [ find default=yes ] name=...').")
    return (FAIL, bad) if bad else (PASS, [])


def mt_input_firewall(cfg, rule) -> Result:
    if cfg.find(r"^/ip firewall filter add (?=.*\bchain=input\b)(?=.*\baction=drop\b)"):
        return PASS, []
    return FAIL, ["No '/ip firewall filter' rule drops traffic in the input chain (traffic to the router itself)."]


# --------------------------------------------------------------------------- #
# Palo Alto PAN-OS
# --------------------------------------------------------------------------- #
def _pan_rules(cfg):
    rx = re.compile(r"\b(?:pre-|post-)?rulebase security rules (\"[^\"]+\"|\S+) (\S+)\s*(.*)$", re.I)
    rules: Dict[str, dict] = {}
    for n, t in cfg.lines:
        m = rx.search(t)
        if not m:
            continue
        name, fld, val = m.group(1).strip('"'), m.group(2).lower(), m.group(3)
        r = rules.setdefault(name, {"line": n, "fields": {}})
        vals = [v.strip('"') for v in val.replace("[", " ").replace("]", " ").split()]
        r["fields"].setdefault(fld, []).extend(vals)
    return rules


def _pan_allow(r) -> bool:
    f = r["fields"]
    return "allow" in [v.lower() for v in f.get("action", [])] and "yes" not in f.get("disabled", [])


def _pan_any(r, fld) -> bool:
    return "any" in [v.lower() for v in r["fields"].get(fld, ["any"])]


def pan_any_any(cfg, rule) -> Result:
    rules = _pan_rules(cfg)
    if not rules:
        return NA, ["No security rules found."]
    bad = [
        f"line {r['line']}: rule '{name}' allows any source, destination, application and service"
        for name, r in rules.items()
        if _pan_allow(r) and all(_pan_any(r, f) for f in ("source", "destination", "application", "service"))
    ]
    return (FAIL, bad) if bad else (PASS, [])


def pan_app_service_any(cfg, rule) -> Result:
    rules = _pan_rules(cfg)
    if not rules:
        return NA, ["No security rules found."]
    bad = [
        f"line {r['line']}: rule '{name}' allows application any with service any"
        for name, r in rules.items()
        if _pan_allow(r) and _pan_any(r, "application") and _pan_any(r, "service")
        and not (_pan_any(r, "source") and _pan_any(r, "destination"))
    ]
    return (FAIL, bad) if bad else (PASS, [])


def pan_log_end(cfg, rule) -> Result:
    rules = _pan_rules(cfg)
    if not rules:
        return NA, ["No security rules found."]
    bad = [f"line {r['line']}: rule '{name}' has log-end no" for name, r in rules.items()
           if _pan_allow(r) and "no" in r["fields"].get("log-end", [])]
    return (FAIL, bad) if bad else (PASS, [])


def pan_no_profile(cfg, rule) -> Result:
    rules = _pan_rules(cfg)
    if not rules:
        return NA, ["No security rules found."]
    bad = [f"line {r['line']}: rule '{name}' has no security profile or profile group" for name, r in rules.items()
           if _pan_allow(r) and "profile-setting" not in r["fields"]]
    return (FAIL, bad) if bad else (PASS, [])


# --------------------------------------------------------------------------- #
# Sophos Firewall (SFOS)
# --------------------------------------------------------------------------- #
def _sop_text(node, *path, default=""):
    v = node.value(*path, default=default) if node is not None else default
    return (v or "").strip()


def sop_wan_admin(cfg, rule) -> Result:
    zones = cfg.root.find_all("Zone")
    zones = [z for z in zones if z.child("Name") is not None]
    if not zones:
        return NA, ["No zones found in the export."]
    bad = []
    for z in zones:
        name, ztype = _sop_text(z, "Name"), _sop_text(z, "Type")
        if name.upper() != "WAN" and ztype.upper() != "WAN":
            continue
        admin = z.child("ApplianceAccess", "AdminServices")
        services = [c.tag for c in (admin.children if admin else []) if c.text.strip()]
        if services:
            bad.append(f"line {z.line}: zone {name} allows admin services: {', '.join(services)}")
    return (FAIL, bad) if bad else (PASS, [])


def _sop_rules(cfg):
    for r in cfg.root.find_all("FirewallRule"):
        if _sop_text(r, "Status", default="Enable").lower() != "enable":
            continue
        pol = r.child("NetworkPolicy") or r.child("UserPolicy")
        if pol is None or _sop_text(pol, "Action").lower() != "accept":
            continue
        yield r, pol


def _sop_empty(pol, tag) -> bool:
    node = pol.child(tag)
    return node is None or not any(c.text.strip() for c in node.children) and not node.text.strip()


def sop_any_any(cfg, rule) -> Result:
    bad = [f"line {r.line}: rule '{_sop_text(r, 'Name')}' accepts any source, destination and service"
           for r, pol in _sop_rules(cfg)
           if _sop_empty(pol, "SourceNetworks") and _sop_empty(pol, "DestinationNetworks") and _sop_empty(pol, "Services")]
    return (FAIL, bad) if bad else (PASS, [])


def sop_any_service(cfg, rule) -> Result:
    bad = [f"line {r.line}: rule '{_sop_text(r, 'Name')}' accepts any service"
           for r, pol in _sop_rules(cfg)
           if _sop_empty(pol, "Services")
           and not (_sop_empty(pol, "SourceNetworks") and _sop_empty(pol, "DestinationNetworks"))]
    return (FAIL, bad) if bad else (PASS, [])


def sop_logging(cfg, rule) -> Result:
    bad = [f"line {r.line}: rule '{_sop_text(r, 'Name')}' has traffic logging disabled"
           for r, pol in _sop_rules(cfg) if _sop_text(pol, "LogTraffic", default="Disable").lower() != "enable"]
    return (FAIL, bad) if bad else (PASS, [])


def sop_wan_ips(cfg, rule) -> Result:
    bad = []
    for r, pol in _sop_rules(cfg):
        zones = [c.text.strip().upper() for c in (pol.child("SourceZones").children if pol.child("SourceZones") else [])]
        if "WAN" in zones and _sop_text(pol, "IntrusionPrevention", default="None").lower() in ("none", ""):
            bad.append(f"line {r.line}: rule '{_sop_text(r, 'Name')}' accepts traffic from WAN without an IPS policy")
    return (FAIL, bad) if bad else (PASS, [])


def sop_snmp_default(cfg, rule) -> Result:
    bad = [f"line {c.line}: SNMP community uses a default name" for c in cfg.root.find_all("SNMPCommunity")
           if _sop_text(c, "Name").lower() in ("public", "private")]
    return (FAIL, bad) if bad else (PASS, [])


def sop_snmp_v1v2(cfg, rule) -> Result:
    comms = cfg.root.find_all("SNMPCommunity")
    if not comms:
        return NA, ["No SNMP communities configured."]
    bad = [f"line {c.line}: SNMP community '{_sop_text(c, 'Name')}' allows SNMPv1/v2c" for c in comms
           if "enable" in (_sop_text(c, "SupportV1Protocol").lower(), _sop_text(c, "SupportV2CProtocol").lower())]
    return (FAIL, bad) if bad else (PASS, [])


def _sop_login_security(cfg):
    nodes = cfg.root.find_all("LoginSecurity")
    return nodes[0] if nodes else None


def sop_lockout(cfg, rule) -> Result:
    ls = _sop_login_security(cfg)
    if ls is None:
        return NA, ["No LoginSecurity settings in the export."]
    if _sop_text(ls, "BlockLogin").lower() == "enable":
        return PASS, []
    return FAIL, [f"line {ls.line}: admin login blocking after failed attempts is disabled"]


def sop_session_timeout(cfg, rule) -> Result:
    ls = _sop_login_security(cfg)
    if ls is None:
        return NA, ["No LoginSecurity settings in the export."]
    raw = _sop_text(ls, "LogoutSession")
    try:
        ok = 0 < int(raw) <= 15
    except ValueError:
        ok = False
    return (PASS, []) if ok else (FAIL, [f"line {ls.line}: admin session logout is '{raw or 'disabled'}' (should be 1-15 minutes)"])


def sop_password_complexity(cfg, rule) -> Result:
    nodes = cfg.root.find_all("PasswordComplexityCheck")
    if not nodes:
        return NA, ["No password complexity settings in the export."]
    if any(n.text.strip().lower() == "enable" for n in nodes):
        return PASS, []
    return FAIL, [f"line {nodes[0].line}: password complexity check is disabled"]


def sop_disclaimer(cfg, rule) -> Result:
    nodes = cfg.root.find_all("LoginDisclaimer")
    if not nodes:
        return NA, ["No login disclaimer setting in the export."]
    if any(n.text.strip().lower() == "enable" for n in nodes):
        return PASS, []
    return FAIL, [f"line {nodes[0].line}: login disclaimer is disabled"]


def sop_syslog(cfg, rule) -> Result:
    servers = [s for s in cfg.root.find_all("SyslogServers") if s.children]
    return (PASS, []) if servers else (FAIL, ["No syslog server is configured."])


CUSTOM_CHECKS: Dict[str, Callable] = {
    # Cisco
    "ios_access_ports_bpduguard": ios_access_ports_bpduguard,
    "ios_dhcp_snooping": ios_dhcp_snooping,
    "ios_ospf_authentication": ios_ospf_authentication,
    # Huawei
    "vrp_bpdu_protection": vrp_bpdu_protection,
    "vrp_dhcp_snooping": vrp_dhcp_snooping,
    "vrp_ospf_authentication": vrp_ospf_authentication,
    # NX-OS
    "nxos_edge_bpduguard": nxos_edge_bpduguard,
    "nxos_snmp_acl": nxos_snmp_acl,
    # Junos
    "junos_snmp_clients": junos_snmp_clients,
    "junos_policy_any_any": junos_policy_any_any,
    "junos_policy_logging": junos_policy_logging,
    "junos_ospf_auth": junos_ospf_auth,
    # MikroTik
    "mt_insecure_services": mt_insecure_services,
    "mt_service_address": mt_service_address,
    "mt_snmp_default": mt_snmp_default,
    "mt_input_firewall": mt_input_firewall,
    # Palo Alto
    "pan_any_any": pan_any_any,
    "pan_app_service_any": pan_app_service_any,
    "pan_log_end": pan_log_end,
    "pan_no_profile": pan_no_profile,
    # Sophos
    "sop_wan_admin": sop_wan_admin,
    "sop_any_any": sop_any_any,
    "sop_any_service": sop_any_service,
    "sop_logging": sop_logging,
    "sop_wan_ips": sop_wan_ips,
    "sop_snmp_default": sop_snmp_default,
    "sop_snmp_v1v2": sop_snmp_v1v2,
    "sop_lockout": sop_lockout,
    "sop_session_timeout": sop_session_timeout,
    "sop_password_complexity": sop_password_complexity,
    "sop_disclaimer": sop_disclaimer,
    "sop_syslog": sop_syslog,
    # FortiGate
    "fgt_insecure_admin_protocols": fgt_insecure_admin_protocols,
    "fgt_wan_admin_access": fgt_wan_admin_access,
    "fgt_admin_trusted_hosts": fgt_admin_trusted_hosts,
    "fgt_default_admin_name": fgt_default_admin_name,
    "fgt_policy_any_any": fgt_policy_any_any,
    "fgt_policy_service_all": fgt_policy_service_all,
    "fgt_policy_logging": fgt_policy_logging,
    "fgt_snmp_default_community": fgt_snmp_default_community,
    "fgt_remote_logging": fgt_remote_logging,
}
