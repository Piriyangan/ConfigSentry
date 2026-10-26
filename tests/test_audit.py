from pathlib import Path

import pytest

from configsentry.engine import FAIL, NA, PASS, PLATFORMS, load_rules, run_audit
from configsentry.masking import mask_line
from configsentry.parsers import CiscoConfig, FortiConfig, detect_platform
from configsentry.report import to_html, to_json

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def audit(name, platform):
    return run_audit((SAMPLES / name).read_text(), platform, source=name)


def status_map(result):
    return {r.id: r.status for r in result.results}


# --------------------------------------------------------------------------- #
# Rule packs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("platform", list(PLATFORMS))
def test_rule_packs_load(platform):
    rules = load_rules(platform)
    assert len(rules) >= 10


# --------------------------------------------------------------------------- #
# Cisco
# --------------------------------------------------------------------------- #
def test_cisco_weak_config_fails_expected_rules():
    s = status_map(audit("cisco_weak.txt", "cisco_ios"))
    for rid in ["IOS-001", "IOS-003", "IOS-009", "IOS-010", "IOS-012", "IOS-017", "IOS-018", "IOS-026", "IOS-028"]:
        assert s[rid] == FAIL, rid


def test_cisco_hardened_config_has_no_findings():
    r = audit("cisco_hardened.txt", "cisco_ios")
    assert [f.id for f in r.failed] == []
    assert r.score == 100


def test_cisco_banner_text_is_ignored():
    cfg = CiscoConfig((SAMPLES / "cisco_weak.txt").read_text())
    # the banner contains the words "enable password" - only the real line should match
    assert len(cfg.find(r"^enable password")) == 1


def test_cisco_shutdown_access_port_is_ignored():
    r = audit("cisco_weak.txt", "cisco_ios")
    bpdu = next(x for x in r.results if x.id == "IOS-026")
    assert not any("GigabitEthernet0/3" in e for e in bpdu.evidence)


def test_cisco_not_applicable_when_feature_missing():
    r = run_audit("hostname R1\ninterface Gi0/0\n ip address 192.0.2.1 255.255.255.0\n", "cisco_ios")
    s = status_map(r)
    assert s["IOS-010"] == NA  # no VTY lines
    assert s["IOS-028"] == NA  # no OSPF


# --------------------------------------------------------------------------- #
# FortiGate
# --------------------------------------------------------------------------- #
def test_fortigate_weak_config_fails_expected_rules():
    s = status_map(audit("fortigate_weak.conf", "fortigate"))
    for rid in ["FGT-001", "FGT-002", "FGT-003", "FGT-010", "FGT-011", "FGT-013", "FGT-014", "FGT-015", "FGT-016"]:
        assert s[rid] == FAIL, rid
    assert s["FGT-012"] == PASS


def test_fortigate_hardened_config_has_no_findings():
    r = audit("fortigate_hardened.conf", "fortigate")
    assert [f.id for f in r.failed] == []


def test_fortigate_parser_handles_multiline_values():
    cfg = FortiConfig((SAMPLES / "fortigate_weak.conf").read_text())
    policies = cfg.find_sections("firewall policy")
    assert len(policies) == 1 and set(policies[0].entries) == {"1", "2"}
    assert cfg.hostname == "LAB-FGT-01"


def test_fortigate_vdom_sections_are_found():
    text = """config vdom
edit root
config firewall policy
    edit 7
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end
next
end
"""
    s = status_map(run_audit(text, "fortigate"))
    assert s["FGT-013"] == FAIL


# --------------------------------------------------------------------------- #
# Masking, detection, reports
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line, secret",
    [
        ("username admin privilege 15 password 7 094F471A1A0A", "094F471A1A0A"),
        ("enable secret 9 $9$abc$def", "$9$abc$def"),
        ("snmp-server community S3cret RO 10", "S3cret"),
        ("tacacs-server key MyTacKey", "MyTacKey"),
        (" ip ospf message-digest-key 1 md5 7 OSPFKEY", "OSPFKEY"),
        ("        set password ENC SH2abcdef", "SH2abcdef"),
        ("        set psksecret ENC xyz123", "xyz123"),
    ],
)
def test_secrets_are_masked(line, secret):
    assert secret not in mask_line(line)


def test_evidence_is_masked_by_default():
    r = audit("cisco_weak.txt", "cisco_ios")
    text = "\n".join(e for x in r.results for e in x.evidence)
    assert "094F471A1A0A" not in text


def test_platform_detection():
    assert detect_platform((SAMPLES / "cisco_weak.txt").read_text()) == "cisco_ios"
    assert detect_platform((SAMPLES / "fortigate_weak.conf").read_text()) == "fortigate"
    assert detect_platform((SAMPLES / "huawei_weak.cfg").read_text()) == "huawei_vrp"
    assert detect_platform("hello world") is None


def test_reports_render():
    r = audit("fortigate_weak.conf", "fortigate")
    html = to_html(r)
    assert "ConfigSentry" in html and "FGT-013" in html
    assert '"score"' in to_json(r)


def test_empty_config_rejected():
    with pytest.raises(ValueError):
        run_audit("   ", "cisco_ios")


def test_bpduguard_skips_port_channels_and_members():
    text = """hostname SW1
interface Port-channel25
 switchport mode access
interface TenGigabitEthernet1/0/1
 switchport mode access
 channel-group 25 mode active
interface GigabitEthernet1/0/5
 description PC-ROOM-101
 switchport mode access
"""
    r = run_audit(text, "cisco_ios")
    bpdu = next(x for x in r.results if x.id == "IOS-026")
    assert bpdu.status == FAIL
    joined = "\n".join(bpdu.evidence)
    assert "GigabitEthernet1/0/5" in joined and "PC-ROOM-101" in joined
    assert "Port-channel25" not in joined and "TenGigabitEthernet1/0/1" not in joined


# --------------------------------------------------------------------------- #
# Huawei VRP
# --------------------------------------------------------------------------- #
def test_huawei_weak_config_fails_expected_rules():
    s = status_map(audit("huawei_weak.cfg", "huawei_vrp"))
    for rid in ["VRP-001", "VRP-003", "VRP-005", "VRP-008", "VRP-013", "VRP-014",
                "VRP-016", "VRP-019", "VRP-020", "VRP-021", "VRP-025", "VRP-027"]:
        assert s[rid] == FAIL, rid


def test_huawei_hardened_config_has_no_findings():
    r = audit("huawei_hardened.cfg", "huawei_vrp")
    assert [f.id for f in r.failed] == []
    assert r.hostname == "LAB-HW-ACCESS-02"


def test_huawei_banner_text_is_ignored():
    r = audit("huawei_weak.cfg", "huawei_vrp")
    clear = next(x for x in r.results if x.id == "VRP-013")
    assert len(clear.evidence) == 1 and "guest" in clear.evidence[0]


def test_huawei_bpdu_skips_eth_trunk_members():
    r = audit("huawei_weak.cfg", "huawei_vrp")
    bpdu = "\n".join(next(x for x in r.results if x.id == "VRP-025").evidence)
    assert "GigabitEthernet0/0/24" not in bpdu and "Eth-Trunk1" not in bpdu
    assert "GigabitEthernet0/0/3" not in bpdu  # shutdown port


@pytest.mark.parametrize(
    "line, secret",
    [
        ("local-user admin password irreversible-cipher $1a$abc$xyz", "$1a$abc$xyz"),
        ("local-user t password simple Huawei@123", "Huawei@123"),
        ("snmp-agent community read cipher %^%#XYZ%^%# acl 2001", "%^%#XYZ%^%#"),
        ("  authentication-mode hmac-sha256 1 cipher OSPFKEY", "OSPFKEY"),
    ],
)
def test_huawei_secrets_are_masked(line, secret):
    assert secret not in mask_line(line)


def test_ssh_algorithm_lines_are_not_masked():
    line = "ssh server hmac sha2_256 md5 sha1_96"
    assert mask_line(line) == line


# --------------------------------------------------------------------------- #
# All platforms: weak samples fail, hardened samples pass, detection works
# --------------------------------------------------------------------------- #
from configsentry.parsers import read_upload  # noqa: E402

SAMPLE_SETS = {
    "cisco_ios": ("cisco_weak.txt", "cisco_hardened.txt"),
    "cisco_nxos": ("nxos_weak.txt", "nxos_hardened.txt"),
    "huawei_vrp": ("huawei_weak.cfg", "huawei_hardened.cfg"),
    "junos": ("junos_weak.conf", "junos_hardened.set"),
    "mikrotik": ("mikrotik_weak.rsc", "mikrotik_hardened.rsc"),
    "cisco_asa": ("asa_weak.txt", "asa_hardened.txt"),
    "fortigate": ("fortigate_weak.conf", "fortigate_hardened.conf"),
    "paloalto": ("paloalto_weak.xml", "paloalto_hardened.set"),
    "checkpoint_gaia": ("checkpoint_weak.txt", "checkpoint_hardened.txt"),
    "sophos": ("sophos_weak.xml", "sophos_hardened.xml"),
}


def _load(name):
    path = SAMPLES / name
    return read_upload(name, path.read_bytes())


def test_every_platform_has_samples():
    assert set(SAMPLE_SETS) == set(PLATFORMS)


@pytest.mark.parametrize("platform", list(SAMPLE_SETS))
def test_hardened_sample_is_clean(platform):
    r = run_audit(_load(SAMPLE_SETS[platform][1]), platform)
    assert [f.id for f in r.failed] == []
    assert r.hostname


@pytest.mark.parametrize("platform", list(SAMPLE_SETS))
def test_weak_sample_has_high_findings(platform):
    r = run_audit(_load(SAMPLE_SETS[platform][0]), platform)
    assert r.count("high") >= 2
    assert r.score < 30


@pytest.mark.parametrize("platform", list(SAMPLE_SETS))
def test_detection(platform):
    for name in SAMPLE_SETS[platform]:
        assert detect_platform(_load(name)) == platform, name


def test_junos_braces_and_set_formats_agree():
    braces = """system { services { telnet; ssh { root-login allow; } } }"""
    set_fmt = "set system services telnet\nset system services ssh root-login allow\n"
    a = status_map(run_audit(braces, "junos"))
    b = status_map(run_audit(set_fmt, "junos"))
    assert a["JUN-001"] == b["JUN-001"] == FAIL
    assert a["JUN-004"] == b["JUN-004"] == FAIL


def test_junos_inactive_statements_are_ignored():
    r = run_audit("system { services { inactive: telnet; } }", "junos")
    assert status_map(r)["JUN-001"] == PASS


def test_paloalto_xml_and_set_formats_agree():
    xml = _load("paloalto_weak.xml")
    s = status_map(run_audit(xml, "paloalto"))
    assert s["PAN-001"] == FAIL and s["PAN-015"] == FAIL and s["PAN-017"] == FAIL
    set_fmt = 'set rulebase security rules "Any" source any\nset rulebase security rules "Any" action allow\n'
    assert status_map(run_audit(set_fmt, "paloalto"))["PAN-015"] == FAIL


def test_mikrotik_defaults_apply_when_not_exported():
    r = run_audit("/system identity\nset name=R1\n", "mikrotik")
    s = status_map(r)
    assert s["MTK-001"] == FAIL  # telnet/ftp/www/api enabled by default
    assert s["MTK-011"] == NA     # SNMP off by default


def test_mikrotik_line_continuation():
    from configsentry.parsers import MikrotikConfig
    cfg = MikrotikConfig("/ip service\nset ssh \\\n    address=192.0.2.0/24\n")
    assert cfg.lines == [(2, "/ip service set ssh address=192.0.2.0/24")]


def test_sophos_tar_upload():
    import io
    import tarfile
    data = (SAMPLES / "sophos_weak.xml").read_bytes()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("API/Entities.xml")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    text = read_upload("backup.tar", buf.getvalue())
    assert detect_platform(text) == "sophos"


def test_asa_line_value_default_applies():
    s = status_map(run_audit("hostname FW\nASA Version 9.18\n", "cisco_asa"))
    assert s["ASA-008"] == FAIL  # default minimum length 3
    assert s["ASA-012"] == FAIL  # console timeout 0 by default


@pytest.mark.parametrize(
    "text",
    [
        "Password complexity is not enabled.",
        "line 13: set password-controls min-password-length 6",
        "line 61: SNMP community uses a default name",
    ],
)
def test_prose_and_settings_are_not_masked(text):
    assert mask_line(text) == text


@pytest.mark.parametrize(
    "line, secret",
    [
        ("set mgt-config users admin phash $5$abc", "$5$abc"),
        ("set user admin password-hash $1$xyz", "$1$xyz"),
        ("snmp-community-string Publ1cX", "Publ1cX"),
        ("/user add name=x password=Secr3t group=full", "Secr3t"),
        ("set security ike policy p pre-shared-key ascii-text \"$9$abc\"", "$9$abc"),
        ("Configuration/AdminSettings/Password = abc123", "abc123"),
        ("username admin password 0 Cl3arText role network-admin", "Cl3arText"),
    ],
)
def test_new_platform_secrets_are_masked(line, secret):
    assert secret not in mask_line(line)


# --------------------------------------------------------------------------- #
# Local web server
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402
import threading as _threading  # noqa: E402
import urllib.error as _uerr  # noqa: E402
import urllib.request as _ureq  # noqa: E402


@pytest.fixture(scope="module")
def server_url():
    from configsentry.server import make_server
    httpd = make_server(0)
    t = _threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://localhost:{httpd.server_address[1]}"
    httpd.shutdown()


def _post(url, body: bytes):
    req = _ureq.Request(url, data=body, method="POST")
    with _ureq.urlopen(req) as r:
        return r.status, r.headers, r.read()


def test_server_serves_app_and_meta(server_url):
    with _ureq.urlopen(server_url + "/") as r:
        assert b"ConfigSentry" in r.read()
        assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    with _ureq.urlopen(server_url + "/api/meta") as r:
        meta = _json.loads(r.read())
    assert len(meta["platforms"]) == len(PLATFORMS)


def test_server_auto_detects_and_audits(server_url):
    body = (SAMPLES / "fortigate_weak.conf").read_bytes()
    _, _, data = _post(server_url + "/api/audit?platform=auto&name=fgt.conf", body)
    data = _json.loads(data)
    assert data["status"] == "ok"
    assert data["result"]["platform_key"] == "fortigate"
    body = (SAMPLES / "cisco_weak.txt").read_bytes()
    _, _, data = _post(server_url + "/api/audit?platform=auto&name=c.txt", body)
    row = [r for r in _json.loads(data)["result"]["results"] if r["id"] == "IOS-003"][0]
    assert any("094F471A1A0A" in e for e in row["evidence"])
    assert not any("094F471A1A0A" in e for e in row["evidence_masked"])


def test_server_reports_mismatch_then_forces(server_url):
    body = (SAMPLES / "fortigate_weak.conf").read_bytes()
    _, _, data = _post(server_url + "/api/audit?platform=checkpoint_gaia&name=x.conf", body)
    assert _json.loads(data) == {"status": "mismatch", "detected": "fortigate", "selected": "checkpoint_gaia"}
    _, _, data = _post(server_url + "/api/audit?platform=checkpoint_gaia&name=x.conf&force=1", body)
    assert _json.loads(data)["result"]["platform_key"] == "checkpoint_gaia"


def test_server_report_download_is_masked(server_url):
    body = (SAMPLES / "cisco_weak.txt").read_bytes()
    status, headers, data = _post(server_url + "/api/report?platform=cisco_ios&name=c.txt&format=html&mask=1", body)
    assert status == 200 and "attachment" in headers["Content-Disposition"]
    assert b"094F471A1A0A" not in data and b"LAB-ACCESS-SW01" in data


def test_server_rejects_foreign_host(server_url):
    req = _ureq.Request(server_url + "/api/meta", headers={"Host": "evil.example"})
    with pytest.raises(_uerr.HTTPError) as exc:
        _ureq.urlopen(req)
    assert exc.value.code == 403


def test_server_blocks_path_traversal(server_url):
    with pytest.raises(_uerr.HTTPError) as exc:
        _ureq.urlopen(server_url + "/../engine.py")
    assert exc.value.code == 404
