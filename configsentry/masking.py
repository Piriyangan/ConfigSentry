"""Hide secrets (passwords, keys, communities) in evidence lines and reports."""

import re

MASK = "****"
_KEYWORDS = r"(?:irreversible-cipher|cipher|simple|ascii-text|hexadecimal)"
# Do not mask a type digit or keyword that is followed by an already-masked
# secret (avoids regex backtracking onto the digit).
_SKIP = rf"(?!\*{{4}}|{_KEYWORDS}\b|\d{{1,2}}\s+(?:{_KEYWORDS}\b|\*{{4}}))"
# Normal words that follow "password" / "community" in messages and settings,
# so they are not mistaken for secrets.
_WORDS = (
    r"(?!(?:is|are|was|still|uses|use|allows|allow|check|complexity|policy|policies|strength-check|"
    r"controls|encryption|history|expiration|reuse|for|of|has|have|a|an|the|name|names|string|"
    r"strings|without|with|in|on|not|to|and|or|setting|settings|list|lists|type|hash|hashes|"
    r"format|length|entry|entries)\b)"
)

# Lines that contain algorithm names, not secrets (e.g. "ssh server hmac md5").
_NO_SECRET_RX = re.compile(r"(^|:\s)ssh (server|client) (cipher|hmac|key-exchange|publickey)\b", re.I)

# key=value formats (MikroTik) and "Tag = value" lines (Sophos XML).
_KV_RX = re.compile(
    r"\b([\w-]*(?:password|passwd|secret|passphrase|pre-shared-key|psk|auth-key|private-key)=)(\"[^\"]*\"|\S+)", re.I
)
_XML_RX = re.compile(r"(/[\w-]*(?:Password|Secret|PSK|Passphrase|Key))( = )(.+)$", re.I)

# Applied in order (Cisco, Huawei, Junos, PAN-OS, Gaia style lines).
_RULES = [
    # PAN-OS / Gaia hashes and community strings
    re.compile(r"\b(phash|password-hash|expert-password-hash|community-string|snmp-community-string)(\s+)(\S+)", re.I),
    # Huawei: "... cipher <secret>", "password irreversible-cipher <hash>", "password simple <pw>"
    re.compile(rf"\b({_KEYWORDS})(\s+)(\S+)", re.I),
    # Huawei plain community: "snmp-agent community read public"
    re.compile(r"\b(community\s+(?:read|write))(\s+)(?!cipher\b)(\S+)", re.I),
    re.compile(rf"\b(md5|sha|sha1|sha256|sha512)((?:\s+\d{{1,2}})?\s+){_SKIP}(\S+)", re.I),
    re.compile(r"\b(priv\s+(?:aes|des|3des)(?:\s+\d{3})?)(\s+)(\S+)", re.I),
    re.compile(rf"\b(password|secret|key-string|key)((?:\s+\d{{1,2}})?\s+){_SKIP}{_WORDS}(\S+)", re.I),
    re.compile(rf"\b(community)(\s+)(?!(?:read|write)\b){_WORDS}(\S+)", re.I),
]

# FortiGate: the setting name must END with a secret word (e.g. "password",
# "psksecret"); settings like "password-controls" or "min-password-length" are
# not secrets.
_FORTI_RX = re.compile(
    r"\b(set\s+(?:[\w-]*-)?(?:password|passwd|psksecret|secret|private-key|key|auth-pwd|priv-pwd))\s+(.+)$",
    re.I,
)


def mask_line(text: str) -> str:
    if _NO_SECRET_RX.search(text):
        return text
    if _XML_RX.search(text):
        return _XML_RX.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    text = _KV_RX.sub(lambda m: f"{m.group(1)}{MASK}", text)
    if _FORTI_RX.search(text):
        return _FORTI_RX.sub(lambda m: f"{m.group(1)} {MASK}", text)
    for rx in _RULES:
        text = rx.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    return text


def mask_config(text: str) -> str:
    """Mask every secret in a whole configuration."""
    return "\n".join(mask_line(line) for line in text.splitlines())
