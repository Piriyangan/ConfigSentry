# Contributing to ConfigSentry

Thank you for helping improve ConfigSentry. New rules, bug reports and new platforms are all welcome.

## Ground rules

- **Never submit real configurations.** Use fake hostnames and documentation IP ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and fake hashes.
- Every new rule needs a test: the weak sample should fail it and the hardened sample should pass it.
- Keep descriptions short and in plain English, and give remediation commands that work on the platform.

## Set up

```bash
pip install -r requirements.txt
python -m pytest
```

## Adding a rule

Rules live in `configsentry/rules/<platform>.yaml`. Every rule needs these fields:

| Field | Meaning |
|---|---|
| `id` | Unique ID, e.g. `IOS-029`, `NXOS-018`, `PAN-019` |
| `title` | Short name of the issue |
| `severity` | `high`, `medium`, `low` or `info` |
| `category` | Group, e.g. `Management Access`, `SNMP`, `Logging` |
| `type` | How the rule is evaluated (see below) |
| `description` | Why it matters |
| `remediation` | Commands to fix it |
| `references` | Optional list, e.g. `[CIS Cisco IOS 1.2 Access Rules, NIST 800-53 AC-17]` |

### Rule types

**`line_present`**: fails if no line matches the pattern (Cisco and Huawei).

```yaml
- id: IOS-099
  title: No archive logging of config changes
  severity: low
  category: Logging
  type: line_present
  pattern: '^archive$'
  missing_message: No 'archive' section found.
  description: Config change logging helps you see who changed what.
  remediation: |
    archive
     log config
      logging enable
```

**`line_absent`**: fails if any line matches the pattern. Add `scope: all` to also search indented lines.

**`block`**: checks child lines of every block whose parent matches. Use `require`, `forbid`, or both.

```yaml
  type: block
  parent: '^line vty\b'
  forbid: '^transport input (.*\btelnet\b|all)'
```

**`fgt_setting`**: FortiGate setting in a section. Always give the FortiOS `default`, because `show`
hides default values. Conditions: `fail_values`, `fail_if_contains`, `fail_if_greater`, `fail_if_less`.

```yaml
  type: fgt_setting
  section: system global
  settings:
    - key: admintimeout
      default: 5
      fail_if_greater: 15
```

**`line_value`**: compares a number or word captured by `pattern` (group 1). Give the
platform `default` used when the setting is not shown, and `fail_if_greater`, `fail_if_less` or
`fail_values`.

```yaml
  type: line_value
  pattern: '^ssh timeout (\d+)'
  default: 5
  fail_if_greater: 15
```

Flat formats (Junos and PAN-OS `set` lines, Check Point Gaia, MikroTik, Sophos) are searched
line by line, so use `line_present`, `line_absent`, `line_value` or `python` rules there.

**`python`**: for logic that is too complex for the types above. Write a function in
`configsentry/checks.py` that returns `(status, evidence_list)`, register it in `CUSTOM_CHECKS`,
and reference it with `function: <name>`.

Optional for Cisco and Huawei rules: `applies_if` / `skip_if` (a pattern searched in all lines) to mark a rule as not applicable.

After adding rules, regenerate the rule list:

```bash
python -m configsentry rules --markdown
```

and paste the output into `docs/RULES.md` below the header.

## Adding a platform

1. Add a parser class in `configsentry/parsers.py` and register it in `PARSERS`.
2. Add the platform to `PLATFORMS` in `configsentry/engine.py` (name, rule file, show command).
3. Create `configsentry/rules/<platform>.yaml`.
4. Add weak and hardened samples in `samples/` and tests in `tests/`.

## Pull requests

- One topic per pull request.
- Run `python -m pytest` before you open it.
- Describe what the rule detects and link the vendor or benchmark guidance you used.
