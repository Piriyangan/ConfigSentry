"""Command-line interface.

Examples
--------
  python -m configsentry ui
  python -m configsentry audit -f samples/cisco_weak.txt -o report.html
  python -m configsentry audit --folder ./backups --out-dir ./reports
  python -m configsentry rules -p huawei_vrp --markdown
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

from . import __version__
from .engine import PLATFORMS, SEVERITY_ORDER, load_rules, run_audit
from .parsers import detect_platform, read_upload
from .report import to_html, to_json, to_text

CONFIG_SUFFIXES = {"", ".txt", ".cfg", ".conf", ".config", ".log", ".bak", ".set", ".rsc", ".xml",
                   ".tar", ".tgz", ".gz", ".zip"}


def _resolve_platform(requested: str, text: str, name: str) -> str:
    if requested != "auto":
        return requested
    detected = detect_platform(text)
    if not detected:
        choices = ", ".join(PLATFORMS)
        raise ValueError(f"{name}: could not detect the platform. Use -p with one of: {choices}.")
    return detected


def _write(result, out: Path, fmt: str, mask: bool) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    data = to_json(result) if fmt == "json" else to_html(result, masked=mask)
    out.write_text(data, encoding="utf-8")


def _fails_threshold(result, fail_on: str | None) -> bool:
    if not fail_on:
        return False
    limit = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] <= limit for f in result.failed)


def cmd_audit(args) -> int:
    mask = not args.no_mask
    fmt = args.format

    # ---- folder mode -------------------------------------------------- #
    if args.folder:
        folder = Path(args.folder)
        files = sorted(
            p for p in folder.rglob("*")
            if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in CONFIG_SUFFIXES
        )
        if not files:
            print(f"No config files found in {folder}", file=sys.stderr)
            return 2
        out_dir = Path(args.out_dir or "reports")
        rows, exit_code = [], 0
        for path in files:
            text = read_upload(path.name, path.read_bytes())
            try:
                platform = _resolve_platform(args.platform, text, path.name)
                result = run_audit(text, platform, source=str(path), mask=mask)
            except ValueError as exc:
                print(f"SKIP  {exc}", file=sys.stderr)
                continue
            report = out_dir / f"{path.stem}.{'json' if fmt == 'json' else 'html'}"
            _write(result, report, fmt, mask)
            rows.append([path.name, platform, result.hostname or "", result.score, result.grade,
                         result.count("high"), result.count("medium"), result.count("low"), str(report)])
            print(f"{result.score:>3}/100  {result.grade}  H:{result.count('high'):<2} M:{result.count('medium'):<2} "
                  f"L:{result.count('low'):<2} {path.name}")
            if _fails_threshold(result, args.fail_on):
                exit_code = 1
        summary = out_dir / "summary.csv"
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(summary, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["file", "platform", "hostname", "score", "grade", "high", "medium", "low", "report"])
            w.writerows(rows)
        print(f"\n{len(rows)} device(s) audited. Reports in {out_dir}/ (summary: {summary})")
        return exit_code

    # ---- single file -------------------------------------------------- #
    if not args.file:
        print("Give a config with -f FILE or --folder DIR.", file=sys.stderr)
        return 2
    text = read_upload(args.file, Path(args.file).read_bytes())
    try:
        platform = _resolve_platform(args.platform, text, args.file)
        result = run_audit(text, platform, source=args.file, mask=mask)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(to_text(result, color=sys.stdout.isatty()))
    if args.out:
        _write(result, Path(args.out), fmt, mask)
        print(f"\nReport saved to {args.out}")
    return 1 if _fails_threshold(result, args.fail_on) else 0


def cmd_rules(args) -> int:
    platforms = PLATFORMS if args.platform == "all" else {args.platform: PLATFORMS[args.platform]}
    for key, info in platforms.items():
        rules = load_rules(key)
        if args.markdown:
            print(f"## {info['name']} ({len(rules)} rules)\n")
            print(f"Input: `{info['command']}`\n")
            print("| ID | Severity | Category | Check | References |")
            print("|---|---|---|---|---|")
            for r in rules:
                refs = ", ".join(r.get("references", []))
                print(f"| {r['id']} | {r['severity'].title()} | {r['category']} | {r['title']} | {refs} |")
            print()
        else:
            print(f"{info['name']} - {len(rules)} rules")
            for r in rules:
                print(f"  {r['id']:<9} {r['severity']:<7} {r['title']}")
    return 0


def cmd_ui(args) -> int:
    from .server import serve

    serve(open_browser=not args.no_browser, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="configsentry", description="Security audit for network device configurations.")
    p.add_argument("--version", action="version", version=f"ConfigSentry {__version__}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="Audit a config file or a folder of config files")
    a.add_argument("-p", "--platform", choices=list(PLATFORMS) + ["auto"], default="auto",
                   help="Platform (default: auto-detect)")
    src = a.add_mutually_exclusive_group()
    src.add_argument("-f", "--file", help="Config file to audit")
    src.add_argument("--folder", help="Audit every config file in a folder (e.g. Oxidized backups)")
    a.add_argument("-o", "--out", help="Save the report to this file")
    a.add_argument("--out-dir", help="Folder for reports in --folder mode (default: reports)")
    a.add_argument("--format", choices=["html", "json"], default="html")
    a.add_argument("--no-mask", action="store_true", help="Do not mask secrets in the report")
    a.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="Exit with code 1 if findings at this severity or higher exist (for CI pipelines)")
    a.set_defaults(func=cmd_audit)

    r = sub.add_parser("rules", help="List the rules for a platform")
    r.add_argument("-p", "--platform", choices=list(PLATFORMS) + ["all"], default="all")
    r.add_argument("--markdown", action="store_true", help="Print as a Markdown table")
    r.set_defaults(func=cmd_rules)

    u = sub.add_parser("ui", help="Start the web app in your browser")
    u.add_argument("--port", type=int, help="Port to use (default: first free port from 8501)")
    u.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    u.set_defaults(func=cmd_ui)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
