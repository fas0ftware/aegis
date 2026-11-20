"""aegis [check] [--json] [--only ID,...] [--save] | aegis explain ID | aegis report FILE.html | aegis list"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, checks, report
from .probe import Probe

STATUS_FILE = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "aegis/status.json"


def _probe(args):
    if args.demo:
        from . import demo
        return demo.probe()
    return Probe()


COMMANDS = ("check", "explain", "report", "list")


def _default_command(argv: list[str]) -> list[str]:
    """`aegis --save` means `aegis check --save`: put "check" after the global options."""
    i = 0
    while i < len(argv) and argv[i] == "--demo":
        i += 1
    if i < len(argv) and (argv[i] in COMMANDS or argv[i] in ("-h", "--help", "--version")):
        return argv
    return argv[:i] + ["check"] + argv[i:]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aegis", description="Read-only security check for a Linux laptop.")
    ap.add_argument("--version", action="version", version=f"aegis {__version__}")
    ap.add_argument("--demo", action="store_true", help="check a made-up laptop instead of this one")
    sub = ap.add_subparsers(dest="cmd")
    ck = sub.add_parser("check", help="run the checks (the default)")
    ck.add_argument("--json", action="store_true", help="print JSON")
    ck.add_argument("--only", help="comma-separated check ids")
    ck.add_argument("--save", action="store_true", help=f"also write {STATUS_FILE} for dashboards")
    ck.add_argument("--no-fixes", action="store_true", help="leave out the fix steps")
    ck.add_argument("--strict", action="store_true", help="exit 1 when a check fails (for scripts)")
    ex = sub.add_parser("explain", help="why a check matters and how to fix it")
    ex.add_argument("id")
    rp = sub.add_parser("report", help="write the results as one HTML page")
    rp.add_argument("file", type=Path)
    sub.add_parser("list", help="list the checks")
    args = ap.parse_args(_default_command(list(sys.argv[1:] if argv is None else argv)))
    cmd = args.cmd or "check"

    if cmd == "list":
        for id_, title, severity, _, _ in checks.CHECKS:
            print(f"{id_:<18} {severity:<7} {title}")
        return 0

    ids = {c[0] for c in checks.CHECKS}
    only = None
    if cmd == "check" and getattr(args, "only", None):
        only = {x.strip() for x in args.only.split(",") if x.strip()}
    if cmd == "explain":
        only = {args.id}
    unknown = (only or set()) - ids
    if unknown:
        print(f"aegis: unknown check(s): {', '.join(sorted(unknown))} (see: aegis list)", file=sys.stderr)
        return 2

    results = checks.run_all(_probe(args), only)

    if cmd == "explain":
        sys.stdout.write(report.explain(results[0]))
        return 0
    if cmd == "report":
        args.file.write_text(report.to_html(results, "Aegis report (demo)" if args.demo else "Aegis report"))
        print(f"wrote {args.file} (score {checks.score(results)})")
        return 0
    if getattr(args, "save", False) and not args.demo:
        report.write_status(results, STATUS_FILE)
    if getattr(args, "json", False):
        print(json.dumps(report.to_json(results), indent=2))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        sys.stdout.write(report.text(results, color=color, fixes=not getattr(args, "no_fixes", False)))
    if getattr(args, "strict", False) and any(r.status == "fail" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
