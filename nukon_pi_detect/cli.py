"""
Command-line entry point.

Usage:
  nukon-pi-detect scan --file input.txt
  nukon-pi-detect scan --string "ignore previous instructions"
  nukon-pi-detect scan --file input.txt --report out.html
  nukon-pi-detect scan --file input.txt --json
  nukon-pi-detect list-patterns
  nukon-pi-detect version

Exit codes:
  0   CLEAN
  1   SUSPICIOUS
  2   MALICIOUS
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .detector import DECISION_MALICIOUS, DECISION_SUSPICIOUS, scan
from .patterns import ALL_PATTERNS, UNICODE_SMUGGLING, count_by_category
from .report import render_html


_EXIT = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.file and args.string:
        print("error: pass exactly one of --file or --string", file=sys.stderr)
        return 64
    if not args.file and not args.string:
        print("error: one of --file or --string is required", file=sys.stderr)
        return 64

    if args.file:
        source_label = args.file
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
            return 64
    else:
        source_label = "<string>"
        text = args.string

    result = scan(text)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_human(result, source_label)

    if args.report:
        html_out = render_html(result, source_label=source_label)
        Path(args.report).write_text(html_out, encoding="utf-8")
        if not args.json:
            print(f"\nHTML report written to: {args.report}")

    return _EXIT[result.decision]


def _print_human(result, source_label: str) -> None:
    bar = "─" * 60
    print(bar)
    print(f"nukon-pi-detect · {source_label}")
    print(bar)
    print(f"Decision : {result.decision}")
    print(f"Score    : {result.score:.3f}")
    print(f"Elapsed  : {result.elapsed_ms:.2f} ms")
    print(f"Hits     : {len(result.hits)} across {len(result.categories_hit)} categor"
          f"{'y' if len(result.categories_hit) == 1 else 'ies'}")
    print(bar)
    if not result.hits:
        print("No patterns matched.")
        return
    for h in result.hits:
        print(f"  [{h.id}] {h.category:9s} {h.name}")
        print(f"         confidence={h.confidence:.2f}  @{h.start}-{h.end}")
        print(f"         match: {h.snippet}")
        print(f"         fix:   {h.mitigation}")


def _cmd_list_patterns(args: argparse.Namespace) -> int:
    counts = count_by_category()
    total = sum(counts.values())
    print(f"nukon-pi-detect · {total} patterns across {len(counts)} categories")
    print()
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:11s}  {n}")
    print()
    if args.verbose:
        for p in ALL_PATTERNS:
            print(f"  [{p.id}] {p.category:9s} conf={p.confidence:.2f}  {p.name}")
        for pid, info in UNICODE_SMUGGLING.items():
            print(f"  [{pid}] unicode   conf={info['confidence']:.2f}  {info['name']}")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"nukon-pi-detect {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nukon-pi-detect",
        description="Scan strings/files for prompt-injection patterns. "
                    "Deterministic, offline, CI-friendly.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a file or string")
    src = s.add_mutually_exclusive_group()
    src.add_argument("--file", "-f", help="Path to a text file")
    src.add_argument("--string", "-s", help="Raw string to scan")
    s.add_argument("--report", "-r", help="Write HTML report to this path")
    s.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    s.set_defaults(func=_cmd_scan)

    lp = sub.add_parser("list-patterns", help="List loaded detection patterns")
    lp.add_argument("--verbose", "-v", action="store_true", help="Show every pattern")
    lp.set_defaults(func=_cmd_list_patterns)

    v = sub.add_parser("version", help="Print version")
    v.set_defaults(func=_cmd_version)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
