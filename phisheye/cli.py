"""Command-line entrypoint: `phisheye`."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .analyzer import analyze
from .models import Analysis, Verdict

_EXIT = {Verdict.SAFE.value: 0, Verdict.SUSPICIOUS.value: 1, Verdict.PHISHING.value: 2}


def _render(a: Analysis) -> str:
    lines = [
        "",
        f"{a.emoji}  {a.verdict.value}  —  risk score {a.score}/100",
        f"URL:    {a.url}",
        f"Domain: {a.registrable_domain or a.host or '(none)'}",
        "",
    ]
    if a.signals:
        lines.append("Risk signals:")
        for s in a.signals:
            lines.append(f"  • [{s.severity:>2}] {s.title}")
            lines.append(f"         {s.detail}")
    else:
        lines.append("No risk signals detected.")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="phisheye",
        description="Score a URL for phishing risk — offline, heuristic, zero-dependency.",
    )
    p.add_argument("url", nargs="?", help="URL to analyze")
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.add_argument("--batch", action="store_true",
                   help="Read URLs from stdin (one per line) — for SOC pipelines")
    args = p.parse_args(argv)

    if args.batch:
        results = [analyze(line) for line in sys.stdin if line.strip()]
        if args.json:
            print(json.dumps([a.to_dict() for a in results], indent=2, ensure_ascii=False))
        else:
            for a in results:
                print(f"{a.emoji} {a.score:>3}/100  {a.verdict.value:<16}  {a.url}")
        return 2 if any(a.verdict is Verdict.PHISHING for a in results) else 0

    if not args.url:
        p.error("provide a URL, or use --batch to read from stdin")

    a = analyze(args.url)
    print(json.dumps(a.to_dict(), indent=2, ensure_ascii=False) if args.json else _render(a))
    return _EXIT[a.verdict.value]


if __name__ == "__main__":
    sys.exit(main())
