#!/usr/bin/env python3
"""Find common hard-coded credentials in tracked repository files."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_FILE_SIZE = 1_048_576


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "assigned-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*"
            r"['\"][^'\"\n]{8,}['\"]"
        ),
    ),
)


def _tracked_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"{root} is not a readable Git repository") from exc

    names = result.stdout.decode("utf-8").split("\0")
    return [root / name for name in names if name]


def scan_repo(root: Path) -> list[Finding]:
    """Scan tracked, reasonably sized text files under *root*."""
    root = root.resolve()
    findings: list[Finding] = []
    for path in _tracked_files(root):
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            data = path.read_bytes()
        except (OSError, UnicodeError):
            continue
        if b"\0" in data:
            continue

        text = data.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, pattern in RULES:
                if pattern.search(line) and not _looks_like_placeholder(line):
                    findings.append(
                        Finding(str(path.relative_to(root)), line_number, rule)
                    )
                    break
    return findings


def _looks_like_placeholder(line: str) -> bool:
    """Avoid flagging common documentation examples and empty settings."""
    lowered = line.lower()
    return any(
        marker in lowered
        for marker in ("your_", "your-", "replace_me", "changeme", "example", "dummy")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan tracked text files for common hard-coded credentials."
    )
    parser.add_argument("path", nargs="?", default=".", help="Git repository to scan")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args(argv)

    try:
        findings = scan_repo(Path(args.path))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    elif findings:
        for item in findings:
            print(f"{item.path}:{item.line}: {item.rule}")
    else:
        print("No credential patterns found in tracked text files.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
