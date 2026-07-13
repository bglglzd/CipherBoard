#!/usr/bin/env python3
"""Fail-closed Kotlin format regression gate for every fork-owned change."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


MAX_LINE = 140
KOTLIN_PATHSPEC = ("*.kt", "*.kts")


def git(root: pathlib.Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", "-c", "core.quotepath=false", *arguments],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
    )
    if process.returncode != 0:
        raise OSError("cannot inspect Kotlin changes with Git")
    return process.stdout


def upstream_commit(root: pathlib.Path) -> str:
    upstream = (root / "UPSTREAM.md").read_text(encoding="utf-8")
    match = re.search(r"^- Commit: `([0-9a-f]{40})`$", upstream, re.MULTILINE)
    if not match:
        raise OSError("cannot determine pinned upstream commit")
    return match.group(1)


def changed_files(root: pathlib.Path, upstream: str) -> list[pathlib.Path]:
    tracked = git(
        root,
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        upstream,
        "--",
        *KOTLIN_PATHSPEC,
    ).splitlines()
    untracked = git(
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        *KOTLIN_PATHSPEC,
    ).splitlines()
    return sorted({root / name for name in tracked + untracked})


def tracked_added_lines(root: pathlib.Path, upstream: str) -> list[tuple[str, int, str]]:
    diff = git(
        root,
        "diff",
        "--unified=0",
        "--no-color",
        upstream,
        "--",
        *KOTLIN_PATHSPEC,
    )
    result: list[tuple[str, int, str]] = []
    relative = ""
    line_number = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            relative = line[6:]
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            if not match:
                raise OSError("cannot parse Kotlin diff hunk")
            line_number = int(match.group(1)) - 1
        elif line.startswith("+") and not line.startswith("+++"):
            line_number += 1
            result.append((relative, line_number, line[1:]))
        elif not line.startswith("-"):
            line_number += 1
    return result


def check_line(relative: str, number: int, line: str, errors: list[str]) -> None:
    if line.endswith((" ", "\t")):
        errors.append(f"{relative}:{number}: trailing whitespace")
    if "\t" in line:
        errors.append(f"{relative}:{number}: tab indentation")
    if len(line) > MAX_LINE:
        errors.append(f"{relative}:{number}: line exceeds {MAX_LINE} characters")


def check(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    upstream = upstream_commit(root)
    files = changed_files(root, upstream)
    untracked = {
        root / name
        for name in git(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            *KOTLIN_PATHSPEC,
        ).splitlines()
    }
    for path in files:
        data = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        if data and not data.endswith(b"\n"):
            errors.append(f"{relative}: missing final newline")
        text = data.decode("utf-8")
        if path in untracked:
            for number, line in enumerate(text.splitlines(), 1):
                check_line(relative, number, line, errors)
    for relative, number, line in tracked_added_lines(root, upstream):
        check_line(relative, number, line, errors)
    return errors


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
    try:
        errors = check(root)
    except (OSError, UnicodeDecodeError) as error:
        print(f"Kotlin style check failed: {error.__class__.__name__}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"Kotlin style failure: {error}", file=sys.stderr)
        return 1
    print("CipherBoard Kotlin format regression check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
