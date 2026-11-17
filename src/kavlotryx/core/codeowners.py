"""GitHub CODEOWNERS parsing and matching (FR-EN-03).

The last matching line wins, as on GitHub. Patterns use gitignore rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pathspec


@dataclass(frozen=True)
class CodeownersLine:
    lineno: int
    pattern: str
    owners: tuple[str, ...]


@dataclass(frozen=True)
class CodeownersMatch:
    line: CodeownersLine
    path: str


def parse(text: str) -> list[CodeownersLine]:
    lines: list[CodeownersLine] = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("\\#") else raw.strip()
        if not line:
            continue
        parts = line.split()
        lines.append(CodeownersLine(lineno=n, pattern=parts[0], owners=tuple(parts[1:])))
    return lines


@lru_cache(maxsize=1024)
def _spec(pattern: str) -> pathspec.PathSpec:
    try:
        return pathspec.PathSpec.from_lines("gitignore", [pattern])  # pathspec >= 1.0
    except (KeyError, LookupError):
        return pathspec.PathSpec.from_lines("gitwildmatch", [pattern])


def match(lines: list[CodeownersLine], path: str) -> CodeownersMatch | None:
    path = path.lstrip("/")
    found: CodeownersMatch | None = None
    for line in lines:
        if _spec(line.pattern).match_file(path):
            found = CodeownersMatch(line=line, path=path)
    return found


def load_file(path: Path) -> list[CodeownersLine]:
    return parse(path.read_text(encoding="utf-8"))
