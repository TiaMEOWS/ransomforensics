"""Family detection: run every registered parser, first match wins."""
from __future__ import annotations

from pathlib import Path

from .models import Analysis
from .parsers.base import FamilyParser
from .parsers.conti import ContiParser


def registered_parsers() -> list[FamilyParser]:
    """Every family parser shipped with the framework.

    New families: implement FamilyParser, append here, done.
    """
    return [
        ContiParser(),
    ]


def analyze_file(path: Path | str) -> Analysis | None:
    path = Path(path)
    data = path.read_bytes()
    return analyze_bytes(data, path)


def analyze_bytes(data: bytes, path: Path | str = "<bytes>") -> Analysis | None:
    for parser in registered_parsers():
        result = parser.parse(data, path)
        if result is not None:
            return result
    return None
