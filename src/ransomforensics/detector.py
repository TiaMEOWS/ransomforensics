"""Family detection: run every registered parser, first match wins."""
from __future__ import annotations

from pathlib import Path

from .models import Analysis
from .parsers.base import FamilyParser
from .parsers.conti import ContiParser

#: how much of a big file to read when only the footer is needed
TAIL_READ_BYTES = 65536


def registered_parsers() -> list[FamilyParser]:
    """Every family parser shipped with the framework.

    New families: implement FamilyParser, append here, done.
    """
    return [
        ContiParser(),
    ]


def analyze_file(path: Path | str, tail_only: bool = False) -> Analysis | None:
    """Analyze one file on disk.

    `tail_only` reads just the last 64 KiB and validates against the real
    file size - the right mode when walking a victim disk full of huge
    VHDX/backup files where only the footer matters.
    """
    path = Path(path)
    size = path.stat().st_size
    if tail_only and size > TAIL_READ_BYTES:
        with path.open("rb") as fh:
            fh.seek(-TAIL_READ_BYTES, 2)
            data = fh.read(TAIL_READ_BYTES)
        return analyze_bytes(data, path, file_size=size)
    return analyze_bytes(path.read_bytes(), path)


def analyze_bytes(
    data: bytes, path: Path | str = "<bytes>", file_size: int | None = None
) -> Analysis | None:
    for parser in registered_parsers():
        result = parser.parse(data, path, file_size=file_size)
        if result is not None:
            return result
    return None
