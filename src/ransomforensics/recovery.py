"""Keyless recovery: carve the regions an encryptor never touched."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import Analysis


@dataclass
class CarveResult:
    out_path: Path
    bytes_written: int
    regions: int


def plan(analysis: Analysis) -> list[tuple[int, int]]:
    """Return the plaintext regions worth carving, largest first."""
    return sorted(
        ((r.start, r.end) for r in analysis.plaintext if r.length > 0),
        key=lambda s: s[1] - s[0],
        reverse=True,
    )


def carve(
    analysis: Analysis,
    source: bytes,
    out_dir: Path,
    stem: str | None = None,
) -> list[CarveResult]:
    """Write each recoverable region to `out_dir` as a separate file.

    For files with a single dominant plaintext tail this effectively
    reconstructs everything except the encrypted head - a 5 GB PARTLY(50%)
    VM disk yields 2.5 GB back with no key.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    base = stem or Path(analysis.path).stem
    results = []
    for i, (start, end) in enumerate(plan(analysis)):
        chunk = source[start:end]
        out_path = out_dir / f"{base}.recovered.{i:02d}.bin"
        out_path.write_bytes(chunk)
        results.append(CarveResult(out_path, len(chunk), 1))
    return results
