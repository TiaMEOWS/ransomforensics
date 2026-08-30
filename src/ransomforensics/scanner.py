"""Directory scanner: triage a whole tree of possibly-encrypted files.

This is the headless engine behind both the TUI console and the `scan` CLI
command. It walks a directory tree, runs every candidate file through the
family detectors (tail-only reads for speed), and aggregates an incident
summary.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .detector import analyze_file
from .models import Analysis

#: files above this size get a tail-only read (footer parsing needs the last
#: 534 bytes; reading a 200 GB VHDX fully would be pointless)
TAIL_READ_THRESHOLD = 4 * 1024 * 1024

#: files smaller than the smallest known footer can't match anything
MIN_CANDIDATE_SIZE = 512


@dataclass
class IncidentStats:
    """Aggregated picture of one scan."""

    files_seen: int = 0
    files_matched: int = 0
    files_unmatched: int = 0
    files_skipped: int = 0
    bytes_read: int = 0
    by_family: dict = field(default_factory=dict)          # family -> file count
    recoverable_by_family: dict = field(default_factory=dict)  # family -> bytes
    total_original_bytes: int = 0
    total_recoverable_bytes: int = 0

    @property
    def recoverable_ratio(self) -> float:
        if not self.total_original_bytes:
            return 0.0
        return self.total_recoverable_bytes / self.total_original_bytes

    def add(self, analysis: Analysis) -> None:
        self.files_matched += 1
        fam = analysis.family or "unknown"
        self.by_family[fam] = self.by_family.get(fam, 0) + 1
        if analysis.original_size:
            self.total_original_bytes += analysis.original_size
        rec = analysis.recoverable_without_key_bytes
        if rec:
            self.total_recoverable_bytes += rec
            self.recoverable_by_family[fam] = (
                self.recoverable_by_family.get(fam, 0) + rec
            )


@dataclass
class ScanResult:
    root: Path
    analyses: list = field(default_factory=list)   # list[Analysis], matched only
    stats: IncidentStats = field(default_factory=IncidentStats)
    errors: list = field(default_factory=list)     # (path, reason)

    @property
    def recoverable_files(self) -> list:
        return [a for a in self.analyses if a.recoverable_without_key_bytes > 0]


def iter_candidate_files(root: Path):
    """Yield files worth analyzing, largest-family footers first is not
    possible pre-parse, so just yield in deterministic walk order."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def scan_directory(
    root: Path | str,
    on_progress: Callable[[str, IncidentStats], None] | None = None,
) -> ScanResult:
    """Analyze every candidate file under `root`.

    `on_progress(path, stats)` fires periodically so UIs can render live
    progress without waiting for the whole tree.
    """
    root = Path(root)
    result = ScanResult(root=root)
    stats = result.stats

    for path in iter_candidate_files(root):
        try:
            size = path.stat().st_size
        except OSError as exc:
            stats.files_skipped += 1
            result.errors.append((str(path), f"stat failed: {exc}"))
            continue

        stats.files_seen += 1
        if size < MIN_CANDIDATE_SIZE:
            stats.files_skipped += 1
            continue

        tail_only = size > TAIL_READ_THRESHOLD
        try:
            if tail_only:
                stats.bytes_read += min(size, 65536)
            else:
                stats.bytes_read += size
            analysis = analyze_file(path, tail_only=tail_only)
        except OSError as exc:
            stats.files_skipped += 1
            result.errors.append((str(path), f"read failed: {exc}"))
            continue

        if analysis is None:
            stats.files_unmatched += 1
        else:
            result.analyses.append(analysis)
            stats.add(analysis)

        if on_progress and stats.files_seen % 10 == 0:
            on_progress(str(path), stats)

    return result
