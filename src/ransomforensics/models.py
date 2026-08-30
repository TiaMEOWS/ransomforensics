"""Core data models for ransomware encrypted-file forensics."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class EncryptMode(IntEnum):
    """Conti-family per-file encryption modes (locker.cpp enum ENCRYPT_MODES)."""

    FULL = 0x24
    PARTLY = 0x25
    HEADER = 0x26

    @property
    def label(self) -> str:
        return {
            EncryptMode.FULL: "full",
            EncryptMode.PARTLY: "partial (percent-based)",
            EncryptMode.HEADER: "header-only (first 1 MiB)",
        }[self]


@dataclass
class ByteRegion:
    """A half-open byte range [start, end) inside the original file."""

    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class EncryptedRegion(ByteRegion):
    cipher: str = "unknown"
    key_wrapped_by: str = "unknown"


@dataclass
class FileFooter:
    """Family-specific trailing metadata attached to an encrypted file."""

    family: str
    raw: bytes
    offset: int
    mode: int | None = None
    data_percent: int | None = None
    original_size: int | None = None
    notes: dict = field(default_factory=dict)


@dataclass
class Analysis:
    """Complete forensic picture of one encrypted file."""

    path: Path
    family: str | None = None
    detected_by: str | None = None
    original_size: int | None = None
    mode: EncryptMode | None = None
    footer: FileFooter | None = None
    encrypted: list[EncryptedRegion] = field(default_factory=list)
    plaintext: list[ByteRegion] = field(default_factory=list)
    key_blob: dict = field(default_factory=dict)

    @property
    def recoverable_without_key_bytes(self) -> int:
        return sum(r.length for r in self.plaintext)

    @property
    def recoverable_ratio(self) -> float:
        if not self.original_size:
            return 0.0
        return self.recoverable_without_key_bytes / self.original_size
