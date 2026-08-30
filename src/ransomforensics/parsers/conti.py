"""Conti locker v2 on-disk format parser.

Layout (derived from the leaked locker source, locker.cpp):

    [ original file data, partially or fully overwritten with ciphertext ]
    [ 524-byte RSA-wrapped key blob: 40B ChaCha20 key+IV, RSA-2048 OAEP ]   <- footer part 1
    [ 10-byte trailer: mode(1) | data_percent(1) | original_size(8 LE) ]   <- footer part 2

Modes (locker.cpp enum ENCRYPT_MODES):
    0x24 FULL    entire file encrypted
    0x25 PARTLY  first `data_percent`% of the file encrypted
    0x26 HEADER  first 1 MiB encrypted

The footer is always the last 534 bytes of the file. The RSA blob is
worthless without the operator's private key, but the 10-byte trailer tells
us exactly which byte ranges were never touched - those are recoverable
without any key.
"""
from __future__ import annotations

import struct

from ..models import (
    Analysis,
    ByteRegion,
    EncryptedRegion,
    EncryptMode,
    FileFooter,
)
from .base import FamilyParser

FOOTER_LEN = 534          # 524-byte key blob + 10-byte trailer
TRAILER_LEN = 10
KEY_BLOB_LEN = 524
HEADER_ENCRYPT_BYTES = 1_048_576  # EncryptHeader hardcodes 1 MiB


class ContiParser(FamilyParser):
    FAMILY = "conti"

    def parse(self, data: bytes, path) -> Analysis | None:
        if len(data) < FOOTER_LEN:
            return None

        trailer = data[-TRAILER_LEN:]
        mode_raw, percent, original_size = struct.unpack("<BBQ", trailer)

        try:
            mode = EncryptMode(mode_raw)
        except ValueError:
            return None

        # Sanity gates: percent is only meaningful for PARTLY, and the
        # declared original size must match the observed file length.
        if mode is EncryptMode.PARTLY and not (0 < percent <= 100):
            return None
        expected = original_size + FOOTER_LEN
        if expected != len(data):
            return None

        key_blob = data[-FOOTER_LEN:-TRAILER_LEN]
        enc_end = self._encrypted_length(mode, percent, original_size)
        enc_end = min(enc_end, original_size)

        analysis = Analysis(
            path=path,
            family=self.FAMILY,
            detected_by="10-byte footer trailer (mode|percent|size)",
            original_size=original_size,
            mode=mode,
            footer=FileFooter(
                family=self.FAMILY,
                raw=data[-FOOTER_LEN:],
                offset=len(data) - FOOTER_LEN,
                mode=mode_raw,
                data_percent=percent,
                original_size=original_size,
            ),
            encrypted=[
                EncryptedRegion(
                    start=0, end=enc_end, cipher="ChaCha20",
                    key_wrapped_by="RSA-2048 (per-build embedded public key)",
                )
            ],
            key_blob={
                "offset": len(data) - FOOTER_LEN,
                "length": KEY_BLOB_LEN,
                "wrapped": "ChaCha20 key(32B) || IV(8B), RSA-encrypted",
            },
        )
        if enc_end < original_size:
            analysis.plaintext.append(
                ByteRegion(start=enc_end, end=original_size)
            )
        return analysis

    @staticmethod
    def _encrypted_length(mode: EncryptMode, percent: int, size: int) -> int:
        if mode is EncryptMode.FULL:
            return size
        if mode is EncryptMode.HEADER:
            return min(HEADER_ENCRYPT_BYTES, size)
        # PARTLY: EncryptPartly reads the first `percent`% of the file
        return size * percent // 100
