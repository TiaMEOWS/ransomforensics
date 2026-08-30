"""Synthetic Conti-format encrypted file generator.

Produces fixture files with the *exact* on-disk structure of a Conti-locked
file without containing any real ciphertext, key, or malware: the "key blob"
is random filler and the payload is a deterministic marker pattern. This is
what lets the test suite (and users) validate parsers with zero exposure.
"""
from __future__ import annotations

import os
import struct

from ..models import EncryptMode

FOOTER_LEN = 534
TRAILER_LEN = 10
HEADER_ENCRYPT_BYTES = 1_048_576


def make_conti_file(
    size: int,
    mode: EncryptMode,
    percent: int = 0,
    marker: bytes = b"\xAA",
) -> bytes:
    """Return bytes shaped like a Conti-encrypted file of `size` bytes.

    Plaintext (untouched) regions carry the `marker` byte so recovery
    tests can assert exactly what was carved out.
    """
    if size <= FOOTER_LEN:
        raise ValueError("size must exceed the 534-byte footer")

    enc_len = size
    if mode is EncryptMode.HEADER:
        enc_len = min(HEADER_ENCRYPT_BYTES, size)
    elif mode is EncryptMode.PARTLY:
        if not (0 < percent <= 100):
            raise ValueError("percent must be 1..100 for PARTLY")
        enc_len = size * percent // 100

    data = bytearray(os.urandom(enc_len))          # stand-in ciphertext
    data.extend(marker * (size - enc_len))          # untouched plaintext
    data.extend(os.urandom(FOOTER_LEN - TRAILER_LEN))  # fake RSA key blob
    trailer = struct.pack("<BBQ", int(mode), percent, size)
    data.extend(trailer)
    return bytes(data)
