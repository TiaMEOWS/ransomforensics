"""Round-trip tests: generate -> parse -> carve, all on synthetic data."""
from __future__ import annotations

import pytest

from ransomforensics.detector import analyze_bytes
from ransomforensics.generator.conti import make_conti_file
from ransomforensics.models import EncryptMode
from ransomforensics.recovery import carve, plan

MARKER = b"\xAA"


def _fixture(size, mode, percent=0):
    return make_conti_file(size, mode, percent=percent, marker=MARKER)


class TestParse:
    def test_full_mode_detected(self):
        blob = _fixture(100_000, EncryptMode.FULL)
        a = analyze_bytes(blob, "test.bin")
        assert a is not None
        assert a.family == "conti"
        assert a.mode is EncryptMode.FULL
        assert a.original_size == 100_000
        assert a.recoverable_without_key_bytes == 0

    def test_partly_mode_tail_recoverable(self):
        blob = _fixture(10_000_000, EncryptMode.PARTLY, percent=25)
        a = analyze_bytes(blob, "test.bin")
        assert a.mode is EncryptMode.PARTLY
        assert a.footer.data_percent == 25
        # 25% head encrypted, 75% tail untouched
        assert a.encrypted[0].end == 10_000_000 * 25 // 100
        assert a.recoverable_without_key_bytes == 7_500_000
        assert a.recoverable_ratio == pytest.approx(0.75)

    def test_header_mode_1mib_encrypted(self):
        blob = _fixture(3_000_000, EncryptMode.HEADER)
        a = analyze_bytes(blob, "test.bin")
        assert a.mode is EncryptMode.HEADER
        assert a.encrypted[0].end == 1_048_576
        assert a.recoverable_without_key_bytes == 3_000_000 - 1_048_576

    def test_header_mode_small_file_becomes_full(self):
        # 500 KiB file: min(1 MiB, size) == size -> nothing recoverable
        blob = _fixture(500_000, EncryptMode.HEADER)
        a = analyze_bytes(blob, "test.bin")
        assert a.recoverable_without_key_bytes == 0

    def test_rejects_random_data(self):
        import os

        assert analyze_bytes(os.urandom(8_192), "rand.bin") is None

    def test_rejects_truncated_footer(self):
        blob = _fixture(100_000, EncryptMode.FULL)
        assert analyze_bytes(blob[:-100], "cut.bin") is None

    def test_rejects_wrong_declared_size(self):
        blob = bytearray(_fixture(100_000, EncryptMode.FULL))
        blob[-1] ^= 0xFF  # corrupt the size field
        assert analyze_bytes(bytes(blob), "bad.bin") is None

    def test_rejects_bad_percent(self):
        import struct

        blob = bytearray(_fixture(100_000, EncryptMode.FULL))
        blob[-10] = 0x25  # PARTLY
        blob[-9] = 0      # percent 0 -> invalid
        assert analyze_bytes(bytes(blob), "bad.bin") is None


class TestCarve:
    def test_carve_returns_marker_bytes(self, tmp_path):
        blob = _fixture(10_000, EncryptMode.PARTLY, percent=40)
        a = analyze_bytes(blob, "victim.doc")
        assert a is not None
        regions = plan(a)
        assert len(regions) == 1
        start, end = regions[0]
        assert start == 4_000
        outs = carve(a, blob, tmp_path)
        assert len(outs) == 1
        data = outs[0].out_path.read_bytes()
        assert len(data) == 6_000
        assert data == MARKER * 6_000  # exactly the untouched tail

    def test_full_mode_carves_nothing(self, tmp_path):
        blob = _fixture(10_000, EncryptMode.FULL)
        a = analyze_bytes(blob, "victim.doc")
        assert plan(a) == []
        assert carve(a, blob, tmp_path) == []


class TestGenerator:
    def test_size_matches(self):
        for mode in EncryptMode:
            blob = _fixture(50_000, mode, percent=50)
            assert len(blob) == 50_000 + 534

    def test_rejects_tiny_size(self):
        with pytest.raises(ValueError):
            make_conti_file(100, EncryptMode.FULL)
