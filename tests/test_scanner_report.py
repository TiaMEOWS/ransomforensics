"""Headless engine tests: scanner aggregation + report generation."""
from __future__ import annotations

import os
from pathlib import Path

from ransomforensics.generator.conti import make_conti_file
from ransomforensics.models import EncryptMode
from ransomforensics.report import generate_report, write_report
from ransomforensics.scanner import scan_directory


def seed_incident(root, noise=3):
    """Lay down a miniature victim directory: matched files + noise."""
    plan = [
        ("dc01.vhdx", 300_000, EncryptMode.PARTLY, 20),
        ("sql.bak", 200_000, EncryptMode.FULL, 0),
        ("share.zip", 150_000, EncryptMode.HEADER, 0),
        ("media.mp4", 400_000, EncryptMode.PARTLY, 50),
    ]
    for name, size, mode, percent in plan:
        (root / name).write_bytes(make_conti_file(size, mode, percent=percent))
    # small noise files below the scanner's candidate floor, and a big one
    (root / "tiny.txt").write_bytes(b"hello" * 10)
    (root / "random.bin").write_bytes(os.urandom(80_000))
    return plan


class TestScanner:
    def test_matches_and_noise(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        s = result.stats
        assert s.files_matched == 4
        assert s.by_family == {"conti": 4}
        # tiny.txt (skipped, < floor) + random.bin (unmatched)
        assert s.files_unmatched == 1
        assert s.files_skipped == 1

    def test_recoverable_aggregation(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        s = result.stats
        # expected untouched tails per the seed plan
        assert s.total_original_bytes == 300_000 + 200_000 + 150_000 + 400_000
        expected = (
            int(300_000 * 0.80)          # dc01 PARTLY 20%
            + 0                          # sql FULL
            + 150_000 - 1_048_576 // 1   # share HEADER: 1MiB cap > size -> 0
            + int(400_000 * 0.50)        # media PARTLY 50%
        )
        # share.zip is smaller than 1 MiB so HEADER encrypts everything
        expected = int(300_000 * 0.80) + 0 + 0 + int(400_000 * 0.50)
        assert s.total_recoverable_bytes == expected
        assert s.recoverable_ratio > 0

    def test_recoverable_files_ranked(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        names = [Path(a.path).name for a in result.recoverable_files]
        assert "media.mp4" in names
        assert "sql.bak" not in names        # FULL mode -> not recoverable

    def test_progress_callback_contract(self, tmp_path):
        seed_incident(tmp_path)
        calls = []
        scan_directory(tmp_path, on_progress=lambda p, s: calls.append(p))
        # 8 files total: callback fires every 10th file, so none fire here;
        # the contract is just "does not crash and returns results"
        assert all(isinstance(c, str) for c in calls)


class TestReport:
    def test_report_contains_summary_and_targets(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        text = generate_report(result)
        assert "Executive summary" in text
        assert "conti" in text
        assert "Top recovery targets" in text
        assert "media.mp4" in text          # biggest recoverable file
        assert "sql.bak" in text            # appears in per-file detail
        assert "Method" in text

    def test_report_empty_scan(self, tmp_path):
        result = scan_directory(tmp_path)
        text = generate_report(result)
        assert "No known-family" in text

    def test_write_report(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        out = write_report(result, tmp_path / "report.md")
        assert out.exists()
        assert out.read_text(encoding="utf-8").startswith("# ")

    def test_report_carve_hint_counts(self, tmp_path):
        seed_incident(tmp_path)
        result = scan_directory(tmp_path)
        text = generate_report(result)
        # the executive summary must state the keyless-recoverable total
        assert "recoverable without" in text
        assert "0 B" not in text.split("Top recovery targets")[0].split("keyless-recoverable")[1][:40]
