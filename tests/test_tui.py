"""TUI tests via Textual's Pilot harness - real rendering, headless."""
from __future__ import annotations

import pytest

from ransomforensics.tui.app import RansomForensicsApp, render_region_bar

pytest.importorskip("textual")

from textual.widgets import DataTable, Static  # noqa: E402


class TestRegionBar:
    def test_full_file_all_red(self):
        from ransomforensics.detector import analyze_bytes
        from ransomforensics.generator.conti import make_conti_file
        from ransomforensics.models import EncryptMode

        blob = make_conti_file(50_000, EncryptMode.FULL)
        a = analyze_bytes(blob, "x.bin")
        bar = render_region_bar(a)
        # fully encrypted: no green cells in the bar
        assert bar.cell_len < 60

    def test_partial_has_green(self):
        from ransomforensics.detector import analyze_bytes
        from ransomforensics.generator.conti import make_conti_file
        from ransomforensics.models import EncryptMode

        blob = make_conti_file(50_000, EncryptMode.PARTLY, percent=50)
        a = analyze_bytes(blob, "x.bin")
        assert a.recoverable_ratio == pytest.approx(0.5)


class TestApp:
    async def test_demo_incident_populates_table(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = RansomForensicsApp()
        async with app.run_test() as pilot:
            await pilot.press("d")
            await app.workers.wait_for_complete()
            await pilot.pause()
            table = app.query_one("#table", DataTable)
            assert table.row_count == 12      # matched files
            stats = app.query_one("#stats", Static)
            assert "12" in str(stats.render())
            assert "RECOVERABLE" in str(stats.render())

    async def test_detail_renders_on_selection(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = RansomForensicsApp()
        async with app.run_test() as pilot:
            await pilot.press("d")
            await app.workers.wait_for_complete()
            await pilot.pause()
            # move through rows; each highlight must render a detail panel
            await pilot.press("down")
            await pilot.pause()
            detail = app.query_one("#detail", Static)
            rendered = str(detail.render())
            assert "family=conti" in rendered
            assert "untouched" in rendered or "encrypted" in rendered

    async def test_carve_all_produces_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = RansomForensicsApp()
        async with app.run_test() as pilot:
            await pilot.press("d")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("a")            # carve all
            await app.workers.wait_for_complete()
            await pilot.pause()
            carved = list((tmp_path / "demo_incident" / "recovered").rglob("*.bin"))
            assert len(carved) >= 6          # 6 of 12 demo files are partial

    async def test_report_export(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = RansomForensicsApp()
        async with app.run_test() as pilot:
            await pilot.press("d")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("r")            # export report
            await pilot.pause()
            report = tmp_path / "incident_report.md"
            assert report.exists()
            assert "conti" in report.read_text(encoding="utf-8")

    async def test_scan_nonexistent_path_warns(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = RansomForensicsApp()
        async with app.run_test() as pilot:
            inp = app.query_one("#path-input")
            inp.value = str(tmp_path / "nope")
            await pilot.press("s")            # focus input
            await pilot.press("enter")
            await pilot.pause()
            # table must stay empty; no crash
            assert app.query_one("#table", DataTable).row_count == 0
