"""ransomforensics TUI - an incident-response triage console.

Run it with `ransomforensics-tui` (or `python -m ransomforensics tui`).
Press D to generate a synthetic demo incident and triage it - no real
malware, no real victims, just the format doing its thing.
"""
from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from ..detector import analyze_file
from ..generator.conti import make_conti_file
from ..models import Analysis, EncryptMode
from ..recovery import carve
from ..report import write_report
from ..scanner import scan_directory

#: how wide the region-map bar renders
REGION_BAR_WIDTH = 56


def _human(n: int) -> str:
    x = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if x < 1024 or unit == "TiB":
            return f"{x:,.1f} {unit}" if unit != "B" else f"{int(x):,} B"
        x /= 1024
    return f"{x:,.1f} TiB"


def _pct(ratio: float) -> str:
    return f"{ratio * 100:.1f}%"


def render_region_bar(analysis: Analysis, width: int = REGION_BAR_WIDTH) -> str:
    """One-line visual of the file: red = encrypted, green = untouched,
    grey = footer."""
    from rich.text import Text

    total = analysis.original_size or 1
    enc_end = analysis.encrypted[0].end if analysis.encrypted else 0
    footer_len = 534

    enc_chars = round(enc_end / total * width)
    footer_chars = max(1, round(footer_len / total * width)) if total > footer_len else 1
    plain_chars = max(0, width - enc_chars - footer_chars)
    if enc_chars + plain_chars + footer_chars != width:  # absorb rounding
        plain_chars = width - enc_chars - footer_chars
        if plain_chars < 0:
            enc_chars, plain_chars = width - footer_chars, 0

    bar = Text()
    bar.append("█" * enc_chars, style="bold on red")
    bar.append("█" * plain_chars, style="bold on green")
    bar.append("▓" * footer_chars, style="on grey37")
    return bar


class RansomForensicsApp(App):
    """Ransomware encrypted-file triage console."""

    TITLE = "ransomforensics"
    SUB_TITLE = "encrypted-file triage console"

    #: focus the table on startup so single-key bindings fire immediately
    #: instead of being swallowed by the path input
    AUTO_FOCUS = "#table"

    CSS = """
    #sidebar {
        width: 36;
        min-width: 36;
        border-right: solid $primary;
        padding: 1 1;
    }
    #sidebar Label { margin: 1 0 0 0; }
    #stats {
        border: round $primary;
        padding: 1 1;
        margin: 1 0;
        height: auto;
    }
    #path-input { margin: 0 0 1 0; }
    Button { width: 100%; margin: 0 0 1 0; }
    #detail {
        height: 12;
        min-height: 12;
        border: round $primary;
        padding: 1 1;
    }
    #table { height: 1fr; }
    .dim { color: $text-muted; }
    """

    BINDINGS = [
        Binding("s", "focus_path", "Path", show=True),
        Binding("d", "demo", "Demo incident", show=True),
        Binding("c", "carve_selected", "Carve file", show=True),
        Binding("a", "carve_all", "Carve all", show=True),
        Binding("r", "export_report", "Report", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._analyses: dict[str, Analysis] = {}
        self._current_root: Path | None = None

    # ------------------------------------------------------------------ UI

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("Scan target", classes="dim")
                yield Input(
                    placeholder="directory path, then Enter",
                    id="path-input",
                )
                yield Button("Scan directory", id="scan", variant="primary")
                yield Button("Generate demo incident", id="demo", variant="warning")
                yield Label("Incident summary", classes="dim")
                yield Static("no scan yet", id="stats")
                yield Label("Recovery", classes="dim")
                yield Button("Carve selected file", id="carve-one", variant="success")
                yield Button("Carve all recoverable", id="carve-all", variant="success")
                yield Button("Export markdown report", id="report", variant="default")
            with Vertical():
                yield DataTable(id="table")
                yield Static(
                    "select a row to inspect its region map",
                    id="detail",
                )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_column("file", key="file", width=34)
        table.add_column("family", key="family", width=8)
        table.add_column("mode", key="mode", width=12)
        table.add_column("original", key="orig", width=11)
        table.add_column("recoverable", key="rec", width=11)
        table.add_column("ratio", key="ratio", width=7)
        table.cursor_type = "row"

    # --------------------------------------------------------------- events

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "path-input":
            self._start_scan(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id
        if button == "scan":
            self._start_scan(self.query_one("#path-input", Input).value.strip())
        elif button == "demo":
            self.action_demo()
        elif button == "carve-one":
            self.action_carve_selected()
        elif button == "carve-all":
            self.action_carve_all()
        elif button == "report":
            self.action_export_report()

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        analysis = self._analyses.get(event.row_key.value)
        if analysis:
            self._render_detail(analysis)

    # -------------------------------------------------------------- actions

    def action_focus_path(self) -> None:
        self.query_one("#path-input", Input).focus()

    def action_demo(self) -> None:
        """Generate a synthetic incident (safe fixtures) and triage it."""
        root = Path.cwd() / "demo_incident"
        root.mkdir(exist_ok=True)
        import os
        import struct

        rng = __import__("random").Random(1337)
        plan = [
            ("vm-dc01.vhdx", 2_400_000, EncryptMode.PARTLY, 20),
            ("vm-sql01.vhdx", 3_100_000, EncryptMode.PARTLY, 25),
            ("backup-full.bak", 1_800_000, EncryptMode.FULL, 0),
            ("hr-db.mdf", 900_000, EncryptMode.FULL, 0),
            ("sharepoint.wim", 1_500_000, EncryptMode.PARTLY, 50),
            ("exchange.edb", 2_200_000, EncryptMode.PARTLY, 30),
            ("fileshare.zip", 700_000, EncryptMode.HEADER, 0),
            ("contracts.7z", 640_000, EncryptMode.HEADER, 0),
            ("ledger.xlsx", 420_000, EncryptMode.FULL, 0),
            ("plans.dwg", 380_000, EncryptMode.PARTLY, 40),
            ("media-archive.mp4", 4_000_000, EncryptMode.PARTLY, 15),
            ("sql-dump.sql", 520_000, EncryptMode.FULL, 0),
        ]
        for name, size, mode, percent in plan:
            (root / name).write_bytes(
                make_conti_file(size, mode, percent=percent)
            )
        # noise: files with no known footer, the way a real disk looks
        for name, size in [
            ("readme.txt", 4096),
            ("wallpaper.png", 300_000),
            ("unrelated.dll", 620_000),
        ]:
            (root / name).write_bytes(os.urandom(size))

        self.notify(f"demo incident generated at {root}", title="demo")
        self._start_scan(str(root))

    def _start_scan(self, raw: str) -> None:
        if not raw:
            self.notify("enter a directory path first", severity="warning")
            return
        root = Path(raw).expanduser()
        if not root.is_dir():
            self.notify(f"not a directory: {root}", severity="error")
            return
        self.query_one("#table", DataTable).clear()
        self._analyses.clear()
        self._render_stats_placeholder(f"scanning {root} ...")
        self.run_scan(root)

    @work(thread=True, exclusive=True)
    def run_scan(self, root: Path) -> None:
        def progress(path: str, stats) -> None:
            self.call_from_thread(
                self._render_stats_placeholder,
                f"scanning... {stats.files_seen} files, "
                f"{stats.files_matched} matched",
            )

        result = scan_directory(root, on_progress=progress)
        self.call_from_thread(self._apply_results, result)

    def _apply_results(self, result) -> None:
        self._current_root = result.root
        table = self.query_one("#table", DataTable)
        table.clear()
        self._analyses.clear()
        for a in result.analyses:
            mode_label = {
                EncryptMode.FULL: "FULL",
                EncryptMode.PARTLY: f"PARTLY {a.footer.data_percent}%",
                EncryptMode.HEADER: "HEADER",
            }.get(a.mode, a.mode.name if a.mode else "?")
            row_key = str(a.path)
            table.add_row(
                Path(a.path).name,
                a.family,
                mode_label,
                _human(a.original_size),
                _human(a.recoverable_without_key_bytes),
                _pct(a.recoverable_ratio),
                key=row_key,
            )
            self._analyses[row_key] = a

        stats = result.stats
        summary = []
        if stats.files_matched:
            summary.append(
                f"[b]{stats.files_matched}[/b]/{stats.files_seen} files matched"
            )
            for fam, count in sorted(stats.by_family.items()):
                summary.append(f"  {fam}: {count}")
            summary.append(
                f"original data: [b]{_human(stats.total_original_bytes)}[/b]"
            )
            summary.append(
                f"RECOVERABLE: [b green]{_human(stats.total_recoverable_bytes)}"
                f" ({_pct(stats.recoverable_ratio)})[/b green] without keys"
            )
        else:
            summary.append(f"{stats.files_seen} files scanned, no known footers")
        self.query_one("#stats", Static).update("\n".join(summary))

        if result.analyses:
            table.move_cursor(row=0, column=0)
            first = self._analyses.get(str(result.analyses[0].path))
            if first:
                self._render_detail(first)
        self.notify(
            f"scan complete: {stats.files_matched} matched, "
            f"{_human(stats.total_recoverable_bytes)} recoverable",
            title="scan",
        )

    def _render_stats_placeholder(self, text: str) -> None:
        self.query_one("#stats", Static).update(text)

    def _render_detail(self, a: Analysis) -> None:
        from rich.text import Text

        detail = self.query_one("#detail", Static)
        block = Text()
        block.append(f"{Path(a.path).name}\n", style="bold white")
        block.append(
            f"family={a.family}  mode={a.mode.name if a.mode else '?'}  "
            f"original={_human(a.original_size)}  "
            f"recoverable={_human(a.recoverable_without_key_bytes)} "
            f"({_pct(a.recoverable_ratio)})\n"
        )
        if a.encrypted:
            enc = a.encrypted[0]
            block.append(
                f"encrypted [0, {enc.end:,}) {enc.cipher}, "
                f"key wrapped by {enc.key_wrapped_by}\n",
                style="red",
            )
        for region in a.plaintext:
            block.append(
                f"untouched [{region.start:,}, {region.end:,}) "
                f"{_human(region.length)}\n",
                style="green",
            )
        block.append("\n")
        block.append(render_region_bar(a))
        block.append("\n")
        block.append("red = encrypted  ", style="red")
        block.append("green = untouched (carvable)  ", style="green")
        block.append("grey = footer", style="grey37")
        detail.update(block)

    def _selected(self) -> Analysis | None:
        table = self.query_one("#table", DataTable)
        try:
            row_key = table.coordinate_to_cell_key(
                table.cursor_coordinate
            ).row_key
        except Exception:
            return None
        return self._analyses.get(row_key.value or "")

    def action_carve_selected(self) -> None:
        analysis = self._selected()
        if analysis is None:
            self.notify("select a file in the table first", severity="warning")
            return
        self.run_carve([analysis])

    def action_carve_all(self) -> None:
        targets = [
            a for a in self._analyses.values()
            if a.recoverable_without_key_bytes > 0
        ]
        if not targets:
            self.notify("nothing recoverable in current results", severity="warning")
            return
        self.run_carve(targets)

    @work(thread=True, exclusive=True)
    def run_carve(self, targets: list) -> None:
        out_root = (self._current_root or Path.cwd()) / "recovered"
        total = 0
        for a in targets:
            path = Path(a.path)
            data = path.read_bytes()
            outs = carve(a, data, out_root / path.stem[:40])
            total += sum(o.bytes_written for o in outs)
        self.call_from_thread(
            self.notify,
            f"carved {_human(total)} from {len(targets)} file(s) into "
            f"{out_root}",
            title="carve",
        )

    def action_export_report(self) -> None:
        if self._current_root is None or not self._analyses:
            self.notify("run a scan first", severity="warning")
            return

        # rebuild a ScanResult from the live table state (cheap; analysis
        # objects already carry everything)
        from ..scanner import IncidentStats, ScanResult

        result = ScanResult(root=self._current_root)
        for a in self._analyses.values():
            result.analyses.append(a)
            result.stats.add(a)
        result.stats.files_seen = result.stats.files_matched

        out = Path.cwd() / "incident_report.md"
        write_report(result, out)
        self.notify(f"report written to {out}", title="report")


def main() -> None:
    RansomForensicsApp().run()


if __name__ == "__main__":
    main()
