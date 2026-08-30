"""CLI entry point.

    python -m ransomforensics analyze FILE [FILE...]
    python -m ransomforensics carve FILE --out DIR
    python -m ransomforensics gen --family conti --size N --mode partly --percent 25 --out FILE
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detector import analyze_file
from .generator.conti import make_conti_file
from .models import EncryptMode


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} GiB"


def cmd_analyze(args) -> int:
    rc = 0
    for target in args.files:
        result = analyze_file(target)
        if result is None:
            print(f"{target}: no known family footer matched")
            rc = 1
            continue
        print(f"{target}")
        print(f"  family        : {result.family}  ({result.detected_by})")
        print(f"  original size : {_human(result.original_size)}")
        print(f"  mode          : {result.mode.name} ({result.mode.label})")
        if result.mode is EncryptMode.PARTLY and result.footer:
            print(f"  data percent  : {result.footer.data_percent}%")
        print(f"  encrypted     : {_human(sum(r.length for r in result.encrypted))}")
        rec = result.recoverable_without_key_bytes
        print(f"  RECOVERABLE   : {_human(rec)} ({result.recoverable_ratio:.1%}) without any key")
        for region in result.plaintext:
            print(f"    - bytes [{region.start:#x}, {region.end:#x})")
    return rc


def cmd_carve(args) -> int:
    from .recovery import carve

    result = analyze_file(args.file)
    if result is None:
        print(f"{args.file}: no known family footer matched", file=sys.stderr)
        return 1
    data = Path(args.file).read_bytes()
    outputs = carve(result, data, Path(args.out))
    if not outputs:
        print("nothing recoverable: file was fully encrypted")
        return 0
    total = 0
    for out in outputs:
        print(f"  wrote {out.out_path} ({_human(out.bytes_written)})")
        total += out.bytes_written
    print(f"recovered {_human(total)} across {len(outputs)} region(s)")
    return 0


def cmd_gen(args) -> int:
    mode = EncryptMode[args.mode.upper()]
    blob = make_conti_file(args.size, mode, percent=args.percent)
    Path(args.out).write_bytes(blob)
    print(f"wrote {args.out} ({_human(len(blob))}, mode={mode.name})")
    return 0


def cmd_scan(args) -> int:
    from .report import write_report
    from .scanner import scan_directory

    result = scan_directory(args.directory)
    s = result.stats
    print(f"scanned {s.files_seen:,} files under {result.root}")
    print(f"  matched   : {s.files_matched:,}")
    print(f"  unmatched : {s.files_unmatched:,}")
    print(f"  skipped   : {s.files_skipped:,}")
    for fam, count in sorted(s.by_family.items()):
        rec = s.recoverable_by_family.get(fam, 0)
        print(f"  {fam:<10}: {count:,} files, {_human(rec)} recoverable")
    print(
        f"TOTAL keyless-recoverable: {_human(s.total_recoverable_bytes)} "
        f"of {_human(s.total_original_bytes)} ({s.recoverable_ratio:.1%})"
    )
    if args.report:
        out = write_report(result, args.report)
        print(f"report written to {out}")
    if args.carve:
        from .recovery import carve

        out_dir = Path(args.carve)
        for a in result.recoverable_files:
            carve(a, Path(a.path).read_bytes(), out_dir / Path(a.path).stem[:40])
        print(f"carved {len(result.recoverable_files)} files into {out_dir}")
    return 0


def cmd_tui(args) -> int:
    try:
        from .tui.app import RansomForensicsApp
    except ImportError:
        print(
            "TUI needs the textual extra:  pip install '.[tui]'",
            file=sys.stderr,
        )
        return 2
    RansomForensicsApp().run()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ransomforensics")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="identify family + map recoverable regions")
    p_an.add_argument("files", nargs="+")
    p_an.set_defaults(func=cmd_analyze)

    p_cv = sub.add_parser("carve", help="extract keyless-recoverable regions to disk")
    p_cv.add_argument("file")
    p_cv.add_argument("--out", default="recovered")
    p_cv.set_defaults(func=cmd_carve)

    p_gen = sub.add_parser("gen", help="generate a synthetic family-format fixture")
    p_gen.add_argument("--family", default="conti", choices=["conti"])
    p_gen.add_argument("--size", type=int, required=True)
    p_gen.add_argument("--mode", required=True, choices=["full", "partly", "header"])
    p_gen.add_argument("--percent", type=int, default=25)
    p_gen.add_argument("--out", required=True)
    p_gen.set_defaults(func=cmd_gen)

    p_sc = sub.add_parser("scan", help="triage a directory tree, headless")
    p_sc.add_argument("directory")
    p_sc.add_argument("--report", default=None, help="write a markdown report here")
    p_sc.add_argument("--carve", default=None, help="carve recoverable regions into this directory")
    p_sc.set_defaults(func=cmd_scan)

    p_tui = sub.add_parser("tui", help="launch the interactive triage console")
    p_tui.set_defaults(func=cmd_tui)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
