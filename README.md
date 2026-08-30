# ransomforensics

**Ransomware encrypted-file forensics: identify the family, map what was encrypted, and recover everything that wasn't — no malware binary, no keys, no live samples required.**

Most ransomware does *not* encrypt entire files. To hit terabytes quickly, encryptors touch only a fraction of each victim file — 25–50% of large files, or just the first 1 MiB — leaving the rest untouched on disk. The trailing metadata the encryptor appends (its "footer") tells you exactly which byte ranges were never touched. This framework parses those footers, maps encrypted vs. plaintext regions per file, and carves out the recoverable plaintext — keyless recovery of whatever the operator skipped.

## Why this exists

When a ransomware incident is detected, the immediate questions are:

1. *Which family is this?* — answered by structural footer matching, not by running the sample.
2. *Is anything recoverable without paying?* — answered by region mapping: a 5 GB PARTLY(50%) VM disk yields 2.5 GB of plaintext back with zero keys.
3. *What exactly did the encryptor do to this file?* — mode, cipher, key-wrap scheme, original size, per-file layout.

This tool answers all three from the encrypted artifacts alone. It never executes, downloads, or contains malware.

## How it works

Take Conti (family parser shipped here, documented from the leaked locker source):

```
[ ciphertext overwriting part of the original file ]
[ 524-byte RSA-wrapped key blob: ChaCha20 key(32B)+IV(8B) ]   <- footer
[ 10-byte trailer: mode(1) | data_percent(1) | orig_size(8 LE) ]
```

The parser reads the last 534 bytes, validates the trailer (`mode ∈ {0x24 FULL, 0x25 PARTLY, 0x26 HEADER}`, declared size matches file length), and derives the region map:

| Mode | Encrypted region | Untouched tail |
|---|---|---|
| FULL (0x24) | entire file | none |
| PARTLY (0x25) | first `percent`% | the rest |
| HEADER (0x26) | first 1 MiB | everything past 1 MiB |

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Identify family + show recoverable regions for one or many files
ransomforensics analyze victim.vhdx victim2.sql

# Carve the untouched plaintext to disk
ransomforensics carve victim.vhdx --out recovered/

# Generate a synthetic family-format fixture (for testing your own tooling)
ransomforensics gen --size 10000000 --mode partly --percent 25 --out sample.bin
```

Example output:

```
victim.vhdx
  family        : conti  (10-byte footer trailer (mode|percent|size))
  original size : 10.0 MiB
  mode          : PARTLY (partial (percent-based))
  data percent  : 25%
  encrypted     : 2.4 MiB
  RECOVERABLE   : 7.6 MiB (76.0%) without any key
    - bytes [0x2625a0, 0x989680)
```

## Library use

```python
from ransomforensics import analyze_file, carve

analysis = analyze_file("victim.vhdx")
if analysis:
    print(analysis.family, analysis.recoverable_ratio)   # e.g. "conti 0.76"
    carve(analysis, open("victim.vhdx","rb").read(), Path("recovered"))
```

## Adding a family

Parsers are pure-structure readers — implement `FamilyParser` and register it:

```python
# src/ransomforensics/parsers/yourfamily.py
class YourFamilyParser(FamilyParser):
    FAMILY = "yourfamily"
    def parse(self, data: bytes, path) -> Analysis | None:
        ...  # validate footer, build region map, return Analysis (or None)
```

Then append it to `registered_parsers()` in `detector.py`. Families worth adding next (footer layouts are publicly documented in incident-response writeups): Black Basta, LockBit 3.0, Akira, Royal/BlackSuit.

## Safety model

- **No malware in this repo.** All test fixtures are synthetic: generated from the format spec by `generator/`, containing random bytes and marker patterns — no real ciphertext, no real keys.
- **No execution.** The tool only reads files and writes recovered regions.
- **Defensive purpose.** Built for incident responders and DFIR work; the same region mapping that guides recovery also documents the encryptor's behavior for the incident report.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
