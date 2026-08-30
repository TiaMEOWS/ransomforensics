# Contributing

The highest-value contribution is a **new family parser**. Every parser means
more incident types that responders can triage and recover from.

## Adding a family parser

1. Derive the on-disk format from a public incident-response writeup (or
   your own analysis): what trailing or leading metadata does the encryptor
   append, and which byte ranges does it leave untouched?
2. Implement `FamilyParser`:

```python
# src/ransomforensics/parsers/yourfamily.py
from ..models import Analysis, ByteRegion, EncryptedRegion, FileFooter
from .base import FamilyParser


class YourFamilyParser(FamilyParser):
    FAMILY = "yourfamily"

    def parse(self, data: bytes, path, file_size: int | None = None) -> Analysis | None:
        observed = file_size if file_size is not None else len(data)
        # 1. locate + validate the footer (return None on any mismatch -
        #    a false family match is worse than no match)
        # 2. extract mode / percent / original size / key blob offset
        # 3. build the region map: encrypted + untouched regions
        return Analysis(...)
```

3. Register it in `registered_parsers()` (`detector.py`).
4. Add a synthetic fixture generator under `generator/` — **no real malware
   samples in this repo, ever**. Fixtures are random bytes shaped like the
   format.
5. Add round-trip tests: generate → parse → assert regions; plus negative
   tests (truncated footer, corrupted size field, random data).

## Rules

- No malware binaries, ciphertext, or keys in commits or fixtures. Synthetic
  data only.
- Parsers are pure-structure readers: no execution, no network.
- Every parser needs tests, including rejection cases.

## Development setup

```bash
pip install -e ".[tui,dev]"
pytest
```
