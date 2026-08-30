"""Parser interface: one module per ransomware family."""
from __future__ import annotations

import abc

from ..models import Analysis


class FamilyParser(abc.ABC):
    """Parses one family's encrypted-file artifacts.

    Parsers are pure-structure readers: they never need the malware binary,
    only knowledge of the on-disk format the encryptor leaves behind.
    """

    #: lowercase family identifier, e.g. "conti"
    FAMILY: str = ""

    @abc.abstractmethod
    def parse(self, data: bytes, path, file_size: int | None = None) -> Analysis | None:
        """Return an Analysis if `data` matches this family, else None.

        `data` may be only the tail of the file (the footer always lives at
        the end); in that case `file_size` carries the real on-disk length
        for validation, and `len(data)` must be ignored for sizing.
        """
