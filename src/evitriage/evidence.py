from __future__ import annotations

import hashlib
from pathlib import Path

from .models import EvidenceFile


def describe_evidence(path: str | Path) -> EvidenceFile:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"Evidence file does not exist: {source}")

    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)

    return EvidenceFile(str(source), digest.hexdigest(), source.stat().st_size)

