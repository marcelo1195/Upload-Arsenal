"""Read and update the suite manifest (index.json) produced by the generator.

The helper tools read this manifest to know which payloads exist, and write
back result/callback status so a single index.json becomes the shared source
of truth across the uploader, the callback listener and the file hunter.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class ManifestEntry:
    path: str
    technique: str = ""
    category: str = ""
    risk: str = ""
    language: str = ""
    description: str = ""
    usage: str = ""
    reference: str = ""
    bytes: int = 0
    # Fields the helper tools add back:
    result: dict = field(default_factory=dict)       # uploader result
    callback: dict = field(default_factory=dict)     # OOB callback hit
    found_at: list = field(default_factory=list)     # discovered stored URLs

    @classmethod
    def from_row(cls, row: dict) -> "ManifestEntry":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in row.items() if k in known})

    def to_row(self) -> dict:
        row = {
            "path": self.path, "technique": self.technique,
            "category": self.category, "risk": self.risk,
            "language": self.language, "description": self.description,
            "usage": self.usage, "reference": self.reference,
            "bytes": self.bytes,
        }
        if self.result:
            row["result"] = self.result
        if self.callback:
            row["callback"] = self.callback
        if self.found_at:
            row["found_at"] = self.found_at
        return row


@dataclass
class Manifest:
    meta: dict
    entries: list
    root: str                         # directory containing index.json

    @classmethod
    def load(cls, path: str) -> "Manifest":
        """Load a manifest from an index.json file or its containing directory."""
        if os.path.isdir(path):
            path = os.path.join(path, "index.json")
        with open(path) as f:
            doc = json.load(f)
        entries = [ManifestEntry.from_row(r) for r in doc.get("artifacts", [])]
        return cls(meta=doc.get("meta", {}), entries=entries,
                   root=os.path.dirname(os.path.abspath(path)))

    def artifact_path(self, entry: ManifestEntry) -> str:
        return os.path.join(self.root, entry.path)

    def read_bytes(self, entry: ManifestEntry) -> bytes:
        with open(self.artifact_path(entry), "rb") as f:
            return f.read()

    def filter(self, *, risk=None, category=None, technique=None,
               language=None) -> list:
        def keep(e: ManifestEntry) -> bool:
            if risk and e.risk not in risk:
                return False
            if category and e.category not in category:
                return False
            if technique and e.technique not in technique:
                return False
            if language and e.language not in language:
                return False
            return True
        return [e for e in self.entries if keep(e)]

    def by_path(self, path: str) -> ManifestEntry | None:
        for e in self.entries:
            if e.path == path:
                return e
        return None

    def save(self, path: str | None = None) -> None:
        dest = path or os.path.join(self.root, "index.json")
        doc = {"meta": self.meta, "artifacts": [e.to_row() for e in self.entries]}
        tmp = dest + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=2)
        os.replace(tmp, dest)


# Tokens embedded in OOB payloads so a callback can be traced to a payload.
def callback_token(entry: ManifestEntry) -> str:
    """A short, URL-safe token derived from the artifact path."""
    import hashlib
    return "ua" + hashlib.sha1(entry.path.encode()).hexdigest()[:10]
