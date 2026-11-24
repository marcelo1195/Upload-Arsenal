"""Technique plugins. Importing this package registers every technique.

To add a technique: drop a module here that calls ``@register(...)`` and add it
to the import list below (or rely on the auto-import loop).
"""
from __future__ import annotations

import importlib
import pkgutil

# Auto-import every submodule so its @register decorators run.
for _mod in pkgutil.iter_modules(__path__):
    if not _mod.name.startswith("_"):
        importlib.import_module(f"{__name__}.{_mod.name}")
