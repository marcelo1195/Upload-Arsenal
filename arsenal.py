#!/usr/bin/env python3
"""Backwards-compatibility shim for Upload Arsenal 1.x.

The tool is now the ``upload_arsenal`` package. The old flags still work and
are mapped onto the new engine:

    -poc / -exploit / --rev-shell / -obfuscate  ->  profile + techniques

Prefer the new CLI:  ``python3 -m upload_arsenal --help``  (or ``upload-arsenal``).
"""
from __future__ import annotations

import sys


def _legacy_to_new(argv: list[str]) -> list[str]:
    poc = "-poc" in argv
    exploit = "-exploit" in argv
    revshell = "--rev-shell" in argv
    obf = "-obfuscate" in argv
    lhost = lport = None
    for i, a in enumerate(argv):
        if a == "--lhost" and i + 1 < len(argv):
            lhost = argv[i + 1]
        if a == "--lport" and i + 1 < len(argv):
            lport = argv[i + 1]

    new = []
    # Choose a profile from the legacy intent.
    if revshell or exploit:
        new += ["--profile", "pentest", "-y"]
    else:
        new += ["--profile", "bugbounty"]
    # Narrow techniques to match the old behaviour.
    only = []
    if poc:
        only += ["poc", "polyglot", "extension-bypass", "content-type", "svg-xss", "xxe"]
    if exploit:
        only += ["rce", "polyglot"]
    if revshell:
        only += ["revshell"]
    for t in dict.fromkeys(only):
        new += ["--only", t]
    if obf:
        new += ["--obfuscate"]
    if lhost:
        new += ["--lhost", lhost]
    if lport:
        new += ["--lport", lport]
    return new


def main() -> int:
    argv = sys.argv[1:]
    if any(a in argv for a in ("-poc", "-exploit", "--rev-shell", "-obfuscate")):
        print("[compat] arsenal.py 1.x flags detected — mapping to the 2.0 engine.\n"
              "         Use 'python3 -m upload_arsenal --help' for the full CLI.\n",
              file=sys.stderr)
        argv = _legacy_to_new(argv)
    from upload_arsenal.cli import main as new_main
    return new_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
