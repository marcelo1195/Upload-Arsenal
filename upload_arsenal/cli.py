"""Command-line interface for Upload Arsenal 2.0."""
from __future__ import annotations

import argparse
import sys

from . import __version__, core, net, generator


BANNER = r"""
  _   _ _ _            _      _                        _
 | | | | | |_ __  ___ | | ___| |     __ _ _ _ ___ ___ | |_
 | |_| | | | '_ \/ _ \| |/ _` |  _  / _` | '_(_-/ -_)| ' \
  \___/|_|_| .__/\___/|_|\__,_| (_) \__,_|_| /__\___||_||_|
           |_|                 Upload Arsenal v%s
""" % __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload-arsenal",
        description="Generate a file-upload test suite for authorized pentest, "
                    "bug bounty and CTF use.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  upload-arsenal --profile bugbounty --target apache-php\n"
               "  upload-arsenal --profile ctf --lport 4444   # LHOST auto from tun0\n"
               "  upload-arsenal --profile pentest --lhost 10.10.14.5 --lport 443 -y\n"
               "  upload-arsenal --tui\n",
    )
    p.add_argument("--version", action="version", version=f"upload-arsenal {__version__}")

    sel = p.add_argument_group("selection")
    sel.add_argument("--profile", default=core.DEFAULT_PROFILE,
                     choices=list(core.PROFILES), help="payload profile")
    sel.add_argument("--target", default=core.DEFAULT_TARGET,
                     choices=list(core.TARGETS), help="upload sink being attacked")
    sel.add_argument("--lang", action="append", default=[],
                     help="restrict payload languages (repeatable)")
    sel.add_argument("--only", action="append", default=[],
                     help="only these technique names (repeatable)")
    sel.add_argument("--exclude", action="append", default=[],
                     help="skip these technique names (repeatable)")

    shell = p.add_argument_group("reverse shell / callbacks")
    shell.add_argument("--lhost", help="LHOST for reverse shells (default: auto)")
    shell.add_argument("--lport", type=int, help="LPORT for reverse shells")
    shell.add_argument("--no-vpn", action="store_true",
                       help="do not auto-detect the tun0/VPN IP for LHOST")
    shell.add_argument("--callback-host", default="ATTACKER_HOST",
                       help="host for XXE/SVG/SSRF callbacks")

    mod = p.add_argument_group("modifiers")
    mod.add_argument("-o", "--output", default="file_upload_suite",
                     help="output directory")
    mod.add_argument("--obfuscate", action="store_true",
                     help="obfuscate code payloads (reliable encoding wrappers)")
    mod.add_argument("--wordlist-size", default="medium",
                     choices=["small", "medium", "large"])
    mod.add_argument("-y", "--yes", action="store_true",
                     help="confirm authorization for active/destructive profiles")

    info = p.add_argument_group("info / modes")
    info.add_argument("--list-techniques", action="store_true")
    info.add_argument("--list-profiles", action="store_true")
    info.add_argument("--list-targets", action="store_true")
    info.add_argument("--dry-run", action="store_true",
                      help="show what would be generated without writing")
    info.add_argument("--tui", action="store_true", help="launch the TUI panel")
    info.add_argument("-q", "--quiet", action="store_true")
    return p


def _print_lists(args) -> bool:
    did = False
    if args.list_profiles:
        did = True
        print("Profiles:")
        for name, pr in core.PROFILES.items():
            auth = " [needs -y]" if pr.requires_authorization else ""
            print(f"  {name:10} risk<={pr.risk_ceiling:11}{auth}  {pr.description}")
    if args.list_targets:
        did = True
        print("Targets:")
        for name, t in core.TARGETS.items():
            print(f"  {name:12} {t.description}  ext={','.join(t.extensions)}")
    if args.list_techniques:
        did = True
        print("Techniques:")
        for t in core.all_techniques():
            print(f"  {t.name:18} [{t.risk:11}] {t.category:16} {t.description}")
    return did


def build_context(args) -> core.Context:
    profile = core.PROFILES[args.profile]
    target = core.TARGETS[args.target]
    langs = tuple(args.lang) if args.lang else target.languages

    lhost, lport = args.lhost, args.lport
    source = None
    # Resolve LHOST only when a shell could be emitted (active+ profiles).
    if profile.risk_ceiling != "safe":
        prefer_vpn = (args.profile == "ctf") and not args.no_vpn
        if lport and not lhost and (prefer_vpn or args.lhost is None):
            lhost, source = net.resolve_lhost(args.lhost, prefer_vpn)
        elif lhost:
            source = "override"
    args._lhost_source = source

    return core.Context(
        profile=profile, target=target, languages=langs,
        lhost=lhost, lport=lport, obfuscate=args.obfuscate,
        wordlist_size=args.wordlist_size, callback_host=args.callback_host,
    )


def _confirm_authorization(args) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        print("error: profile '%s' emits active/destructive payloads; pass -y to "
              "confirm you are authorized." % args.profile, file=sys.stderr)
        return False
    ans = input(f"Profile '{args.profile}' generates active/destructive payloads. "
                "Confirm you have authorization for this target [y/N]: ")
    return ans.strip().lower() in ("y", "yes")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.tui:
        from .tui import run_tui
        return run_tui(args)

    if _print_lists(args):
        return 0

    profile = core.PROFILES[args.profile]
    if profile.requires_authorization and not args.dry_run:
        if not _confirm_authorization(args):
            return 2

    ctx = build_context(args)
    result = generator.run(ctx, only=set(args.only) or None,
                           exclude_names=set(args.exclude))

    if not args.quiet:
        print(BANNER)
        src = getattr(args, "_lhost_source", None)
        if ctx.lhost:
            print(f"[*] LHOST {ctx.lhost}:{ctx.lport}"
                  + (f"  (source: {src})" if src else ""))
        elif profile.risk_ceiling != "safe" and args.lport:
            print("[!] could not resolve LHOST; reverse shells skipped. "
                  "Pass --lhost explicitly.")
        print(f"[*] profile={ctx.profile.name} target={ctx.target.name} "
              f"langs={','.join(ctx.langs())}")
        print(f"[*] {len(result.artifacts)} artifacts, "
              f"{len(result.skipped)} techniques skipped")

    if args.dry_run:
        for art in sorted(result.artifacts, key=lambda a: a.relpath):
            print(f"    {art.risk:11} {art.relpath}")
        print("[dry-run] nothing written.")
        return 0

    generator.write(result, args.output)
    if not args.quiet:
        print(f"[+] written to: {args.output}/")
        print(f"[+] manifest:   {args.output}/index.md  (+ index.json, report.html)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
