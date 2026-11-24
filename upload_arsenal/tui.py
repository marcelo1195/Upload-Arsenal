"""A small curses TUI panel for Upload Arsenal (stdlib only).

Lets the operator pick a profile, target, languages, toggle obfuscation, set
LHOST/LPORT (with tun0 auto-detect), preview the selection, and generate.
"""
from __future__ import annotations

import curses

from . import core, net, generator


class State:
    def __init__(self, args):
        self.profiles = list(core.PROFILES)
        self.targets = list(core.TARGETS)
        self.profile_i = self.profiles.index(
            args.profile if args.profile in self.profiles else core.DEFAULT_PROFILE)
        self.target_i = self.targets.index(
            args.target if args.target in self.targets else core.DEFAULT_TARGET)
        self.obfuscate = args.obfuscate
        self.wordlist_size = args.wordlist_size
        self.output = args.output
        self.lhost = args.lhost or ""
        self.lport = str(args.lport or "")
        self.no_vpn = args.no_vpn
        self.callback_host = args.callback_host
        self.status = "arrows: move/change  o: obfuscate  v: vpn  g: generate  q: quit"

    @property
    def profile(self):
        return core.PROFILES[self.profiles[self.profile_i]]

    @property
    def target(self):
        return core.TARGETS[self.targets[self.target_i]]

    def context(self) -> core.Context:
        lhost = self.lhost or None
        lport = int(self.lport) if self.lport.isdigit() else None
        if self.profile.risk_ceiling != "safe" and lport and not lhost:
            prefer_vpn = self.profiles[self.profile_i] == "ctf" and not self.no_vpn
            lhost, _ = net.resolve_lhost(None, prefer_vpn)
        return core.Context(
            profile=self.profile, target=self.target,
            languages=self.target.languages, lhost=lhost, lport=lport,
            obfuscate=self.obfuscate, wordlist_size=self.wordlist_size,
            callback_host=self.callback_host,
        )


FIELDS = ["profile", "target", "obfuscate", "wordlist", "lhost", "lport", "output"]


def _draw(stdscr, st: State, row: int, preview_count: int):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    title = f" Upload Arsenal — TUI panel "
    stdscr.addstr(0, 0, title.center(w - 1, "="), curses.A_BOLD)

    vpn_ip, vpn_if = net.detect_vpn_ip()
    vpn_txt = f"{vpn_ip} ({vpn_if})" if vpn_ip else "none"

    lines = [
        ("profile", f"{st.profiles[st.profile_i]:12}  risk<={st.profile.risk_ceiling}"),
        ("target", f"{st.targets[st.target_i]:12}  {st.target.description}"),
        ("obfuscate", "on" if st.obfuscate else "off"),
        ("wordlist", st.wordlist_size),
        ("lhost", st.lhost or f"(auto; tun0={vpn_txt})"),
        ("lport", st.lport or "(unset)"),
        ("output", st.output),
    ]
    for i, (label, val) in enumerate(lines):
        mark = "> " if i == row else "  "
        attr = curses.A_REVERSE if i == row else curses.A_NORMAL
        stdscr.addstr(2 + i, 2, f"{mark}{label:10}: {val}"[:w - 3], attr)

    stdscr.addstr(2 + len(lines) + 1, 2,
                  f"would generate ~{preview_count} artifacts", curses.A_DIM)
    if st.profile.requires_authorization:
        stdscr.addstr(2 + len(lines) + 2, 2,
                      "[!] active/destructive profile — authorized targets only",
                      curses.A_BOLD)
    stdscr.addstr(h - 1, 0, (" " + st.status)[:w - 1], curses.A_REVERSE)
    stdscr.refresh()


def _edit_string(stdscr, prompt, current):
    curses.echo()
    h, w = stdscr.getmaxyx()
    stdscr.addstr(h - 2, 2, " " * (w - 3))
    stdscr.addstr(h - 2, 2, f"{prompt}: {current}")
    stdscr.refresh()
    try:
        val = stdscr.getstr(h - 2, 2 + len(prompt) + 2, 60).decode()
    except Exception:
        val = current
    curses.noecho()
    return val or current


def _preview_count(st: State) -> int:
    try:
        res = generator.run(st.context())
        return len(res.artifacts)
    except Exception:
        return 0


def _loop(stdscr, st: State):
    curses.curs_set(0)
    row = 0
    preview = _preview_count(st)
    while True:
        _draw(stdscr, st, row, preview)
        key = stdscr.getch()
        if key in (ord("q"), 27):
            return None
        elif key == curses.KEY_UP:
            row = (row - 1) % len(FIELDS)
        elif key == curses.KEY_DOWN:
            row = (row + 1) % len(FIELDS)
        elif key in (curses.KEY_LEFT, curses.KEY_RIGHT):
            delta = 1 if key == curses.KEY_RIGHT else -1
            field = FIELDS[row]
            if field == "profile":
                st.profile_i = (st.profile_i + delta) % len(st.profiles)
            elif field == "target":
                st.target_i = (st.target_i + delta) % len(st.targets)
            elif field == "obfuscate":
                st.obfuscate = not st.obfuscate
            elif field == "wordlist":
                sizes = ["small", "medium", "large"]
                st.wordlist_size = sizes[(sizes.index(st.wordlist_size) + delta) % 3]
            preview = _preview_count(st)
        elif key == ord("o"):
            st.obfuscate = not st.obfuscate
            preview = _preview_count(st)
        elif key == ord("v"):
            st.no_vpn = not st.no_vpn
        elif key in (10, 13):  # Enter edits text fields
            field = FIELDS[row]
            if field == "lhost":
                st.lhost = _edit_string(stdscr, "LHOST", st.lhost)
            elif field == "lport":
                st.lport = _edit_string(stdscr, "LPORT", st.lport)
            elif field == "output":
                st.output = _edit_string(stdscr, "output", st.output)
            preview = _preview_count(st)
        elif key == ord("g"):
            return st


def run_tui(args) -> int:
    st = State(args)
    chosen = curses.wrapper(_loop, st)
    if chosen is None:
        print("[tui] cancelled.")
        return 0
    ctx = chosen.context()
    if ctx.profile.requires_authorization and not args.yes:
        ans = input(f"Profile '{ctx.profile.name}' is active/destructive. "
                    "Confirm authorization [y/N]: ")
        if ans.strip().lower() not in ("y", "yes"):
            print("[tui] aborted (no authorization).")
            return 2
    result = generator.run(ctx)
    generator.write(result, chosen.output)
    print(f"[+] {len(result.artifacts)} artifacts written to {chosen.output}/")
    print(f"[+] manifest: {chosen.output}/index.md")
    return 0
