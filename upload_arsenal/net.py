"""Attacker-host detection.

For the CTF profile the reverse-shell LHOST should be the attacker's VPN
address (the ``tun0`` interface handed out by OpenVPN on labs such as
HackTheBox). This resolves it automatically, with a manual override always
winning.
"""
from __future__ import annotations

import ipaddress
import socket
import subprocess

# Interfaces to probe, in order of preference for VPN-based labs.
VPN_IFACES = ("tun0", "tun1", "wg0", "tap0")


def iface_ipv4(iface: str) -> str | None:
    """Return the IPv4 bound to `iface`, or None. Linux-first, portable fallback."""
    # Preferred: `ip -4 addr show <iface>`
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except (OSError, subprocess.SubprocessError):
        pass
    # Fallback: `ifconfig <iface>` (BSD/macOS)
    try:
        out = subprocess.run(
            ["ifconfig", iface], capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "inet6" not in line:
                return line.split()[1]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def detect_vpn_ip() -> tuple[str | None, str | None]:
    """(ip, iface) for the first available VPN interface, else (None, None)."""
    for iface in VPN_IFACES:
        ip = iface_ipv4(iface)
        if ip:
            return ip, iface
    return None, None


def primary_ip() -> str | None:
    """Best-guess outbound local IP (used as a non-VPN fallback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def resolve_lhost(explicit: str | None, prefer_vpn: bool) -> tuple[str | None, str]:
    """Resolve the LHOST to use.

    Returns (ip, source) where source explains where it came from, so the CLI
    can tell the operator exactly which address was baked into the payloads.
    """
    if explicit:
        try:
            ipaddress.ip_address(explicit)
            return explicit, "override"
        except ValueError:
            return explicit, "override (not an IP — assuming hostname)"
    if prefer_vpn:
        ip, iface = detect_vpn_ip()
        if ip:
            return ip, f"auto:{iface}"
    ip = primary_ip()
    if ip:
        return ip, "auto:primary"
    return None, "unresolved"
