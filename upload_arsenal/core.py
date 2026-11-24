"""Core model: artifacts, techniques, the technique registry, profiles,
targets and the generation context.

Everything the generator needs is expressed as *data* here, so adding a new
technique never means editing the orchestration code — a technique module just
decorates a function with ``@register(...)``.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Callable, Iterable


# --------------------------------------------------------------------------- #
# Risk model
# --------------------------------------------------------------------------- #
# safe        -> non-intrusive, only proves/exercises a code path (bug bounty).
# active       -> gives command execution / a shell / calls back out (pentest).
# destructive  -> can degrade or crash the target (DoS-ish); never on by default.
RISK_ORDER = {"safe": 0, "active": 1, "destructive": 2}
RISK_LEVELS = tuple(RISK_ORDER)


def risk_at_most(risk: str, ceiling: str) -> bool:
    return RISK_ORDER[risk] <= RISK_ORDER[ceiling]


# --------------------------------------------------------------------------- #
# Artifact: one generated file + the metadata that feeds the manifest
# --------------------------------------------------------------------------- #
@dataclass
class Artifact:
    relpath: str                 # path relative to the output root
    data: bytes                  # raw bytes written to disk
    technique: str               # owning technique name
    category: str                # e.g. "extension-bypass", "xxe"
    risk: str                    # safe | active | destructive
    description: str             # what this file tests
    usage: str = ""              # how to use it in the field
    reference: str = ""          # CWE / article / id
    language: str = ""           # payload language if relevant

    def __post_init__(self) -> None:
        if isinstance(self.data, str):
            self.data = self.data.encode()
        if self.risk not in RISK_ORDER:
            raise ValueError(f"invalid risk {self.risk!r} on {self.relpath}")


# --------------------------------------------------------------------------- #
# Technique + registry
# --------------------------------------------------------------------------- #
@dataclass
class Technique:
    name: str
    category: str
    risk: str
    description: str
    generate: Callable[["Context"], Iterable[Artifact]]
    reference: str = ""
    tags: tuple = ()

    def __post_init__(self) -> None:
        if self.risk not in RISK_ORDER:
            raise ValueError(f"invalid risk {self.risk!r} on technique {self.name}")


_REGISTRY: dict[str, Technique] = {}


def register(name, *, category, risk, description, reference="", tags=()):
    """Decorator that registers a technique generator function."""
    def _wrap(fn):
        if name in _REGISTRY:
            raise ValueError(f"duplicate technique name: {name}")
        _REGISTRY[name] = Technique(
            name=name, category=category, risk=risk, description=description,
            generate=fn, reference=reference, tags=tuple(tags),
        )
        return fn
    return _wrap


def all_techniques() -> list[Technique]:
    return sorted(_REGISTRY.values(), key=lambda t: (t.category, t.name))


def get_technique(name: str) -> Technique | None:
    return _REGISTRY.get(name)


# --------------------------------------------------------------------------- #
# Target: the upload sink we are attacking. Drives languages + extensions.
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    name: str
    description: str
    languages: tuple            # payload languages that make sense here
    extensions: tuple           # extensions worth trying against this sink
    trailing: tuple = ()        # server-specific trailing chars for ext bypass


TARGETS: dict[str, Target] = {
    "apache-php": Target(
        "apache-php", "Apache/PHP stack",
        ("php",),
        ("php", "phtml", "phar", "pht", "php5", "png", "jpg", "gif", "svg", "pdf"),
        trailing=(".", "/", "%20", "%0a", "::$DATA"),
    ),
    "nginx-php": Target(
        "nginx-php", "Nginx + PHP-FPM",
        ("php",),
        ("php", "phtml", "phar", "png", "jpg", "gif", "svg", "pdf"),
        trailing=("%00", ".", "%20"),
    ),
    "iis-aspnet": Target(
        "iis-aspnet", "IIS / ASP.NET",
        ("aspx",),
        ("aspx", "asp", "asax", "ashx", "config", "png", "jpg", "gif", "svg", "pdf"),
        trailing=("::$DATA", ".", "%20", ";.jpg"),
    ),
    "tomcat-java": Target(
        "tomcat-java", "Tomcat / Java servlet container",
        ("java",),
        ("jsp", "jspx", "war", "png", "jpg", "gif", "svg", "pdf"),
        trailing=(".", "%00"),
    ),
    "node": Target(
        "node", "Node.js backend",
        ("nodejs",),
        ("js", "png", "jpg", "gif", "svg", "pdf"),
    ),
    "generic": Target(
        "generic", "Unknown stack — broad coverage",
        ("php", "java", "python", "ruby", "nodejs"),
        ("png", "jpg", "jpeg", "gif", "svg", "pdf", "bmp", "webp"),
        trailing=(".", "/", "%20", "%00", "%0a"),
    ),
}

DEFAULT_TARGET = "generic"


# --------------------------------------------------------------------------- #
# Profile: which risk ceiling + technique categories to emit.
# --------------------------------------------------------------------------- #
@dataclass
class Profile:
    name: str
    description: str
    risk_ceiling: str                  # max risk emitted
    include: tuple = ("*",)            # category globs to include
    exclude: tuple = ()               # category globs to exclude
    requires_authorization: bool = False  # active/destructive engagement

    def accepts(self, tech: Technique) -> bool:
        if not risk_at_most(tech.risk, self.risk_ceiling):
            return False
        if any(fnmatch.fnmatch(tech.category, g) for g in self.exclude):
            return False
        return any(fnmatch.fnmatch(tech.category, g) for g in self.include)


PROFILES: dict[str, Profile] = {
    "bugbounty": Profile(
        "bugbounty",
        "Non-intrusive validation kit (safe). Default for bug bounty.",
        risk_ceiling="safe",
    ),
    "pentest": Profile(
        "pentest",
        "Adds RCE and reverse shells. Active engagement — needs authorization.",
        risk_ceiling="active",
        requires_authorization=True,
    ),
    "ctf": Profile(
        "ctf",
        "Maximum coverage, aggressive. Uses the attacker VPN (tun0) IP by default.",
        risk_ceiling="destructive",
        requires_authorization=True,
    ),
}

DEFAULT_PROFILE = "bugbounty"


# --------------------------------------------------------------------------- #
# Generation context passed to every technique
# --------------------------------------------------------------------------- #
@dataclass
class Context:
    profile: Profile
    target: Target
    languages: tuple
    lhost: str | None = None
    lport: int | None = None
    obfuscate: bool = False
    wordlist_size: str = "medium"       # small | medium | large
    callback_host: str = "ATTACKER_HOST"  # for OOB/XXE/SVG callbacks
    extras: dict = field(default_factory=dict)

    def langs(self) -> tuple:
        """Languages applicable to this run, intersected with the target."""
        chosen = tuple(l for l in self.languages if l in self.target.languages)
        return chosen or self.target.languages
