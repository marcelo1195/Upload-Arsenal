# Upload Arsenal 2.0

File-upload security test-suite generator for **authorized** pentest engagements,
bug bounty programs and CTFs. It produces a structured suite of payloads and
fuzzing wordlists for probing file-upload functionality, each catalogued in a
manifest so you know exactly what every file tests and how to use it.

> ⚠️ **Authorized use only.** Active and destructive payloads (RCE, reverse
> shells, decompression bombs) are gated behind explicit profiles and a
> confirmation flag. Use only against systems you are permitted to test.

## What's new in 2.0

- **Plugin technique registry** — each technique is a self-registering module;
  adding one never touches the orchestration code.
- **Payloads as data** with reliable, *verified* obfuscation (the suite ships a
  test that confirms obfuscated payloads still execute).
- **Profiles** instead of flag soup: `bugbounty` (safe), `pentest` (active),
  `ctf` (max coverage).
- **Targets** (`--target`) that drive extensions/magic bytes per stack
  (Apache/PHP, Nginx/PHP, IIS/ASP.NET, Tomcat/Java, Node, generic).
- **CTF VPN auto-detect**: LHOST defaults to your `tun0`/OpenVPN address; override
  with `--lhost`.
- **New techniques**: Zip Slip (ZIP/TAR), validated polyglots (PNG/GIF/JPEG/PDF),
  SVG XSS + SVG/standalone XXE (file read, OOB/blind, SSRF, php filter),
  ImageMagick/ImageTragick (MVG/MSL), EXIF-embedded payloads.
- **Parameter fuzzing wordlists**: upload param names, filename values, path
  traversal, SSRF URLs (incl. cloud metadata).
- **Manifest + report**: every run writes `index.json`, `index.md` and
  `report.html` describing each artifact.
- **TUI panel** (`--tui`) and a backwards-compatible `arsenal.py` shim.

Pure Python 3, **no external dependencies**.

## Install

```bash
git clone https://github.com/marcelo1195/Upload-Arsenal.git
cd Upload-Arsenal
pip install -e .          # provides the `upload-arsenal` command
# or run without installing:
python3 -m upload_arsenal --help
```

## Usage

```bash
# Bug bounty (safe, non-intrusive) against an Apache/PHP sink
upload-arsenal --profile bugbounty --target apache-php

# CTF: LHOST auto-detected from tun0, just give the port
upload-arsenal --profile ctf --lport 4444 -y

# Pentest with an explicit listener and obfuscation
upload-arsenal --profile pentest --lhost 10.10.14.5 --lport 443 --obfuscate -y

# Preview without writing, or launch the TUI
upload-arsenal --profile ctf --lport 4444 --dry-run
upload-arsenal --tui

# Discover what's available
upload-arsenal --list-profiles
upload-arsenal --list-targets
upload-arsenal --list-techniques
```

Narrow the output with `--only <technique>` / `--exclude <technique>`
(repeatable), `--lang php`, and `--wordlist-size small|medium|large`.

### Profiles & risk model

| Profile    | Risk ceiling  | Emits                                            |
|------------|---------------|--------------------------------------------------|
| `bugbounty`| `safe`        | PoC, polyglots (PoC), filter-bypass & fuzzing wordlists, SVG XSS, EXIF |
| `pentest`  | `active`      | + RCE, reverse shells, XXE, SVG XXE, Zip Slip, ImageMagick |
| `ctf`      | `destructive` | + decompression bombs; VPN LHOST auto-detect     |

`pentest` and `ctf` require `-y`/`--yes` (or an interactive confirmation) to
assert you are authorized.

## Output layout

```
file_upload_suite/
├── index.json         # machine-readable manifest
├── index.md           # human manifest: file → technique → what it tests → usage
├── report.html        # styled report to attach to an engagement writeup
├── <lang>/            # code payloads + polyglots per language
├── svg/  xxe/  archives/  image-processing/
└── wordlists/         # content-type + fuzz/ (param names, filenames, traversal, ssrf)
```

## Legacy compatibility

The old `arsenal.py -poc / -exploit / --rev-shell / -obfuscate` flags still work
and are mapped onto the 2.0 engine. New work should use the `upload-arsenal` CLI.

## Development

```bash
pip install pytest
pytest
```

## License

GNU General Public License v3.0 — see `LICENSE`.
