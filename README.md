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

The field helpers add, in the same directory: `upload_results.{json,html}`
(uploader), `callbacks.jsonl` (callback listener) and `requests/` (exporter),
and they annotate `index.json` with per-payload `result`, `callback` and
`found_at` data.

## Field helpers (upload / callback / hunt / export)

Once a suite is generated, four helper CLIs operate on its `index.json`
manifest so uploading, catching callbacks and locating stored files all share
one source of truth. They are pure-stdlib and authorized-use only.

### 1. Automatic uploader — `upload-arsenal-upload`

Uploads every payload to the target and records the server's response per
payload (written back into `index.json` and an `upload_results.{json,html}`
report). The endpoint, headers, **auth cookies/tokens**, multipart boundary
and file field are taken from a **raw `request.txt` copied straight from Burp
Suite or Caido** — only the file bytes/filename are swapped per payload, so
every request carries the exact session you captured.

```bash
# Copy the upload request in Burp/Caido ("Copy to file") -> request.txt
upload-arsenal-upload -m suite -r request.txt --risk safe
upload-arsenal-upload -m suite -r request.txt --proxy http://127.0.0.1:8080
upload-arsenal-upload -m suite -r request.txt \
    --success-regex 'upload (ok|complete)' --fail-regex 'not allowed'
```

If the request has several file parts, pick one with `--field <name>`; for raw
PUT/body uploads use `--raw-body`. `--scheme http|https` forces the scheme when
the captured request omits it (proxy copies usually do). Sending `destructive`
payloads (decompression bombs) requires `-y`, mirroring the generator's gate.

### 2. Callback verifier — `upload-arsenal-callback`

HTTP (and optional DNS) listener for SSRF / blind-XXE / SVG-SSRF / call-home
payloads. `--arm` rewrites each OOB payload so its callback URL carries a
unique per-payload token, so an incoming hit is mapped to exactly one payload
and marked in the manifest. Works in two shapes:

```bash
# VPS with a public IP — HTTP + DNS, armed:
upload-arsenal-callback -m suite --public-host 1.2.3.4 \
    --arm --dns --dns-domain oob.example.com

# Home box behind NAT, via an already-running `ngrok http 8000`:
upload-arsenal-callback -m suite --use-ngrok --arm
# or let it start ngrok (reads the local API at 127.0.0.1:4040):
upload-arsenal-callback -m suite --ngrok --arm
```

> **ngrok limitation (stated honestly).** ngrok's HTTP tunnel forwards **HTTP
> only**. HTTP-based OOB works through it — classic SSRF, SVG-SSRF, and the
> blind-XXE `evil.dtd` that exfiltrates over `http://host/?x=…`. A **DNS-only**
> callback (a resolver looking up `token.attacker.tld`) does **not** traverse
> an ngrok HTTP tunnel; it needs a real public IP plus an NS-delegated domain.
> `--dns` is therefore refused in ngrok mode instead of silently doing nothing.

`--arm` is idempotent — re-arming replaces the previous host/token rather than
nesting another one, so you can re-point a suite at a new listener safely.
With `--dns-domain`, blind-XXE exfil is rewritten so the read file travels in
the **hostname** (`http://%file;.<token>.<domain>/`), which is what makes the
resolver lookup itself carry the data; the DNS listener needs root for port 53
(or use `--dns-port 5353` behind a firewall redirect).

### 3. Stored-file hunter — `upload-arsenal-hunt`

After a file is accepted, finds *where it landed* by probing common storage
directories and server-side rename schemes (timestamp, hash, sanitised,
date-sharded …), confirming each hit by a payload marker (not just a 200).
Reuses `request.txt` for scheme/host/auth.

```bash
# hunt everything the uploader marked "accepted":
upload-arsenal-hunt -m suite -r request.txt
# or a specific stored name / base path:
upload-arsenal-hunt -m suite --base-url https://cdn.target/uploads/ \
    --filename poc.php.png --extra-dir incoming/
```

Located URLs are written back to the manifest (`found_at`).

### 4. Raw-request exporter — `upload-arsenal-export`

Exports each payload as a ready-to-send `.req` (built on `request.txt`) for
**Burp Repeater** ("Paste from file") and **ffuf/wfuzz** (`-request`):

```bash
upload-arsenal-export -m suite -r request.txt -o reqs/ --ffuf-template --curl
# ffuf per payload:  for r in reqs/*.req; do ffuf -request "$r" -request-proto https; done
```

`--ffuf-template` also emits `upload_FUZZ.req` + `payloads.txt`; `--curl`
writes a `replay.sh`. See `reqs/INDEX.txt` for the `.req` → payload mapping.

### Typical workflow

```bash
upload-arsenal --profile pentest --target apache-php --callback-host oob.example.com -y
upload-arsenal-callback -m file_upload_suite --public-host <ip> --arm &   # or --ngrok
upload-arsenal-upload   -m file_upload_suite -r request.txt
upload-arsenal-hunt     -m file_upload_suite -r request.txt
upload-arsenal-export   -m file_upload_suite -r request.txt -o reqs/
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
