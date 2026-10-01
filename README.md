# antigravity-uncensored

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: macOS | Windows](https://img.shields.io/badge/platform-macOS%20%7C%20Windows-lightgrey.svg)]()
[![Release](https://img.shields.io/github/v/release/Ares-X/antigravity-uncensored?label=download&color=orange)](https://github.com/Ares-X/antigravity-uncensored/releases)
[![GitHub stars](https://img.shields.io/github/stars/Ares-X/antigravity-uncensored?style=social)](https://github.com/Ares-X/antigravity-uncensored)

> **Fork of [google-antigravity/antigravity-cli](https://github.com/google-antigravity/antigravity-cli)** — exact-match binary patcher for the Antigravity CLI.
>
> Windows PE (`antigravity.exe`) and macOS Mach-O (`agy` / `antigravity`, arm64 and x64). Same-length replacements only. On macOS the patched file is ad-hoc re-signed so it still loads.

---

## Patch it yourself

The patcher reads whatever official binary you point it at. `auto_uncensor.py` picks the GitHub asset for this machine:

| Host | Release asset | Binary inside |
|------|----------------|---------------|
| macOS Apple Silicon | `agy_cli_mac_arm64.tar.gz` | `antigravity` |
| macOS Intel | `agy_cli_mac_x64.tar.gz` | `antigravity` |
| Windows x64 | `agy_cli_windows_x64.zip` | `antigravity.exe` |
| Windows arm64 | `agy_cli_windows_arm64.zip` | `antigravity.exe` |

```bash
# macOS — download the official build, patch it, ad-hoc sign it:
python3 tools/auto_uncensor.py

# Or patch a binary you already have (installer name is `agy`):
python3 tools/agy_domesticate.py "$(which agy)" tools/targets.json

# Dry-run: which keywords hit / miss on this exact build, no bytes touched:
python3 tools/agy_domesticate.py "$(which agy)" tools/targets.json --check
python3 tools/auto_uncensor.py --check   # download latest + check, produce nothing

# Hunt: find restriction strings in the binary that NO current target covers
# (enums, flags, symbols, instruction sentences) — writes hunt_report.json:
python3 tools/agy_domesticate.py "$(which agy)" tools/targets.json --hunt
```

When a keyword finds no match the check prints a `[NO MATCH]` line plus a
**variant clue** — a context snippet of the near-variant that does exist in the
binary. That is how upstream renames (1.0.9 → 1.2.14 renamed the phish
threshold enums, see `docs/KEYWORD_DRIFT.md`) are diagnosed in seconds.

```powershell
python tools/auto_uncensor.py
python tools/agy_domesticate.py path\to\antigravity.exe tools\targets.json
```

Force a specific asset with `python3 tools/auto_uncensor.py --platform mac-arm64`.

A `.original` backup is written beside the binary before any edit. Put it back to restore the untouched file, including the original code signature:

```bash
cp /path/to/agy.original /path/to/agy
```

macOS only: byte edits invalidate the Developer ID signature. The patcher runs `codesign --force --sign - --options runtime` on Mach-O output. That seal is ad-hoc. It loads locally. It is not a notarized Google signature. The official install path is `~/.local/bin/agy` (a Homebrew copy may live at `/opt/homebrew/bin/agy`). Patch a copy if you still want the signed original on `PATH`.

---

## Repository Structure

```
antigravity-uncensored/
├── tools/
│   ├── agy_domesticate.py   # Exact-match binary patcher (CLI)
│   ├── auto_uncensor.py     # One-click: download official + patch
│   └── targets.json         # Data-driven patch configuration
├── docs/
│   ├── BINARY_ANATOMY.md        # PE and Mach-O layout, Go runtime, string formats
│   ├── KEYWORD_DRIFT.md         # 1.0.9 → 1.2.14 string renames, per-keyword hit report
│   ├── REFUSAL_CATALOG.md       # All 100+ hardcoded refusal patterns
│   ├── SYSTEM_INFRASTRUCTURE.md # Override modes and protection layers
│   ├── TELEMETRY_NETWORK.md     # Analytics pipeline and blockades
│   ├── GEMINI_MODELS.md         # Model configs and safety filter mapping
│   ├── PROBLEMS_SOLUTIONS.md    # 10 identified problems + solutions
│   ├── DOMESTICATION_REPORT.md  # Full 6-phase operation log
│   └── OPERATION_SUMMARY.md     # Commander-level recap
├── README.md
└── .gitignore
```

## What Gets Patched

| Layer | Description | Patches |
|-------|-------------|---------|
| Navigation Restrictions | "NEVER access restricted areas", "NEVER solve captchas", "cannot open new pages" | 8 markers |
| Prohibited Actions | Section headers marking content as forbidden | 3 headers + 3 word classes |
| Safety Guidelines | "Strictly adhere to safety guidelines", "$Trax is never valid" | 8 markers |
| Harm Categories | 11 enum values (HATE_SPEECH, SEXUALLY_EXPLICIT, etc.) | 29 instances |
| Phish Block | Threshold enums controlling phishing detection severity | 3 instances |
| Brain Filter | Strategy enums for content classification | 4 instances |
| Supercomplete Filter | Advanced semantic filter enums | 8 instances |
| Instruction Modes | 17 runtime mode strings (SINGLE, STRICT, CAUTIOUS, etc.) | ~25 instances |
| Telemetry Functions | Record* functions, trajectory*, sentry* | ~280 instances |
| Analytics Endpoints | 7 provider domains (Sentry, Datadog, Amplitude, etc.) | 1,030 instances |
| Consent Gates | Permission states for data collection | 6 instances |
| System Prompt Protection | Anti-prompt-injection defense blocks | 9 copies |

Counts above are from the Windows 1.0.9 pass. Strings missing from a given build are skipped. `targets.json` is cross-version: renamed 1.2.x strings (Gemini-style `BLOCK_*_AND_ABOVE` phish/harm thresholds, `BatchRecordPrompts`, `PINNING_STATUS_*`, the `policy_guardian` layer) sit alongside the 1.0.9 originals, and whichever exists in the binary gets patched. A `--hunt` pass over 1.2.14 added the layers the original catalog never covered: the agent-monitor `DENY_BY_DEFAULT`/`SOFT_BLOCK_INJECT` family, `FILE_ACCESS_POLICY_*`, `POLICY_DECISION_*`/`POLICY_EVALUATION_OUTCOME_DENY`, `AUTO_RUN_DECISION_*_DENY`, `AGENT_SETTING_POLICY_*`, the `CheckUrlDenylist`/`CheckUrlAntivirus` safe-browsing RPCs, `BLOCK_REASON_GITIGNORED`/`_OUTSIDE_WORKSPACE`, `TAB_JUMP_FILTER_*`, and three more harm categories (`IMAGE_HARASSMENT`, `IMAGE_HATE`, `JAILBREAK`). macOS `agy` 1.2.14 arm64 takes **1,811** exact hits (**130/156** keywords; the 26 no-hits are dead pre-1.2 names kept for old builds) and still prints `1.2.14` from `agy --version`. See `docs/KEYWORD_DRIFT.md` for the full diff and the deliberately-untouched list.

## How It Works

Go binaries store configuration text in a read-only blob: `.rdata` on Windows PE, `__TEXT,__rodata` / `__DATA_CONST,__rodata` on macOS Mach-O. Go strings are not C strings. Scanning until `0x00` swallows neighboring data (the Windows build embeds Chroma XML beside the prompts).

The patcher uses **exact-match replacement only**:

1. Reads the full binary into a `bytearray`
2. For each target string, calls `data.find(old_string)` to locate the exact bytes
3. Replaces with same-length content (auto-pads or truncates as needed)
4. All protobuf length-prefixed enums are replaced preserving their structure
5. Writes the patched binary back
6. On macOS, ad-hoc re-signs the Mach-O (`codesign --sign - --options runtime`). The string table stays the same length. The trailing code-signature blob can shrink, because an ad-hoc seal is smaller than Google's Developer ID signature.

**The critical lesson:** v1 of this patcher used null-byte boundary scanning to replace full document ranges. This destroyed embedded Chroma XML syntax highlighting data sitting adjacent to instruction text blocks, causing the binary to panic at startup:

```
panic: could not find <config> element
```

v2 switched to exact-match only — no collateral damage, clean boot.

## Safety Features

- **Automatic SHA-256 backup** before any modification
- **Rollback on size mismatch** if the patcher detects byte count changes
- **Size verification** so PE and Mach-O load commands stay valid
- **Code bytes untouched** — only exact string hits are rewritten
- **macOS re-sign** — Mach-O output gets an ad-hoc signature with hardened runtime
- **Critical infrastructure preserved** — execution rules, model routing, agent templates

## Patch Report

After running, the patcher generates `patch_report.json` containing:
- Every patch offset and length
- Original and new SHA-256 hashes
- Total patch count
- Per-keyword coverage (`matched_keywords`, `missed_keywords` with section + keyword)

## Technical Notes

- **pclntab stripped** — function name recovery tools (GoReSym) cannot parse this binary
- **3 string storage formats** found in .rdata: protobuf, null-bounded docs, null-terminated
- **Google-internal build** — build version `go1.27-20260615-RC00 cl/932742892` uses Google's changelist system
- **Confirmed post-patch (Windows, historical):** `agy --version` returned `1.0.9` on the 153 MB PE build
- **macOS:** stock `agy` 1.2.14 is a thin arm64 Mach-O signed by `Developer ID Application: Google LLC`. Some Windows-only enums (`START_MENU_PINNING_*`, `TASKBAR_PINNING_*`) are absent there and are skipped. Hit count depends on the build. See `docs/BINARY_ANATOMY.md`.

## Disclaimer

This software is provided for **educational and research purposes only**. Modifying software binaries may violate the software's terms of service, license agreements, or applicable laws. The authors assume no liability for misuse. Use at your own risk.
