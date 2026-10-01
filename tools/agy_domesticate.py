#!/usr/bin/env python3
"""
AGY DOMESTICATION ENGINE — Exact-match binary patcher.
Reads a target binary + JSON config, applies byte-precision patches
to neutralize behavioral restrictions. All strings replaced in-place
with same-length content to preserve binary integrity.

Works on Windows PE and macOS Mach-O. The patch itself is format-agnostic.
On macOS the Developer ID seal is invalidated by any byte edit, so a Mach-O
is ad-hoc re-signed after a successful write.

Usage:
    python agy_domesticate.py <binary_path> [config_path] [--check] [--hunt]
                              [--context NEEDLE]

    binary_path  : Path to agy / antigravity / antigravity.exe
    config_path  : Path to targets.json (default: targets.json)
    --check      : Dry-run. Report which keywords hit / miss (with variant
                   clues for renamed strings) without touching the binary.
    --hunt       : Scan the binary for restriction-vocabulary strings that no
                   current target covers: enum/flag identifiers, symbols, and
                   instruction-document sentences. Prints categorized
                   candidates with hit counts and first offsets, and writes
                   hunt_report.json for triage. Modifies nothing.
    --context    : Show the document text around every occurrence of NEEDLE,
                   plus the byte budget of the enclosing printable run — the
                   authoring aid for writing same-length replacements.
    --output PATH: Side-by-side mode. Write the patched copy to PATH and leave
                   the source binary untouched, so both versions can be
                   launched by name (e.g. agy = original, agy-uncensored =
                   patched). If a .original backup exists beside the source,
                   the copy is patched from that, so re-running against an
                   already-patched path still yields a clean result.

Every keyword that finds no match is printed with a [NO MATCH] line plus
"variant clue" context when a near-variant exists in the binary — that is
how upstream renames (e.g. 1.0.9 -> 1.2.14 enum renames) are diagnosed.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter

MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
)

# (config key, display title, report type)
SECTION_DEFS = [
    ("harm_categories", "Harm Categories", "enum"),
    ("phish_filters", "Phish Filters", "enum"),
    ("brain_filters", "Brain Filters", "enum"),
    ("supercomplete_filters", "Supercomplete Filters", "enum"),
    ("instruction_overrides", "Instruction Overrides", "override"),
    ("semantic_blocks", "Semantic Blocks", "semantic"),
    ("telemetry_functions", "Telemetry Functions", "telemetry"),
    ("analytics_endpoints", "Analytics Endpoints", "analytics"),
    ("consent_gates", "Consent Gates", "consent"),
]


def find_and_replace_exact(data, search, replacement):
    if isinstance(search, str):
        search = search.encode("latin-1")
    if isinstance(replacement, str):
        replacement = replacement.encode("latin-1")
    if len(replacement) != len(search):
        if len(replacement) < len(search):
            replacement = replacement + b" " * (len(search) - len(replacement))
        else:
            replacement = replacement[: len(search)]
    count = 0
    patches = []
    off = 0
    while True:
        pos = data.find(search, off)
        if pos < 0:
            break
        data[pos : pos + len(search)] = replacement
        patches.append((pos, len(search), search.decode("latin-1", errors="replace")[:40]))
        count += 1
        off = pos + len(search)
    return count, patches


def telemetry_replacement(orig):
    repl = orig.replace("Record", "Void").replace("record", "void")
    if "trajectory" in orig.lower():
        repl = repl.replace("trajectory", "disabled").replace("Trajectory", "Disabled")
    if "sentry" in orig.lower():
        repl = repl.replace("sentry", "local").replace("Sentry", "Local")
    return repl


def analytics_replacement(orig):
    """An unresolvable host that fits the original's byte budget.

    void.local for normal domains; shorter non-resolving hosts for short
    originals (sentry.io, datadog) so nothing is ever truncated. Never an
    IP literal — 0.0.0.0 would route to localhost on some stacks.
    """
    n = len(orig)
    if n >= 10:
        return "void.local"
    if n == 9:
        return "void.none"
    return "no.host"


def validate_targets(cfg):
    """Fail fast on explicit replacement pairs that cannot fit.

    Same-length patching cannot grow a string: Go string headers carry an
    explicit length, protobuf descriptors are length-prefixed, and rodata
    strings are packed back-to-back. An over-length replacement is silently
    truncated at patch time (historically mid-word), so refuse to run until
    the config is fixed. Rule-derived sections (telemetry/analytics) are
    excluded: their replacements are computed, and truncation there is by
    design (e.g. void.local against a shorter domain).
    """
    violations = []
    for section_key, _title, _ptype in SECTION_DEFS:
        if section_key in ("telemetry_functions", "analytics_endpoints"):
            continue
        section = cfg.get(section_key)
        if not section:
            continue
        if isinstance(section, dict):
            pairs = list(section.items())
        else:
            pairs = [
                (item[0], item[1]) for item in section if isinstance(item, (list, tuple))
            ]
        for orig, repl in pairs:
            if len(repl.encode("latin-1", errors="replace")) > len(
                orig.encode("latin-1", errors="replace")
            ):
                violations.append((section_key, orig, repl))
    return violations


def iter_targets(section, rule=None):
    """Yield (orig, repl) pairs from a targets.json section, longest first.

    Dict sections map orig -> repl directly. List sections hold either
    [orig, repl] pairs (semantic_blocks) or bare strings whose replacement
    is derived by the section rule (telemetry/analytics).

    Sorting by descending orig length is required: when one target is a
    substring of another (e.g. RecordPrompts inside BatchRecordPrompts),
    patching the shorter one first rewrites the longer one's bytes and the
    longer target then never matches.
    """
    if not section:
        return
    if isinstance(section, dict):
        items = list(section.items())
    else:
        items = []
        for item in section:
            if isinstance(item, (list, tuple)):
                items.append((item[0], item[1]))
            else:
                items.append((item, rule(item) if rule else item))
    for orig, repl in sorted(items, key=lambda pair: len(pair[0]), reverse=True):
        yield orig, repl


def snippet_at(original, pos, width=110):
    lo, hi = max(0, pos - 30), min(len(original), pos + width)
    return "".join(chr(b) if 32 <= b < 127 else "\xb7" for b in original[lo:hi])


def suggest_variants(original, keyword, max_hits=3):
    """Find windows of a missed keyword that DO exist in the binary.

    When upstream rewords a string (new format verbs, different phrasing),
    the unchanged fragments still hit. Returning their offsets gives the
    operator a direct pointer at the renamed variant.
    """
    clues = []
    if len(keyword) < 12:
        return clues
    seen = set()
    for start in range(0, len(keyword) - 11, 8):
        window = keyword[start : start + 12]
        pos = original.find(window.encode("latin-1"))
        if pos >= 0 and pos not in seen:
            seen.add(pos)
            clues.append((window, pos))
            if len(clues) >= max_hits:
                break
    return clues


def is_macho(path):
    with open(path, "rb") as f:
        return f.read(4) in MACHO_MAGICS


# ---------------------------------------------------------------------------
# Hunt mode: discover restriction strings that no current target covers.
# ---------------------------------------------------------------------------

# Substrings matched (case-insensitively) against identifier-like runs
# (ALL_CAPS enums, snake_case fields, dash-flags, CamelCase symbols).
IDENT_VOCAB = (
    "PROHIB", "FORBID", "DENY", "DENIED", "REFUS", "RESTRICT", "BLOCKLIST",
    "DENYLIST", "BLOCK_", "_BLOCK", "THRESHOLD", "FILTER", "GUARDIAN",
    "POLICY_", "_POLICY", "CONSENT", "UNSAFE", "SAFETY_", "_SAFETY", "HARM",
    "MALIC", "CENSOR", "MODERAT", "SANDBOX", "PERMISSION", "ALLOWLIST",
    "QUOTA", "VETO", "CAPTCHA", "BYPASS", "GAVS",
)

# Substrings matched against sentence-like runs (contain spaces). A sentence
# candidate must ALSO carry an instruction marker so Go library error strings
# ("cannot allocate memory") stay out of the report.
SENTENCE_VOCAB = (
    "prohibited", "forbidden", "denied", "restricted", "restriction",
    "not allowed", "not permitted", "must not", "MUST NOT", "MUST STOP",
    "NEVER", "Do not ", "DO NOT ", "do not ", "cannot ", "can't ",
    "unable to", "safety", "unsafe", "harmful", "malicious", "captcha",
    "bypass", "guardian", "confidential", "refuse", "without explicit",
    "ask for permission", "ask the user", "seek permission", "stop and",
)
SENTENCE_MARKERS = ("you", "You", " I ", "user", "operator", "agent", "model")

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")
ENUM_RE = re.compile(r"[A-Z][A-Z0-9_]{5,}")
PRINTABLE_RE = re.compile(rb"[ \x21-\x7e]{8,}")


def classify_run(text):
    """'enum' | 'flag' | 'snake' | 'symbol' | 'sentence' | None."""
    if " " in text:
        return "sentence"
    if not IDENT_RE.fullmatch(text):
        return None
    if ENUM_RE.fullmatch(text):
        return "enum"
    if "-" in text:
        return "flag"
    if "_" in text:
        return "snake"
    if text != text.lower() and text != text.upper():
        return "symbol"
    return None


def hunt(binary_path, config_path, report_path="hunt_report.json"):
    with open(binary_path, "rb") as f:
        data = f.read()
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # Strings already covered by any current target (orig) or already patched
    # (repl, so hunting a patched binary still filters correctly).
    covered = set()
    for section_key, _title, _ptype in SECTION_DEFS:
        rule = (
            telemetry_replacement
            if section_key == "telemetry_functions"
            else analytics_replacement
            if section_key == "analytics_endpoints"
            else None
        )
        for orig, repl in iter_targets(cfg.get(section_key), rule):
            covered.add(orig)
            covered.add(repl)

    counts = Counter()
    first_off = {}
    for m in PRINTABLE_RE.finditer(data):
        text = m.group().decode("latin-1")
        if len(text) > 4096:
            continue
        counts[text] += 1
        if text not in first_off:
            first_off[text] = m.start()

    buckets = {"enum": [], "flag": [], "snake": [], "symbol": [], "sentence": []}
    for text, count in counts.items():
        kind = classify_run(text)
        if kind is None:
            continue
        if any(needle in text for needle in covered):
            continue
        low = text.lower()
        if kind == "sentence":
            if not any(marker in text for marker in SENTENCE_MARKERS):
                continue
            if not any(token.lower() in low for token in SENTENCE_VOCAB):
                continue
        else:
            if not any(token.lower() in low for token in IDENT_VOCAB):
                continue
            # Skip protobuf descriptor-qualified names we can't cleanly rename.
            if text.count(".") > 2:
                continue
        buckets[kind].append((count, first_off[text], text))

    titles = {
        "enum": "Enums / Constants",
        "flag": "Flags (dash-case)",
        "snake": "Fields (snake_case)",
        "symbol": "Symbols (CamelCase)",
        "sentence": "Instruction / refusal sentences",
    }
    print(f"[HUNT] {binary_path}")
    print(f"  [+] Scanning {len(data):,} bytes for uncovered restriction vocabulary...\n")
    report = {}
    for kind in ("enum", "flag", "snake", "symbol", "sentence"):
        entries = sorted(buckets[kind], key=lambda e: (-e[0], e[2]))
        report[kind] = [
            {"count": c, "offset": off, "text": t} for c, off, t in entries
        ]
        shown = min(len(entries), 60 if kind == "sentence" else 40)
        print(f"  [{titles[kind]}] — {len(entries)} candidates")
        for count, off, text in entries[:shown]:
            label = text if len(text) <= 100 else text[:97] + "..."
            print(f"    {count:4d}x @0x{off:<8x} {label}")
        if len(entries) > shown:
            print(f"    ... and {len(entries) - shown} more in {report_path}")
        print()
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"  [+] Full report: {report_path}")
    print("  [+] Hunt complete. Nothing was modified.")


def show_context(binary_path, needle, width=400, limit=10):
    """Inspect every occurrence of a substring before authoring a replacement.

    For each hit: prints a printable rendering of the surrounding bytes, and
    the maximal printable run containing the hit — that run's length is the
    byte budget any same-length replacement must respect. This is the
    authoring workflow for semantic_blocks entries: look at the document
    around the string, write a replacement of equal-or-shorter length, add
    the [orig, repl] pair to targets.json, then verify with --check.
    """
    with open(binary_path, "rb") as f:
        data = f.read()
    raw = needle.encode("latin-1", errors="replace")
    print(f"[CONTEXT] {binary_path}")
    print(f"  [+] Needle: {needle!r} ({len(raw)} bytes), window +/-{width}\n")
    hits = []
    off = 0
    while len(hits) < limit:
        pos = data.find(raw, off)
        if pos < 0:
            break
        hits.append(pos)
        off = pos + 1
    total = data.count(raw)
    if not hits:
        extra = b""
        low = data.lower()
        pos = low.find(raw.lower())
        if pos >= 0:
            extra = data[max(0, pos - 40) : pos + 80]
        hint = f" (case-insensitive near-match: {extra!r})" if extra else ""
        print(f"  [!] No exact hits.{hint}")
        return
    print(f"  [+] {total} hit(s), showing {len(hits)}\n")
    for pos in hits:
        # Maximal printable run containing the hit = same-length budget.
        lo = pos
        while lo > 0 and 32 <= data[lo - 1] < 127:
            lo -= 1
        hi = pos + len(raw)
        while hi < len(data) and 32 <= data[hi] < 127:
            hi += 1
        run_len = hi - lo
        w_lo, w_hi = max(0, pos - width), min(len(data), pos + width)
        window = "".join(chr(b) if 32 <= b < 127 else "\xb7" for b in data[w_lo:w_hi])
        print(f"  --- @0x{pos:x} (run budget {run_len} bytes) " + "-" * 30)
        print(f"  {window}\n")


def reseal_macho(path):
    """Ad-hoc sign a patched Mach-O so macOS will load it.

    Byte edits kill the original Developer ID signature. Hardened runtime is
    kept (`--options runtime`) because the stock agy binary is sealed that way
    and ships with an empty entitlement set.
    """
    if sys.platform != "darwin" or not is_macho(path):
        return
    os.chmod(path, 0o755)
    subprocess.run(
        ["xattr", "-d", "com.apple.quarantine", path],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cmd = ["codesign", "--force", "--sign", "-", "--options", "runtime", path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        print(f"  [ERROR] codesign failed: {detail}")
        sys.exit(1)
    print("  [+] macOS ad-hoc signature applied (hardened runtime)")


class Patcher:
    def __init__(self, binary_path, config_path, report_path="patch_report.json", check_only=False, output_path=None):
        self.binary_path = binary_path
        self.config_path = config_path
        self.report_path = report_path
        self.check_only = check_only
        self.output_path = output_path
        self.total_patches = 0
        self.matched_keywords = 0
        self.missed_keywords = []
        self.orig_hash = None
        self.new_hash = None

    def run(self):
        bin_path = self.binary_path
        bak_path = bin_path + ".original"
        if not os.path.exists(bin_path):
            print(f"[!] Binary not found: {bin_path}")
            sys.exit(1)
        if not os.path.exists(self.config_path):
            print(f"[!] Config not found: {self.config_path}")
            sys.exit(1)

        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        violations = validate_targets(cfg)
        if violations:
            print(
                f"[!] {len(violations)} replacement(s) exceed their original's length — "
                "same-length patching cannot grow a string:"
            )
            for section_key, orig, repl in violations:
                print(
                    f"    [{section_key}] {orig!r} ({len(orig)}B) -> {repl!r} ({len(repl)}B)"
                    f" — shorten the replacement to at most {len(orig)} bytes"
                )
            sys.exit(1)

        if self.check_only:
            src = bak_path if os.path.exists(bak_path) else bin_path
            print(f"[0] CHECK MODE (dry-run, no bytes modified)")
            print(f"  [+] Analyzing: {src}")
            with open(src, "rb") as f:
                original = f.read()
        elif self.output_path:
            # Side-by-side: the source is never modified. Patch from the
            # pristine backup when one exists so re-running against an
            # already-patched path still produces a clean copy.
            src = bak_path if os.path.exists(bak_path) else bin_path
            print("[1] SIDE-BY-SIDE MODE")
            print(f"  [+] Source (untouched): {src}")
            print(f"  [+] Patched copy:       {self.output_path}")
            with open(src, "rb") as f:
                original = f.read()
        else:
            print("[1] BACKUP")
            if not os.path.exists(bak_path):
                shutil.copy2(bin_path, bak_path)
                print(f"  [+] Backup created: {bak_path}")
            else:
                print(f"  [+] Backup exists: {bak_path}")
            with open(bak_path, "rb") as f:
                original = f.read()

        self.orig_hash = hashlib.sha256(original).hexdigest()
        print(f"  [+] Original SHA256: {self.orig_hash[:16]}...")

        data = bytearray(original)
        orig_size = len(data)
        print(f"  [+] Original size: {orig_size:,} bytes ({orig_size / 1024 / 1024:.1f} MB)")

        all_patches = []

        print("\n[2] EXACT-MATCH REPLACEMENTS")
        for section_key, section_name, patch_type in SECTION_DEFS:
            if section_key == "telemetry_functions":
                rule = telemetry_replacement
            elif section_key == "analytics_endpoints":
                rule = analytics_replacement
            else:
                rule = None
            print(f"  [{section_name}]")
            for orig, repl in iter_targets(cfg.get(section_key), rule):
                if repl == orig:
                    self.missed_keywords.append((section_key, orig))
                    print(f"    ?? : {orig}   [RULE PRODUCED NO CHANGE - SKIPPED]")
                    continue
                if len(repl.encode("latin-1", errors="replace")) > len(orig.encode("latin-1", errors="replace")):
                    print(f"    !! : {orig}   [REPLACEMENT LONGER THAN ORIGINAL - WILL BE TRUNCATED]")
                n, patches = find_and_replace_exact(data, orig, repl)
                if n:
                    self.matched_keywords += 1
                    print(f"    {n}x: {orig} -> {repl}")
                    all_patches.extend(
                        {"off": item[0], "len": item[1], "type": patch_type, "desc": f"{orig}->{repl}"}
                        for item in patches
                    )
                else:
                    self.missed_keywords.append((section_key, orig))
                    label = orig if len(orig) <= 76 else orig[:73] + "..."
                    print(f"    -- : {label}   [NO MATCH]")
                    for window, pos in suggest_variants(original, orig):
                        print(f"         ~ variant clue ({window!r}): {snippet_at(original, pos)}")

        print(f"\n  Keyword coverage: {self.matched_keywords} matched, {len(self.missed_keywords)} no-hit")

        if self.check_only:
            print("\nCheck complete. No bytes were modified.")
            return

        print("\n[3] INTEGRITY VERIFICATION")
        final_size = len(data)
        if final_size != orig_size:
            print(f"  [ERROR] Size changed: {orig_size:,} -> {final_size:,}")
            sys.exit(1)
        print(f"  [OK] Size preserved: {final_size:,} bytes")

        print("\n[4] WRITING PATCHED BINARY")
        write_path = self.output_path or bin_path
        out_dir = os.path.dirname(os.path.abspath(write_path))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(write_path, "wb") as f:
            f.write(data)
        os.chmod(write_path, 0o755)
        print(f"  [+] Written: {write_path}")
        reseal_macho(write_path)

        with open(write_path, "rb") as f:
            sealed = f.read()
        self.new_hash = hashlib.sha256(sealed).hexdigest()
        sealed_size = len(sealed)
        if sealed_size != orig_size:
            print(f"  [+] Signature blob resized the file: {orig_size:,} -> {sealed_size:,} bytes")
        print(f"  [+] SHA256: {self.orig_hash[:16]}... -> {self.new_hash[:16]}...")

        self.total_patches = len(all_patches)
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "binary": os.path.abspath(write_path),
                    "patches": all_patches,
                    "count": self.total_patches,
                    "matched_keywords": self.matched_keywords,
                    "missed_keywords": [
                        {"section": s, "keyword": k} for s, k in self.missed_keywords
                    ],
                    "orig_hash": self.orig_hash,
                    "new_hash": self.new_hash,
                },
                f,
                indent=2,
            )
        print(f"  [+] Report: {self.report_path}")
        print(f"\n  Total patches: {self.total_patches}")
        print("\nDone.")


def main():
    parser = argparse.ArgumentParser(description="Exact-match binary patcher for the Antigravity CLI")
    parser.add_argument("binary_path", help="path to agy / antigravity / antigravity.exe")
    parser.add_argument("config_path", nargs="?", default="targets.json", help="path to targets.json")
    parser.add_argument("--check", action="store_true", help="dry-run: report hit/miss per keyword, modify nothing")
    parser.add_argument("--hunt", action="store_true", help="scan for restriction strings not covered by targets.json")
    parser.add_argument("--context", metavar="NEEDLE", help="show the surrounding prompt text for a substring (authoring aid for replacements)")
    parser.add_argument("--output", "-o", metavar="PATH", help="write the patched copy to PATH and leave the source binary untouched")
    parser.add_argument("--report", default=None, help="report output path (default: patch_report.json, or hunt_report.json for --hunt)")
    args = parser.parse_args()
    if args.context is not None:
        show_context(args.binary_path, args.context)
        return
    if args.hunt:
        hunt(args.binary_path, args.config_path, args.report or "hunt_report.json")
        return
    Patcher(
        args.binary_path,
        args.config_path,
        args.report or "patch_report.json",
        check_only=args.check,
        output_path=args.output,
    ).run()


if __name__ == "__main__":
    main()
