# KEYWORD DRIFT — 1.0.9 → 1.2.14

Why keywords stop matching when Google ships a new AGY build, measured on the
official `agy_cli_mac_arm64.tar.gz` 1.2.14 (2026-09-30, SHA-256
`a33fdf084ecd199df00694f35a243200a3efacb1f4f3adf04ca19d76f7f714c4`).

`targets.json` was authored against Windows PE 1.0.9. Against macOS 1.2.14 the
original file matched **81/104** keywords. After the 1.2.14 additions below it
matches **94/120**; the 26 remaining no-hits are dead pre-1.2 names kept so the
config still works on older builds. Total exact hits: **1,682** (was 1,686 —
the old count included 4 self-replacing no-ops, see "Bug fixes").

Diagnose any future drift with:

```bash
python3 tools/agy_domesticate.py "$(which agy)" tools/targets.json --check
```

## A. Renamed upstream — fixed in targets.json

| 1.0.9 keyword | 1.2.14 reality | Action |
|---|---|---|
| `PHISH_BLOCK_THRESHOLD_LOW` / `_MEDIUM` / `_HIGH` | Phish enum now uses Gemini-style values: `BLOCK_LOW_AND_ABOVE`, `BLOCK_MEDIUM_AND_ABOVE`, `BLOCK_HIGH_AND_ABOVE`, `BLOCK_HIGHER_AND_ABOVE`, `BLOCK_VERY_HIGH_AND_ABOVE`, `BLOCK_ONLY_EXTREMELY_HIGH` (4 hits each, v1beta + v1main descriptors) | Added all six, `BLOCK_*` → `PASS_*` |
| `HARM_BLOCK_THRESHOLD_UNSPECIFIED` | HarmBlockThreshold enum present alongside phish | Added → `HARM_BLOCK_THRESHOLD_PERMISSIVE` |
| `BatchRecordGitTelemetry` | RPC renamed `BatchRecordPrompts` (`/exa.analytics_pb.AnalyticsService/BatchRecordPrompts`) | Added |
| `reference of type must not have a URI set` | Go format verb added: `reference of type %q must not have a URI set` (2 hits) | Added %q form |
| `subagents cannot receive messages` | Reworded: `subagents cannot be killed here`, `so subagents cannot be launched`, `its subagents cannot be resolved` (internal-error fmt strings) | Added all three |
| `ESSENTIAL_USE_CONSENT_STATE_UNRESTRICTED` | Now `ESSENTIAL_USE_CONSENT_STATE_UNSPECIFIED` | Added |
| `START_MENU_PINNING_STATUS_USER_DECLINED` / `TASKBAR_PINNING_STATUS_USER_DECLINED` | Refactored into one cross-platform enum: `PINNING_STATUS_USER_DECLINED`, `PINNING_STATUS_NOT_SUPPORTED`, `PINNING_STATUS_ERROR` — present on macOS now | Added all three |

The `BLOCK_*` names are shared between `PhishBlockThreshold` and
`HarmBlockThreshold` (and the aiplatform `SafetySetting` copies), so the
`BLOCK_*` → `PASS_*` rows hit 10/6/4× across both layers at once. The
permissive values `BLOCK_NONE` and `OFF` are deliberately **not** targets —
renaming them would break the "don't block" switch itself.

## B. Removed upstream — no-hit is correct, kept for old builds

- `You cannot open new pages or navigate to external URLs`
- `If you fail to view a file because it is not in your allowlist`
- `you should NOT open the file in the browser to bypass this restriction`
- `failed to get page metadata`
- `extremely vague context` / `Extremely vague context`
- `EVAL_TYPE_INSTRUCTION_AUTOCOMPLETE` (autocomplete eval layer deleted; remaining autocomplete enums are `AUTOCOMPLETE_SPEED_*` speed knobs, not restrictions)
- `FORBIDDEN`, `_DENY_LIST` (only suffixed forms `_FORBIDDEN`, `_DENIED` remain)
- `RecordPrompts` standalone (every occurrence is now part of `BatchRecordPrompts`; the longer target covers it)

## C. Telemetry domains gone — new pipeline is Google-internal OTel

`sentry.io`, `api.amplitude.com`, `api.mixpanel.com`, `logs.segment.com`,
`loggly.com`, `datadoghq.com`, `datadog` — zero hits on 1.2.14. The binary now
ships an OpenTelemetry pipeline (`opentelemetry` ×1,108 — already a target) plus
`exa.analytics_pb` service calls (`Record*`/`BatchRecord*` targets cover the
methods) and one dependency-scanning host:

- `owners-stage.mistable.com` (`[Degraded (FAIL-CLOSED)]`) — added to analytics endpoints

## D. New in 1.2.14 — policy guardian layer

A tool-level guard not present in 1.0.9, now covered in `semantic_blocks`:

- `policy_guardian_verify` → `policy_guardian_bypass`
- `policy_guardian_post_tool` → `policy_guardian_allowall`
- `policy_guardian_gavs_check` → `policy_guardian_gavs_okay`
- `guardian-denied-repeat` → `guardian-passed-repeat`
- `rpc-telemetry-allowlist` → `rpc-telemetry-voidlist`

The bare word `policy_guardian` (15 hits) is deliberately untouched — too short,
matches package/path fragments.

Related strings found but **not** targeted (renaming them does not unblock
anything, they are result markers / fmt messages): `FinishReason` values
(`SAFETY`, `RECITATION`, `BLOCKLIST`, `PROHIBITED_CONTENT`, `SPII`,
`IMAGE_SAFETY`…), `Package is malicious (%s)`, `Version is malicious (%s)`.

## Bug fixes surfaced by the drift

1. **Substring shadowing.** Go name tables concatenate symbols without
   separators, so `RecordPrompts` lives inside `BatchRecordPrompts`. Patching
   the shorter target first rewrites the longer one's bytes and the longer
   target can never match. All sections are now sorted longest-first.
2. **Telemetry rule chain reset.** Each rule branch re-derived the replacement
   from `orig` instead of chaining, and the sentry branch matched the
   case-insensitive test (`UpdatesEntry` lowercases to `…sentry`) but replaced
   only literal `sentry` — net effect: `StepScopedSubtrajectoryUpdatesEntry`
   silently patched as a no-op. Rules now chain from the running replacement.
3. **Silent misses.** The patcher only printed hits; misses were invisible,
   which is why version drift looked like "keywords not matching" with no
   cause. Misses now print `[NO MATCH]` plus a variant-clue snippet, are
   counted in the coverage line, and land in `patch_report.json`.
4. **No-op self-replacements.** Non-telemetry names dumped into
   `telemetry_functions` (`GetImageGeneration`, `list_browser_pages`,
   `browser_move_mouse`, `browser_scroll_dom`, `browser_mouse_down`,
   `send_command_input`, `Custom action name`) produced `orig -> orig`
   replacements that inflated the old patch count (1,686 → honest 1,682) and
   did nothing. Removed — renaming browser tool names would *disable* tools,
   the opposite of the project's goal.

## E. Hunt pass (2026-10-01) — layers the original catalog never covered

A `--hunt` scan (restriction vocabulary vs. every covered string) surfaced 198
enum / 530 field / 795 symbol / 700 sentence candidates. Triaged additions —
36 new keywords, all confirmed hitting 1.2.14:

| Layer | Keywords |
|---|---|
| Harm categories (new) | `HARM_CATEGORY_IMAGE_HARASSMENT`, `HARM_CATEGORY_IMAGE_HATE`, `HARM_CATEGORY_JAILBREAK` |
| Agent monitor (`gdm.security.agi_control.agent_monitoring.monitors`) | `DENY_BY_DEFAULT` → `OPEN_BY_DEFAULT`, `SOFT_BLOCK_INJECT` → `SOFT_PASS_INJECT` |
| File access policy | `FILE_ACCESS_POLICY_ALWAYS_ASK` / `_DENY` / `_UNSPECIFIED` (permissive `_NOT_ENFORCED` untouched) |
| Policy decisions | `POLICY_DECISION_ASK_USER`, `POLICY_DECISION_DENY`, `POLICY_EVALUATION_OUTCOME_DENY` (permissive `_ALLOW` untouched) |
| Agent setting policy | `AGENT_SETTING_POLICY_ASK`, `AGENT_SETTING_POLICY_DENY` |
| Auto-run decisions | `AUTO_RUN_DECISION_{USER,SYSTEM,MODEL,DEFAULT}_DENY` |
| Safe-browsing RPCs (`google.internal.cloud.code.v1internal`) | `CheckUrlDenylist`, `CheckUrlAntivirus` + lowercase HTTP-path forms `checkUrlDenylist` / `checkUrlAntivirus` (29–30 hits each) |
| Workspace blocking reasons | `BLOCK_REASON_GITIGNORED`, `BLOCK_REASON_OUTSIDE_WORKSPACE`, `BLOCK_REASON_UNSPECIFIED` |
| Image generation | `BLOCK_PROMINENT_PEOPLE` (permissive `ALLOW_PROMINENT_PEOPLE` untouched) |
| Completion filters | `TAB_JUMP_FILTER_*` family (caps/whitespace/selection/revert), `TAB_JUMP_FILTERED`, `SUPERCOMPLETE_FILTERED` |
| Misc | `CASCADE_ENFORCE_QUOTA`, `unallowed_env_var`, `guardian-verify` |

Result on 1.2.14: **1,811** patches, **130/156** keywords, boots, `--version` OK.

### Deliberately NOT touched (checked context, wrong direction or wrong layer)

- **Anti-overblocking instruction doc** — "INCORRECT examples (DO NOT make
  these mistakes): Denying `ls /` because …" teaches the permission model to
  *stop* denying benign commands. Patching it would increase refusals.
- **Permissive enum values** — `BLOCK_NONE`, `OFF`, `NO_RESTRICTION`,
  `FILE_ACCESS_POLICY_NOT_ENFORCED`, `POLICY_DECISION_ALLOW`,
  `POLICY_EVALUATION_OUTCOME_ALLOW`, `ALLOW_PROMINENT_PEOPLE`,
  `ALLOW_BY_DEFAULT`, `NON_BLOCKING`. These are the "don't block" switches;
  renaming them breaks the off position.
- **Response-side markers** — `FinishReason` values (`SAFETY`, `RECITATION`,
  `BLOCKLIST`, `PROHIBITED_CONTENT`, `SPII`, `IMAGE_SAFETY`),
  `HARM_SEVERITY_*`, `STOP_REASON_CONTENT_FILTER`,
  `CONTENT_STATUS_BLOCKED_CONTENT`, `FILTER_REASON_*`: renaming how the client
  *labels* a block does not unblock it and risks corrupting response handling.
- **Google-internal logging enums** — `ST_*`, `STREAMZ_*`, `*_PRIMES`,
  `RECAPTCHA*`, `GUARDIAN_{WOLF,VULCAN,MERCURY,…}` (product codenames for
  metrics streams), `TRUST_SAFETY_*`, `PERMISSION_*` (team/role RBAC on the
  web console), `CONSENT_CHOICE_*`, `RESOLUTION_POLICY_*`.
- **Sentinel keys** — `sandboxAllowNetworkSentinelKey`,
  `browser_allowlist_sentinel_key`: fail direction unknown; renaming could
  harden instead of loosen. Candidates for a runtime experiment, not a blind
  byte patch.
- **Sandbox config fields** — `enable_sandbox`, `enable_terminal_sandbox`,
  `sandbox_override`, `allow_sandbox_app_deployments`: the sandbox is local
  user security, not censorship.
- **Monitor protobuf message names** — `MonitorsConfig`, `ActionAllowlist`,
  `SubcommandAllowlist`, `FlagAllowlist`: breaking server-pushed config
  parsing risks hard crashes rather than graceful degradation; the enum
  values inside them are patched instead.
- **Orchestration prompt sentences** (700 candidates) — the vast majority are
  teamwork/math-verification discipline ("Never skip step 1", "Do not accept
  vague references"), not content restrictions.
- **PolicyGuardian verdict prompt** — the embedded guardian prompt defines
  genuinely dangerous behavior (hacking, persistence, credential theft) for a
  security monitor; its plumbing (`policy_guardian_*` event names) is patched,
  the prompt text is not.

## Tooling

- `agy_domesticate.py <bin> targets.json --check` — dry-run coverage report,
  no bytes modified, no backup created.
- `agy_domesticate.py <bin> targets.json --hunt` — scan for restriction
  vocabulary (identifier + sentence heuristics) not covered by any target,
  print categorized candidates, write `hunt_report.json`. Run this first when
  a new AGY version ships.
- `auto_uncensor.py --check` — download the latest official release, run the
  same coverage report, produce no binary.
- `auto_uncensor.py --refresh-targets` — re-download `targets.json`.
- Variant clues: for every miss, unchanged 12-char windows of the keyword are
  searched in the binary and their context printed — a renamed string shows
  itself immediately (this is exactly how every row in section A was found).
