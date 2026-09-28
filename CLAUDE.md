# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Elderward is a **single-file** PHP malware scanner and cleanup utility for compromised WordPress sites, aimed at incident responders. Everything lives in `elderward.php` — no dependencies, no build system, no test framework. It must run on locked-down shared hosting: target **PHP 5.6+ compatibility** (no typed properties, arrow functions, or null coalescing), assume curl/zip/zlib extensions may be absent and degrade gracefully.

## Commands

```sh
php -l elderward.php                 # lint — run after every change
php elderward.php help=1            # list all scan modes and options
```

There is no test suite. Testing is done by building synthetic fixtures (a fake WordPress root, tampered files, crafted access logs, offline checksum manifests/zips via `checksumdir=`) in a scratch directory and asserting on the output — see `TESTPLAN.md` for the canonical fixtures and expected results, including the live wordpress.org API tests that can only run on a networked machine. Every scanner must be exercised with both a positive case and its false-positive negatives (e.g. a legitimate plugin update must not trip the timestamp outlier check).

Options are passed as `key=value` CLI args, which are parsed into `$_GET` (the same script runs over HTTP, gated by `WEB_ACCESS_TOKEN`). Scan modes are mutually exclusive; the first matching mode in the dispatch block runs and `die()`s.

## Architecture

One file, three layers:

1. **Signature data** — three arrays, all compile-checked at startup by `lint_signatures()` (a malformed regex exits non-zero naming the signature; a pattern that silently never matches is the worst failure mode):
   - `$CLEANUP_SIGNATURES`: keyed by unique signature name; each has `prefilter` (cheap check, counts as evidence), `triggers` (ALL must also match), and one `action` (`remove_regex` or `delete_file`). Full PCRE with delimiters/flags everywhere.
   - `$ACCESS_LOG_SIGS`: per-line log patterns with a `threshold` (volume-based signatures like wp-login floods only report above it) and optional `severity` (default MEDIUM; HIGH means traffic to a shell already on disk).
   - `$CRONTAB_SIGS`: name => pattern pairs.
2. **Engine helpers** — `pattern_matches`/`signature_matches`/`apply_action` (file cleanup), `verify_against_manifest` + zip acquisition/restore helpers (integrity), clustering in `analyze_time_group` (timestamps).
3. **Scan modes** — default recursive cleanup scan, `scancron`, `scanlog` (+`correlate`), `scanintegrity` (+`restore`, `quarantinedir`, `checksumdir` offline mode), `scantimes`, `quickscan`.

All scanners report through `report_finding($severity, $type, $path, $detail)` printing `SEVERITY,TYPE,path,detail` — severities HIGH/MEDIUM/LOW/INFO/ERROR; indented lines under a finding are supporting context. Keep this contract: users pipe the output into grep/tickets.

## Invariants — do not break these

- **Fail closed**: only `preg_match(...) === 1` counts as a match; engine errors (`false`) and unknown condition/action types never flag or clean a file.
- **`dryrun=1` must cover every destructive action** (writes, deletes, restores). A dry run that touches disk is a P0 bug — this happened once with `DELETE_FILE`.
- **Restore safety**: content is byte-verified against the reference checksum manifest before writing (a tampered package zip must be refused); `INTEGRITY_EXTRA` files are never deleted or overwritten; failed quarantine aborts the overwrite; writes go through `write_cleaned_file` (temp file + rename, never truncate in place).
- **Heuristics are report-only**: timestamp and correlation findings must never feed a cleanup or restore action, and their output says "leads, not proof".
- **Never disable TLS verification** — the tool runs on already-compromised hosts; an "all clean" answer must not be attacker-supplied. Treat API responses and everything read from the scanned host (filenames, log lines, file contents) as hostile data.
- **Memory/scale**: logs are streamed line-by-line, zips streamed to disk, per-minute bucketing bounds correlation memory. The script advertises a 96M limit; don't buffer unbounded input.
- False positives get downgraded with an explanation (`$INTEGRITY_KNOWN_BENIGN`, hex-filename annotation), not silently suppressed — an attacker can hide behind any known-benign name.

## Style

Procedural PHP matching the existing file: `////` banner comments for sections, snake_case helpers (a few legacy camelCase `scanX` entry points), explicit `return (...)`, Yoda-ish comparisons (`false === $x`), errors suppressed with `@` only where the failure is handled on the next line.
