# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Elderward is a malware scanner and incident-response toolkit for compromised WordPress sites, shipped as a **WordPress plugin** (this repo is the plugin folder, slug `elderward`) whose scanning engine also runs as a **standalone CLI** with no WordPress. Audience: incident responders. It must run on locked-down shared hosting and degrade gracefully when curl/zip/zlib/mysqli are missing.

Layout:

- `elderward.php` — plugin main file (headers, constants, requires, hooks). PHP 7.2+.
- `includes/engine/` — the engine, namespace `Elderward\Engine`, **PHP 5.6 syntax** (no `??`, typed properties, arrow functions, `fn`), **no WordPress functions**, no `$_GET`, no `echo`, no `exit`. Loaded by `includes/engine/load.php`.
- `includes/plugin/` — WordPress side (PHP 7.2+): `Elderward_Plugin` (bootstrap, table, `make_context()`), `Elderward_WP_Http` (WordPress HTTP API adapter), `Elderward_WP_Db` (`$wpdb` adapter), `Elderward_Job` + `Elderward_Store_Reporter` (resumable admin scan), `Elderward_Admin` (Tools page, ajax, export), `Elderward_CLI` (WP-CLI).
- `bin/elderward.php` — standalone CLI entry (`php bin/elderward.php key=value ...`); refuses non-CLI SAPIs.
- `tests/` — `regress.sh` (old-vs-new output diff), `chunking.php` (resumability), `admin-ui.js` (Playwright). No PHPUnit.

## Commands

```sh
php -l <file>                                # lint — run after every change
php bin/elderward.php help=1                 # CLI options
tests/regress.sh [old-ref]                   # must report failed=0 (DB cases need the MariaDB fixture; see TESTPLAN E)
php tests/chunking.php /path/to/wp-root      # must print IDENTICAL
composer install && composer phpcs           # WordPress security/DB/WP sniffs + PHPCompatibilityWP: must be clean
```

Testing is done by building synthetic fixtures (fake WordPress root, tampered files, crafted logs, offline manifests via `checksumdir=`) and asserting on the output; `TESTPLAN.md` is the canonical list, including the live wordpress.org API tests and the plugin tests (section F) that need a real WordPress install. Every scanner needs a positive case and its false-positive negatives.

## Engine contracts

- **Context** (`context.php`) carries the options (same `key=value` names as the CLI: `scandirectory`, `dryrun`, `allfiles`, `scanlog`, `correlate`, `window`, `checksumdir`, `locale`, `restore`, `quarantinedir`, `format`), the Reporter, the `Http` and `Db` adapters, `plugin_dir` (never scanned), `work_dir`, and an optional `deadline`. Read options with `$ctx->has()/get()`; derive variants with `$ctx->with()`.
- **Reporter** (`reporter.php`) is the only output path: `finding($severity,$type,$path,$detail,$context)`, `summary($scan,$data,$text)`, `progress($text)`, `fatal($message)`, `exit_code()`. `TextReporter` prints `SEVERITY,TYPE,path,detail` (attacker-controlled fields percent-encoded, context indented) and buffers for scanall's severity-sorted flush; `JsonReporter` prints NDJSON events on stdout and progress to STDERR; the plugin's `Elderward_Store_Reporter` writes to the findings table. Never `echo` from a scanner.
- **Fatal** (usage errors, unreadable targets, non-WordPress root, standalone DB failure) is thrown, never exited; entry layers catch it and present it (text `Error: ...`, JSON `{"event":"error"}`, WP-CLI halt 1, admin job `failed`).
- **Admin job** (`Elderward_Job`): the attempt record is saved *before* a unit runs and a unit started more than `MAX_ATTEMPTS` times fails the job; a PHP fatal inside a step is recorded through the `wp_php_error_message` filter (WordPress's own fatal handler dies before any later shutdown function). A unit must always make progress (byte offset, primary key, range end) or the attempt counter will stop it.
- **Scanner** (`scanner.php`): `init_state()`, `plan(&$state)` → list of serialisable units, `run($unit, &$state)` → `null` or unit(s) to run next, `finish(&$state)`. Units and state are plain arrays so the admin job can persist them between requests; a scanner checks `$ctx->out_of_time()` and returns a continuation unit (byte offset, primary key, file-list position) instead of blocking. `Scanner::run_all()` is the CLI path; `Runner::make_stage()`/`scanall_stages()` is the stage list shared by `run_scanall()` and `Elderward_Job`.
- **Adapters**: `Http::get()/download()` (`CurlHttp` standalone, `Elderward_WP_Http` in WordPress — TLS verification is never disabled anywhere); `Db::connect()/each(query, callback, after)` (`MysqliDb` streams with `MYSQLI_USE_RESULT`, `Elderward_WP_Db` walks primary-key *ranges* with an adaptive range size and checks the Context deadline between ranges, so one query never scans the whole table and the cursor advances even when nothing matches; both iterate in pk order and the engine's queries are fixed SQL with `ORDER BY pk`). SELECT-only, never `unserialize()`.
- **Signatures** (`signatures.php`) are static arrays compile-checked by `Signatures::lint()` before every scan; a malformed regex throws Fatal naming the signature. Cleanup signatures have `prefilter` + `triggers` (ALL must match) + one `action` (`remove_regex`/`delete_file`).
- Exit codes: 0 clean/INFO, 1 fatal, 2 LOW/MEDIUM/ERROR, 3 HIGH. Anything that blocks a check (unreadable file or log, missing zlib/zip/mysqli, unreachable DB, failed query, disabled `shell_exec`, failing `crontab -l`) is an `ERROR` finding (`INTEGRITY_UNREADABLE`, `LOG_UNREADABLE`, `DB_UNAVAILABLE`, `DB_QUERY_FAILED`, `CRONTAB_UNAVAILABLE`) so it shows in the exit code — a silent skip makes "clean" mean "never looked". Note `function_exists('shell_exec')` is true for a `disable_functions` entry; check `ini_get('disable_functions')` too.

## Plugin side rules (WordPress.org guidelines)

- Prefix everything global: `Elderward_*` classes, `elderward_*` options/hooks/table, `ELDERWARD_*` constants, text domain `elderward`. `if (!defined('ABSPATH')) exit;` at the top of every plugin-side file.
- Capability `manage_options` plus `is_super_admin()` on multisite (`Elderward_Plugin::can_manage()`); nonce on every ajax/admin-post action; the only free-text input (log path) must `realpath()` to a readable file/dir; escape all output (findings are hostile data); `$wpdb->prepare()` for every value; table name from `$wpdb->base_prefix`.
- The admin page is **report-only**: it never cleans, restores, writes site files or changes the database. Destructive actions are WP-CLI/CLI only (`wp elderward scan`, `wp elderward integrity --restore`), with `--dryrun`.
- Outbound requests only to `api.wordpress.org`/`downloads.wordpress.org`, only during an integrity check, disclosed in `readme.txt` (External services). No telemetry, no remote signature feeds, no CDN assets; `assets/admin.js` is vanilla, no build step. No site-wide admin notices.
- Direct filesystem writes (atomic temp+rename, quarantine) and `shell_exec('crontab -l')` are deliberate and documented in `readme.txt` FAQ; each site carries a `phpcs:ignore` with the reason. Keep `composer phpcs` clean.
- `readme.txt` `Stable tag` must equal `Version:` in `elderward.php` and `ELDERWARD_VERSION`; bump all three together. `.distignore` keeps tests/tooling out of the WordPress.org zip.

## Invariants — do not break these

- **Fail closed**: only `preg_match(...) === 1` counts as a match; engine errors (`false`) and unknown condition/action types never flag or clean a file.
- **`dryrun` must cover every destructive action** (writes, deletes, restores). A dry run that touches disk is a P0 bug — this happened once with `DELETE_FILE`. `scanall` forces `dryrun` and drops `restore`.
- **Restore safety**: content is byte-verified against the reference checksum manifest before writing (a tampered package zip must be refused); `INTEGRITY_EXTRA` files are never deleted or overwritten; failed quarantine aborts the overwrite; writes go through `write_cleaned_file` (temp file + rename, never truncate in place).
- **Heuristics are report-only**: timestamp and correlation findings must never feed a cleanup or restore action, and their output says "leads, not proof".
- **Never disable TLS verification** — the tool runs on already-compromised hosts; an "all clean" answer must not be attacker-supplied. Treat API responses and everything read from the scanned host (filenames, log lines, file contents, DB values) as hostile data.
- **Memory/scale**: logs are streamed line-by-line, zips streamed to disk, per-minute bucketing bounds correlation memory, DB values capped at 256KB, file lists go to a work file. Don't buffer unbounded input.
- **The engine never scans itself**: `is_scannable_file()` skips `Context::$plugin_dir` (the signature strings in the source would match).
- False positives get downgraded with an explanation (`Signatures::known_benign()`, hex-filename annotation), not silently suppressed — an attacker can hide behind any known-benign name.
- The output contract (text format, JSON events, exit codes) is what `tests/regress.sh` protects: a change there is a deliberate decision, documented in README, not a side effect.

## Style

Procedural-flavoured PHP matching the existing files: `////` banner comments for sections, snake_case helpers, explicit `return (...)`, Yoda-ish comparisons (`false === $x`), errors suppressed with `@` only where the failure is handled on the next line. Formatting sniffs are intentionally not enforced; security/DB/WP sniffs are.
