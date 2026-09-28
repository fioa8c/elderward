# Elderward local test plan

Covers what couldn't be verified from the development environment (live wordpress.org API access) plus the new timestamp heuristics. Run from the repo checkout; paste back the outputs marked **PASTE**.

**Prerequisites:** PHP CLI 5.6+ (`php -v`), `curl`, `unzip`, outbound HTTPS to wordpress.org. No database or web server needed — every scanner works on files on disk.

**Setup — disposable WordPress tree** (used by parts B and C; skip if you'd rather point at a copy of a real site):

```sh
mkdir -p /tmp/ew && cd /tmp/ew
curl -L -o wp.zip https://wordpress.org/latest.zip && unzip -q wp.zip
# unzip preserves the release's file mtimes; normalize so part C starts deterministic:
find /tmp/ew/wordpress -exec touch {} +
```

`WP=/tmp/ew/wordpress` below (or your site's root). `EW=php /path/to/elderward.php`.

---

## A. Quick regressions (no WordPress needed)

**A1.** `php -l elderward.php` → `No syntax errors detected`.

**A2.** `$EW help=1` → usage screen listing scandirectory, scan_all, dryrun, scancron, scanlog, scanintegrity, checksumdir, locale, scantimes, help.

**A3. Cleanup engine.**

```sh
mkdir -p /tmp/ew/site && cat > /tmp/ew/site/ndsw.js <<'EOF'
var legit=1;
if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};
console.log(legit);
EOF
$EW scandirectory=/tmp/ew/site dryrun=1
$EW scandirectory=/tmp/ew/site
cat /tmp/ew/site/ndsw.js
```

Expect: `HIGH,MALWARE_FOUND,...,javascript_ndsw (dry run: file not modified)`, then `HIGH,MALWARE_CLEANED,...`, and the file keeps only the `var legit` and `console.log` lines.

**A4. Log scanner.**

```sh
cat > /tmp/ew/access.log <<'EOF'
203.0.113.5 - - [20/Sep/2026:10:05:01 +0000] "POST /wp-content/uploads/2026/09/wp-cache.php HTTP/1.1" 200 312 "-" "python-requests/2.31"
192.0.2.44 - - [20/Sep/2026:10:08:30 +0000] "GET /.env HTTP/1.1" 404 210 "-" "Mozilla/5.0"
192.0.2.44 - - [20/Sep/2026:10:09:00 +0000] "GET /?q=eval(base64_decode($_POST[1])) HTTP/1.1" 200 100 "-" "Mozilla/5.0"
EOF
$EW scanlog=/tmp/ew/access.log
```

Expect: `HIGH,LOG_IOC,...access.uploads.php...`, two `MEDIUM,LOG_IOC` lines (env probe, code injection), example lines indented, and a top-source-IP list.

---

## B. Integrity — live wordpress.org API ← the untested part

**B1. Clean baseline.** `$EW scanintegrity=1 scandirectory=$WP`

Expect: `Checking core <version> (~1500 files)`, `Checking plugin akismet <version> (...)`, `INFO,INTEGRITY_NO_REFERENCE,...hello.php,single-file plugin...`, and a summary of `0 modified, 0 missing, 0 extra` on the fresh tree. **PASTE the full output** — especially if anything reports MODIFIED/EXTRA on a fresh download, or any `NO_REFERENCE ... (error)` (that would mean an API response shape I need to adjust for).

**B2. Tampering is caught.**

```sh
echo "// tampered" >> $WP/wp-includes/functions.php
touch $WP/wp-includes/zz-elderward-extra.php
touch $WP/wp-content/plugins/akismet/zz-elderward-extra.php
rm $WP/wp-admin/link.php
$EW scanintegrity=1 scandirectory=$WP
```

Expect exactly four findings: `HIGH,INTEGRITY_MODIFIED` (functions.php), `HIGH,INTEGRITY_EXTRA` ×2, `LOW,INTEGRITY_MISSING` (link.php), summary `1 modified, 1 missing, 2 extra`. **PASTE if it differs.**

**B3. Offline parity.** Using the core version from B1's output:

```sh
mkdir -p /tmp/ew/checksums
VER=<version from B1>
AKVER=<akismet version from B1>
curl -o /tmp/ew/checksums/core-$VER.json "https://api.wordpress.org/core/checksums/1.0/?version=$VER&locale=en_US"
curl -o /tmp/ew/checksums/plugin-akismet-$AKVER.json "https://downloads.wordpress.org/plugin-checksums/akismet/$AKVER.json"
$EW scanintegrity=1 scandirectory=$WP checksumdir=/tmp/ew/checksums
```

Expect: identical findings to B2. Then undo B2's tampering (`rm` the two zz files; simplest for the rest: re-extract the zip and re-run the `find ... touch` normalization).

**B4 (optional, real site).** Run B1 against a copy of a real site — ideally one with premium plugins and one with a non-`en_US` locale (`locale=xx_XX`). **PASTE the full output**: real-world noise (legit `INTEGRITY_EXTRA` from plugins writing into their own directories, locale-related core mismatches) is exactly what I need to build the ignore list from.

---

## C. Timestamps

**C1. Clean baseline.** `$EW scantimes=1 scandirectory=$WP`

Expect on the normalized fresh tree: `Timestamp scan complete: 0 outliers, 0 possible timestomps...`.

**C2. Post-install edit is caught** (the backdoored-plugin-file case). Age akismet so it has an install-time cluster in the past, then drop one new file:

```sh
find $WP/wp-content/plugins/akismet -exec touch -t 202601011200 {} +
echo "<?php // planted" > $WP/wp-content/plugins/akismet/zz-outlier.php
$EW scantimes=1 scandirectory=$WP
```

Expect exactly one finding: `MEDIUM,TIMESTAMP_OUTLIER,...zz-outlier.php,plugin akismet: modified <today> but N of N+1 files cluster around 2026-01-01 12:00`. No TIMESTOMP findings for akismet (all its files now have mtime ≠ ctime — that whole-tree pattern is deliberately suppressed as migration noise).

**C3. Faked mtime is caught.** In a package with natural timestamps (a bundled theme), back-date one file:

```sh
THEME=$(ls -d $WP/wp-content/themes/twenty* | head -1)
echo "<?php // planted" > $THEME/zz-stomp.php && touch -t 202001010000 $THEME/zz-stomp.php
$EW scantimes=1 scandirectory=$WP
```

Expect one new finding: `MEDIUM,TIMESTAMP_TIMESTOMP,...zz-stomp.php,theme ...: content claims to be from 2020-01-01 00:00 but the inode changed <today> ...`. Clean up: `rm` both zz files.

**C4 (optional but the most valuable one). Real-site baseline.** `$EW scantimes=1 scandirectory=/path/to/real/site`

**PASTE the full output** plus roughly how the site is maintained (auto-updates? recently migrated?). A healthy site should produce zero to a handful of findings; whatever legitimate things do show up (recently edited theme files, plugin-generated files) are the tuning input for the thresholds (2h cluster tolerance, 5% outlier limit, 30-day timestomp gap).

---

## D. Phase 3 — correlation and restore (live)

**D1. Log-to-file correlation.** Reuses A4's log (timestamps are UTC, so create the file's mtime in UTC too):

```sh
echo "<?php // planted" > $WP/zz-corr.php
TZ=UTC touch -t 202609201006 $WP/zz-corr.php
$EW scanlog=/tmp/ew/access.log correlate=1 scandirectory=$WP
```

Expect: the usual LOG_IOC report, then `HIGH,LOG_FILE_CORRELATION,...zz-corr.php,modified ... within 300s of flagged traffic: access.uploads.php ...` with the example request line, and `Correlation complete: 1 file(s)...`. No other file in the tree should correlate. Clean up: `rm $WP/zz-corr.php`.

**D2. Plugin restore (live download).**

```sh
echo "// tampered" >> $WP/wp-content/plugins/akismet/akismet.php
rm $WP/wp-content/plugins/akismet/index.php
$EW scanintegrity=1 restore=1 dryrun=1 scandirectory=$WP        # preview
$EW scanintegrity=1 restore=1 quarantinedir=/tmp/ew/quarantine scandirectory=$WP
$EW scanintegrity=1 scandirectory=$WP                            # rescan
ls -R /tmp/ew/quarantine
```

Expect: preview reports two `INFO,INTEGRITY_RESTORABLE` and changes nothing; the real run reports two `INFO,INTEGRITY_RESTORED`; the rescan comes back `0 modified, 0 missing, 0 extra`; the quarantine dir holds `plugin-akismet-<ver>/akismet.php.quarantine` containing your `// tampered` line (only the modified file — the deleted one had nothing to preserve). **PASTE if it differs.**

**D3. Core restore (live download, ~30 MB).**

```sh
echo "// tampered" >> $WP/wp-includes/functions.php
$EW scanintegrity=1 restore=1 quarantinedir=/tmp/ew/quarantine scandirectory=$WP
$EW scanintegrity=1 scandirectory=$WP
```

Expect: `INFO,INTEGRITY_RESTORED,...functions.php,core <ver>: pristine copy restored...` and a clean rescan. This is the one live path with no offline equivalent tested (the full core zip download + `wordpress/` prefix extraction), so **PASTE the output either way.**

---

## What to paste back

1. B1 output (always), B4/C4 outputs if you can run them (always), `php -v` and the OS.
2. Any test whose result differs from the stated expectation.
