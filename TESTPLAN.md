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

`WP=/tmp/ew/wordpress` below (or your site's root). `EW=php /path/to/elderward/bin/elderward.php` (the standalone CLI inside the plugin folder; section F covers the plugin and WP-CLI).

---

## A. Quick regressions (no WordPress needed)

**A1.** `php -l` on every PHP file (`for f in $(git ls-files '*.php'); do php -l $f; done`) → only `No syntax errors detected`. `tests/regress.sh` → `failed=0`.

**A2.** `$EW help=1` → usage screen listing scandirectory, allfiles, dryrun, scancron, scanlog, scanintegrity, checksumdir, locale, scantimes, help.

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

**A5. Blocked checks are ERROR findings, not silent passes.**

```sh
php -d disable_functions=shell_exec bin/elderward.php scancron=1; echo "exit=$?"
$EW scancron=1; echo "exit=$?"
mkdir -p /tmp/ew/logs && ln -sf /nonexistent/access.log.1.gz /tmp/ew/logs/access.log.1.gz && cp /tmp/ew/access.log /tmp/ew/logs/
$EW scanlog=/tmp/ew/logs; echo "exit=$?"
```

Expect: the first command prints `ERROR,CRONTAB_UNAVAILABLE,crontab,crontab NOT checked: shell_exec is not available...` and exits 2. The second prints `No crontab for the current user.` (exit 0) when the user has none, the usual `CRONTAB_IOC` lines when it has malicious entries, or `CRONTAB_UNAVAILABLE` with the `crontab -l` error if the binary is missing. The directory log scan prints `ERROR,LOG_UNREADABLE,/tmp/ew/logs/access.log.1.gz,log NOT scanned: cannot open it (permissions?)` alongside the A4 findings (on a host without zlib a real `.gz` reports `compressed log NOT scanned: PHP zlib extension not available`); the exit code is 3 because of the HIGH log IoC.

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

## E. Database scan (needs a real WordPress DB)

Run against `$WP` (or a copy of a real site). The scan is **read-only** — it issues only SELECTs — but run it against a staging copy if you're cautious.

**E1. Baseline on a clean install.** `$EW scandb=1 scandirectory=$WP`

Expect: a `DB_ADMIN_USER` INFO line per administrator, `DB_SITE_URL` INFO lines for `siteurl`/`home`, and `0 flagged options, 0 flagged posts`. On a fresh install this should be all INFO (exit 0). **PASTE the output** — real sites carry legitimate `<script src=...>` analytics snippets in options that flag as `DB_OPTION_IOC` (MEDIUM); those are the tuning input for the option signatures.

**E2. Planted artifacts are caught.** On a throwaway DB:

```sql
INSERT INTO wp_options (option_name, option_value) VALUES ('ew_test','<script>eval(atob("eA=="))</script>');
UPDATE wp_options SET option_value='http://evil.example/' WHERE option_name='siteurl';
-- create a fresh admin through wp-admin, or:
-- INSERT a user + wp_usermeta row with meta_key wp_capabilities LIKE '%administrator%'
```

Expect: `HIGH,DB_OPTION_IOC` for `ew_test` with the `e.g.` excerpt showing the `eval(atob(` itself, `HIGH,DB_SITE_URL` for the non-URL... (`http://evil.example/` is a valid URL so it reports INFO — the point is it should now differ from your real address, which the operator eyeballs), and `MEDIUM,DB_NEW_ADMIN` for the new admin. Remember to restore `siteurl` afterward or the site breaks.

Role tampering: with a role-editor plugin (or by editing `wp_user_roles` directly) grant `manage_options` to the Subscriber role. Expect `MEDIUM,DB_ROLE_CAPS,db:wp_options:wp_user_roles,role "subscriber" holds administrator-level capabilities: manage_options ...`. The Editor role's default `unfiltered_html` must NOT flag. Save a few revisions of a post containing `<?php` — expect exactly one `DB_POST_IOC` for the live post, none for the revisions.

**E3. Non-standard setups.** If your site uses a custom `$table_prefix`, external DB host, or has `wp-config.php` one level above the web root, confirm E1 still connects. **PASTE any connection error** — DB_HOST parsing (socket vs port vs IPv6) is the most likely real-world snag. A commented-out `// define('DB_HOST', ...)` left above the live one must be ignored.

**E4. Failures are loud, not silent.** Temporarily set a wrong `DB_PASSWORD` (or `$table_prefix`) in a *copy* of wp-config.php and point `scandirectory` at that copy's root:

- `$EW scandb=1 scandirectory=$COPY` → `Error: could not connect ...`, exit 1; with `format=json` the only stdout line is `{"event":"error",...}`.
- `$EW scanall=1 scandirectory=$COPY` → the sorted report contains `ERROR,DB_UNAVAILABLE,...wp-config.php,... the database was NOT scanned` and exit is at least 2. With a wrong prefix instead: three `ERROR,DB_QUERY_FAILED` lines (users, options, posts).

---

## F. The plugin (needs a WordPress install with WP-CLI)

Install the repo as `wp-content/plugins/elderward` on a disposable site (a symlink works) and activate it with `WP_DEBUG` and `WP_DEBUG_LOG` on. Nothing plugin-specific should appear in `wp-content/debug.log` at any point below (WordPress' own "could not establish a secure connection to WordPress.org" warnings on an offline box are not ours).

**F1. Activation and WP-CLI parity.** `wp plugin activate elderward` creates `{prefix}elderward_findings`. Then, with the E2 artifacts planted plus a PHP file under `wp-content/uploads/`, a dotfile PHP under `wp-content/`, an mu-plugin, a `.user.ini` with `auto_prepend_file`, and the A3 `ndsw` payload in a `.js` under `wp-content/themes/`:

```sh
wp elderward scanall --log=/path/to/logs --format=json; echo "exit=$?"
wp elderward db --format=json | sort > /tmp/ew/db-wpcli.txt
php bin/elderward.php scandb=1 format=json scandirectory=$(wp eval 'echo ABSPATH;') | sort > /tmp/ew/db-cli.txt
diff /tmp/ew/db-wpcli.txt /tmp/ew/db-cli.txt && echo IDENTICAL
```

Expect: exit 3 and finding types `UPLOADS_PHP`, `HIDDEN_PHP`, `MU_PLUGIN`, `PHP_PREPEND`, `MALWARE_FOUND` (dry run), `DB_NEW_ADMIN`/`DB_ADMIN_USER`, `DB_ROLE_CAPS`, `DB_OPTION_IOC`, `DB_POST_IOC`, `DB_SITE_URL`, `LOG_IOC`, plus `INTEGRITY_*` lines (on a networked site the live checks from section B apply; offline every package is `INTEGRITY_NO_REFERENCE`). The `$wpdb` and mysqli database scans must be line-for-line identical. **PASTE the type counts.**

**F2. Cleanup and restore from WP-CLI.** `wp elderward scan --dryrun` → `MALWARE_FOUND` exit 3, file unchanged; `wp elderward scan` → `MALWARE_CLEANED`, payload gone, the `var legit`/`console.log` lines intact. On a networked site, D2's tampered `functions.php`: `wp elderward integrity --restore --dryrun` → `INTEGRITY_RESTORABLE`; `wp elderward integrity --restore --quarantine-dir=/tmp/ew/quarantine` → `INTEGRITY_RESTORED` and a `*.quarantine` copy.

**F3. Admin page.** Tools > Elderward (Network Admin > Settings > Elderward on multisite): enter the log directory, **Start scan**. The progress bar advances through "Quick checks … Malware signatures (dry run)"; reload the page mid-scan and it resumes; when done the page reloads with the findings table sorted HIGH, ERROR, MEDIUM, LOW, INFO, the filter counts matching, and both exports downloading. The JSON export must carry the same (severity, type) multiset as `wp elderward scanall --format=json` for the same log path. `node tests/admin-ui.js` (Playwright; `ELDERWARD_URL`, `ELDERWARD_USER`, `ELDERWARD_PASS`, `ELDERWARD_LOG`) automates this and prints the counts. Confirm that nothing on disk changed (the `.js` payload is still there after an admin scan) and that `wp-content/uploads/elderward/` holds no job folder once the scan is finished.

**F4. Access control.** Logged in as a Subscriber/Editor, `tools.php?page=elderward` → "You are not allowed"; an `admin-ajax.php` POST with `action=elderward_step` and no nonce → HTTP 403; `admin-post.php?action=elderward_export&format=json` logged out → no finding lines in the response.

**F5. Uninstall.** `wp plugin deactivate elderward && wp plugin uninstall elderward --skip-delete` → the findings table, the `elderward_*` options and `wp-content/uploads/elderward/` are gone. Reactivate → the table is recreated.

**F6. Large tables.** Pad the database (30k posts with ids 13 apart, a block of 600 consecutive posts that all contain `<iframe`, 20k options with ids 17 apart, `autoload='no'`, a planted injection every 1000 rows; the SQL is in the plugin's git history under "range paging"). Then `wp elderward db --format=json | sort` must equal `php bin/elderward.php scandb=1 format=json | sort` (range paging vs streaming), and an admin scan with the step budget forced down (copy `tests/mu-plugin-test-hooks.php` into `wp-content/mu-plugins/` and `wp option update elderward_test_budget 0.05`) must finish with the same `DB_*` rows in the findings table and show "Scanning database: … past id …" messages while it runs. A step that dies (`wp option update elderward_test_die 1`, then start a scan) must leave the job **failed** with "PHP stopped the request: elderward test fatal" on the next status read, with no `elderward_job_lock` option left behind; a step that exits silently (`elderward_test_exit 1`) must fail the job after three attempts with "cut short 3 times". Remove the mu-plugin afterwards. **PASTE the step counts.**

**F7. Plugin Check.** With the [Plugin Check](https://wordpress.org/plugins/plugin-check/) plugin installed: `wp plugin check elderward --format=table`. Expect zero errors; **PASTE any warnings** (expected ones: the direct filesystem writes in the engine, `shell_exec` in the crontab scanner, and the `$wpdb` adapter's unprepared fixed SELECTs — each is documented in `readme.txt`).

---

## What to paste back

1. B1 output (always), B4/C4 outputs if you can run them (always), `php -v` and the OS.
2. Any test whose result differs from the stated expectation.
