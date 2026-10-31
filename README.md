# elderward

Elderward is a free, single-file PHP malware scanner and cleanup utility for compromised sites (WordPress in particular). It checks files for signs of compromise and can remove known malware, and it scans access logs for known indicators of compromise (IoCs) so you can understand how the attack happened — not just clean up after it.

It is a variation of the Jetpack Cleanup Util, packaged so anyone can run it on their own host.

## Requirements

- PHP 5.6+ (CLI preferred)
- Shell access to the host, or the ability to upload a PHP file and reach it over HTTP

The signature scan, quick checks and timestamp checks need nothing else. The other scanners use PHP extensions that locked-down hosts sometimes lack; a missing one is reported as an `ERROR` finding rather than skipped:

| Needed for | Requirement |
|---|---|
| `.gz` rotated logs (`scanlog=`) | zlib extension |
| Online integrity checks (`scanintegrity=1`) | curl extension, or `allow_url_fopen=On` |
| Theme verification and every `restore=1` | zip extension |
| Database scan (`scandb=1`) | mysqli extension |
| Crontab scan (`scancron=1`) | `shell_exec` not in `disable_functions` |

## Usage

Options are `key=value` arguments. The first look at a site is one command, run against the WordPress root:

```
php elderward.php scanall=1 scandirectory=/path/to/wp-root         # every scanner, report-only
php elderward.php scanall=1 scanlog=/var/log/apache2 scandirectory=/path/to/wp-root  # ... incl. logs
php elderward.php scanall=1 format=json scandirectory=/path/to/wp-root               # machine-readable
```

`scanall=1` runs the quick checks, integrity, timestamp, crontab, database and (with `scanlog=`) access log scanners, then the malware signature scan, and **changes nothing**: it only reports. In text mode the findings are collected and printed once at the end, sorted worst-first; with `format=json` they stream as each scanner produces them. Once you've read that report, clean up with the specific commands below. Each one is a separate run, because only one scan mode is accepted per invocation.

Fixing what was found:

```
php elderward.php dryrun=1 scandirectory=/path/to/site   # preview the signature cleanup, write nothing
php elderward.php scandirectory=/path/to/site            # remove known malware from infected files
php elderward.php scan_all=1 scandirectory=/path/to/site # ... scanning every file, not just risky extensions
php elderward.php scanintegrity=1 restore=1 dryrun=1 scandirectory=/path/to/wp-root  # preview restore
php elderward.php scanintegrity=1 restore=1 quarantinedir=/safe/place scandirectory=/path/to/wp-root
```

Note the two similarly named options: `scan_all=1` widens the *signature scan* to every file extension, while `scanall=1` runs *every scanner*. The signature cleanup is the default mode, so with no mode option the script modifies files; `dryrun=1` is the switch that makes it report-only.

Running one scanner at a time:

```
php elderward.php scancron=1               # check the current user's crontab for malware
php elderward.php scanlog=/var/log/apache2/access.log   # scan one access log for IoCs
php elderward.php scanlog=/var/log/apache2 # scan every access log in a directory (.gz included)
php elderward.php scanlog=/var/log/apache2 correlate=1 scandirectory=/path/to/wp-root  # link traffic to files
php elderward.php scanintegrity=1 scandirectory=/path/to/wp-root   # verify core, plugins and themes
php elderward.php scanintegrity=1 checksumdir=/path/to/manifests   # ... without network access
php elderward.php scanintegrity=1 locale=pt_BR scandirectory=/path/to/wp-root  # non-English core
php elderward.php scantimes=1 scandirectory=/path/to/wp-root       # timestamp anomaly report
php elderward.php scandb=1 scandirectory=/path/to/wp-root          # scan the database (read-only)
php elderward.php quickscan=1 scandirectory=/path/to/wp-root       # uploads PHP, prepend hooks, mu-plugins
php elderward.php help=1                   # show usage
```

`scandirectory=` defaults to the current directory. The signature scan and `correlate=1` accept any directory; `scanintegrity`, `scantimes`, `quickscan`, `scandb` and `scanall` need the WordPress root (the directory holding `wp-includes/`) and stop with an error otherwise. Arguments are parsed like a URL query string, so quote paths that contain spaces or `&`, and write `+` as `%2B` and `%` as `%25` (a literal `+` would be read as a space).

**Always take a backup before cleaning.** `dryrun=1` is the safe way to see what would change first.

### Output

Every scanner reports findings in one shared format, so results are easy to grep, sort, and paste into a ticket:

```
SEVERITY,TYPE,path,detail
```

The first three fields never contain commas; everything after the third comma is free-form detail. Because paths and log content come from a compromised host, `%`, control characters, and (in the path field) commas are percent-encoded, so a crafted filename can't shift fields or inject fake finding lines. Severities are `HIGH`, `MEDIUM`, `LOW`, `INFO`, and `ERROR`. Indented lines under a finding are supporting context (example log lines, top source IPs). For example:

```
HIGH,MALWARE_CLEANED,/path/to/file.js,javascript_ndsw
HIGH,MALWARE_FOUND,/path/to/file.js,javascript_ndsw (dry run: file not modified)
HIGH,CRONTAB_IOC,crontab,crontab.tmp.006: * * * * * echo ... | base64 --decode > /tmp/x
MEDIUM,LOG_IOC,/var/log/apache2/access.log,access.xmlrpc.flood: 4182 hit(s) - High volume of xmlrpc.php POSTs, ...
```

Log IoCs report as `MEDIUM` (attack attempts, including failed ones) except traffic to a shell already on disk, which is `HIGH`. Noisy-by-nature signatures (e.g. `wp-login.php` POSTs) only fire above a volume threshold, so normal traffic doesn't raise alarms.

### JSON output and exit codes

`format=json` switches stdout to NDJSON — one event object per line, with raw (JSON-escaped) values:

```
{"event":"finding","severity":"HIGH","type":"LOG_IOC","path":"...","detail":"...","context":["e.g. ..."]}
{"event":"summary","scan":"integrity","MODIFIED":1,"MISSING":0,...}
```

Progress and informational text moves to stderr, so stdout is pure machine-readable events for pipelines. A usage/fatal error (bad arguments, unreadable target, DB unreachable in `scandb=1`) is emitted as `{"event":"error","detail":"..."}` before exiting 1, so the stream never carries loose text.

Anything that blocks a check is an `ERROR` finding (exit 2), never a silent skip: inside `scanall=1` an unreachable database reports `DB_UNAVAILABLE`, a failed query reports `DB_QUERY_FAILED`, an unreadable file `INTEGRITY_UNREADABLE`, a log that can't be opened or decompressed `LOG_UNREADABLE`, and a crontab that can't be read (no `shell_exec`, no `crontab` binary) `CRONTAB_UNAVAILABLE`. A clean report means every scanner actually looked.

The exit code reflects the worst finding, so cron jobs and CI can alert on it: **0** clean (or INFO-only), **1** usage/fatal error, **2** LOW/MEDIUM/ERROR findings, **3** HIGH findings. Note that a successful cleanup also exits 3 — malware was found.

### Running over HTTP (no shell access)

Web access is disabled by default. If your host offers no shell, set a long random value for `WEB_ACCESS_TOKEN` at the top of `elderward.php`, upload it, and pass the token on every request:

```
https://example.com/elderward.php?token=YOUR_TOKEN&dryrun=1
```

Delete the file from the server when you're done.

## What it checks

- **Files** — signature-based detection and cleanup of known malware injections (e.g. the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns), across common web extensions (`php`, `js`, `html`, ...). Cleaned files are written atomically (temp file + rename) so a failed write can never truncate the original.
- **Crontab** (`scancron=1`) — runs `crontab -l` for the user PHP executes as and checks it for known persistence patterns (piped base64 decoders, pastebin downloads, tmp-dir droppers). Other users' crontabs and `/etc/cron.*` are not covered; if the command can't run, `CRONTAB_UNAVAILABLE` says so.
- **Access logs** — known attack traffic: webshell requests, PHP files served from `wp-content/uploads`, wp-file-manager / Slider Revolution / TimThumb exploit attempts, `.env` probes, directory traversal, code and PHP-CGI injection, user enumeration, and xmlrpc/wp-login brute-force floods. Add `correlate=1` (with `scandirectory=`) to also report files whose mtime falls within `window=` seconds (default 300) of flagged traffic — `LOG_FILE_CORRELATION`, the "this request created that file" artifact. A hit is a strong lead; a miss clears nothing, since later edits or faked mtimes erase the link.
- **Integrity** (`scanintegrity=1`) — verifies WordPress core, every plugin, and every theme against official wordpress.org packages for the installed version (pass `locale=xx_XX` for a non-English core, otherwise its translated files show as modified). Reports `INTEGRITY_MODIFIED` (checksum mismatch), `INTEGRITY_MISSING` (file from the package gone), and `INTEGRITY_EXTRA` (file on disk that the package doesn't contain — extra PHP inside core or a plugin is the classic dropped webshell and reports as `HIGH`; commonly legitimate extras like `error_log` and the Wordfence WAF bootstrap report as `INFO` with an explanation). Packages that can't be verified (custom/premium plugins and themes, child themes, versions not in the archive) report as `INTEGRITY_NO_REFERENCE`, so a clean report never silently means "unchecked". Core and plugins use the checksum APIs; themes have no checksum API, so the manifest is built by hashing the official theme zip (requires the PHP zip extension). Bundled themes/plugins under `wp-content` are skipped in the core pass, and `wp-config.php` is ignored.
- **Quick checks** (`quickscan=1`) — cheap, high-signal places attackers hide: executable PHP inside `wp-content/uploads` (`UPLOADS_PHP`, HIGH), `auto_prepend_file`/`auto_append_file` directives in `.user.ini`/`php.ini`/`.htaccess` that execute a file on every request (`PHP_PREPEND` — the Wordfence WAF bootstrap is recognized and reported as INFO), an inventory of mu-plugins, which load with no activation step (`MU_PLUGIN`, INFO), and hidden dotfile PHP (`HIDDEN_PHP`).

- **Database** (`scandb=1`) — read-only (SELECT-only) scan of the database, using the credentials parsed from `wp-config.php` (never executed — read with regexes). Reports an inventory of administrator accounts (`DB_ADMIN_USER`, INFO — confirm each) with admins created in the last 30 days escalated to `DB_NEW_ADMIN` (MEDIUM, the classic takeover artifact); non-administrator roles that were granted takeover capabilities such as `manage_options`/`edit_users` in the `user_roles` option (`DB_ROLE_CAPS`, MEDIUM — role-editor plugins and shop-manager roles do this legitimately, so verify rather than assume); injected option values (`DB_OPTION_IOC` — PHP/eval, hidden iframes, obfuscated JS, remote scripts), `siteurl`/`home` hijacks (`DB_SITE_URL`), and `active_plugins` tampering (`DB_ACTIVE_PLUGIN` — path traversal or entries missing on disk); and script/PHP injections in post content (`DB_POST_IOC`, found via a server-side `LIKE` prefilter so the posts table isn't pulled wholesale; revisions are skipped so each injected post reports once). Every value is pattern-matched only and **never `unserialize()`d** — hostile serialized data can trigger PHP object injection. Needs the `mysqli` extension; if it's missing, credentials can't be read (`getenv()`-style configs can't be parsed without executing them), or the DB is unreachable, `scandb=1` exits 1 with an error while `scanall=1` reports `DB_UNAVAILABLE` (ERROR) and continues; a query that fails mid-scan reports `DB_QUERY_FAILED` for that table.
- **Timestamps** (`scantimes=1`) — report-only heuristics for when files were touched apart from their package. Every check is an outlier *within* one package (core, a plugin, a theme), never a comparison against a site-wide date, which would drown in false positives after any migration. `TIMESTAMP_OUTLIER` flags a handful of files modified after the package's dominant install/update cluster (the classic backdoored `functions.php` or dropped loader); a large newer cluster is a legitimate update and doesn't flag. `TIMESTAMP_TIMESTOMP` flags PHP files whose mtime sits far behind their ctime — `touch -t` can back-date content time, but the inode change time can't be set without root — and only when few files in the package show it, since migrations and `rsync -a` do that to whole trees. Timestamps are leads, not proof: attackers fake them and updates rewrite them, so these findings never feed a cleanup action and a clean result does not clear a file.

### Restoring files (`restore=1`)

With `scanintegrity=1 restore=1`, every `INTEGRITY_MODIFIED` and `INTEGRITY_MISSING` file is restored from the official package zip for the exact installed version. Safety properties:

- **Take a backup first**, and preview with `dryrun=1` (reports `INTEGRITY_RESTORABLE` without writing).
- Every file is **byte-verified against the reference checksum manifest before writing** — a tampered or mismatched zip is refused (`RESTORE_FAILED`), never written.
- `EXTRA` files are **never touched**: deleting unknown files is the operator's call.
- Overwriting a backdoored file destroys evidence. Set `quarantinedir=/path` (outside the webroot) to copy each original aside as `*.quarantine` before it's overwritten; if quarantining fails, the file is left alone.
- Offline: with `checksumdir=`, package zips are read as `core-{version}.zip` / `plugin-{slug}-{version}.zip` / `theme-{slug}-{version}.zip` from the same directory. Non-`en_US` core restore isn't supported yet (plugin and theme restore are locale-independent).

### Integrity checks without network access

On hosts with no outbound network, download the reference data on another machine, put it in one directory, and pass `checksumdir=/path`. With that option set the script never touches the network: anything missing from the directory reports as `INTEGRITY_NO_REFERENCE`.

```
core-{version}.json           from https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
plugin-{slug}-{version}.json  from https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
theme-{slug}-{version}.zip    from https://downloads.wordpress.org/theme/{slug}.{version}.zip
```

Themes have no checksum API, so verifying them offline needs the theme package zip itself (and the PHP zip extension). The core manifest is named by version only: for a non-English site, download it with your locale in the URL and still save it as `core-{version}.json`. For `restore=1`, add `core-{version}.zip` and `plugin-{slug}-{version}.zip` (from `https://wordpress.org/wordpress-{version}.zip` and `https://downloads.wordpress.org/plugin/{slug}.{version}.zip`); the theme zip already covers theme restores.

TLS verification stays on for all API requests — this tool runs on already-compromised hosts, and an "all clean" answer must not be attacker-supplied.

## Adding signatures

File cleanup signatures live in `$CLEANUP_SIGNATURES`, keyed by a unique name:

```php
'javascript_example' => array(
    // Cheap check run first on every file: array('string' => needle) for a
    // fast strpos lookup (preferred), or array('regex' => pattern).
    'prefilter' => array('string' => 'example-malware-marker'),
    // Zero or more further conditions that must ALL also match. The
    // prefilter already counts, so don't repeat it here.
    'triggers'  => array(
        array('regex' => '/eval\(example_\w+\(/'),
    ),
    // What to do with a confirmed file: remove every match of a pattern,
    // or delete the file outright.
    'action'    => array('remove_regex' => '/eval\(example_\w+\([^;]+;/s'),
    // 'action' => array('delete_file' => true),
),
```

Regexes are full PCRE patterns with delimiters and flags. Every pattern (including the crontab and access log sets) is compile-checked at startup, so a malformed regex stops the run and names the broken signature instead of silently never matching. `remove_regex` fails loudly if it matched nothing, and `dryrun=1` covers both action types.

## Limitations

- Signature-based: it finds and removes *known* malware. A clean scan is not proof of a clean site.
- Log IoC checks show attack *attempts*, including plenty that failed (status 403/404). Treat them as awareness and a starting point for investigation, not confirmation of compromise.
- Files larger than 2 MB are skipped by the file scanner.
