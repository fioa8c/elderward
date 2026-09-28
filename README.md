# elderward

Elderward is a free, single-file PHP malware scanner and cleanup utility for compromised sites (WordPress in particular). It checks files for signs of compromise and can remove known malware, and it scans access logs for known indicators of compromise (IoCs) so you can understand how the attack happened — not just clean up after it.

It is a variation of the Jetpack Cleanup Util, packaged so anyone can run it on their own host.

## Requirements

- PHP 5.6+ (CLI preferred; zlib extension needed only for reading `.gz` rotated logs)
- Shell access to the host, or the ability to upload a PHP file and reach it over HTTP

## Usage

Run it from the directory you want to scan (or pass one explicitly):

```
php elderward.php                          # scan the current directory
php elderward.php scandirectory=/path/to/site
php elderward.php dryrun=1                 # report what would be cleaned, write nothing
php elderward.php scan_all=1               # scan every file, not just risky extensions
php elderward.php scancron=1               # check the current user's crontab for malware
php elderward.php scanlog=/var/log/apache2/access.log   # scan one access log for IoCs
php elderward.php scanlog=/var/log/apache2 # scan every access log in a directory (.gz included)
php elderward.php scanintegrity=1 scandirectory=/path/to/wp-root   # verify core + plugins
php elderward.php scanintegrity=1 checksumdir=/path/to/manifests   # ... without network access
php elderward.php scanintegrity=1 restore=1 dryrun=1 scandirectory=/path/to/wp-root  # preview restore
php elderward.php scanintegrity=1 restore=1 quarantinedir=/safe/place scandirectory=/path/to/wp-root
php elderward.php scantimes=1 scandirectory=/path/to/wp-root       # timestamp anomaly report
php elderward.php quickscan=1 scandirectory=/path/to/wp-root       # uploads PHP, prepend hooks, mu-plugins
php elderward.php scanlog=/var/log/apache2 correlate=1 scandirectory=/path/to/wp-root  # link traffic to files
php elderward.php help=1                   # show usage
```

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

### Running over HTTP (no shell access)

Web access is disabled by default. If your host offers no shell, set a long random value for `WEB_ACCESS_TOKEN` at the top of `elderward.php`, upload it, and pass the token on every request:

```
https://example.com/elderward.php?token=YOUR_TOKEN&dryrun=1
```

Delete the file from the server when you're done.

## What it checks

- **Files** — signature-based detection and cleanup of known malware injections (e.g. the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns), across common web extensions (`php`, `js`, `html`, ...). Cleaned files are written atomically (temp file + rename) so a failed write can never truncate the original.
- **Crontab** — known persistence patterns (piped base64 decoders, pastebin downloads, tmp-dir droppers).
- **Access logs** — known attack traffic: webshell requests, PHP files served from `wp-content/uploads`, wp-file-manager / Slider Revolution / TimThumb exploit attempts, `.env` probes, directory traversal, code and PHP-CGI injection, user enumeration, and xmlrpc/wp-login brute-force floods. Add `correlate=1` (with `scandirectory=`) to also report files whose mtime falls within `window=` seconds (default 300) of flagged traffic — `LOG_FILE_CORRELATION`, the "this request created that file" artifact. A hit is a strong lead; a miss clears nothing, since later edits or faked mtimes erase the link.
- **Integrity** (`scanintegrity=1`) — verifies WordPress core, every plugin, and every theme against official wordpress.org packages for the installed version. Reports `INTEGRITY_MODIFIED` (checksum mismatch), `INTEGRITY_MISSING` (file from the package gone), and `INTEGRITY_EXTRA` (file on disk that the package doesn't contain — extra PHP inside core or a plugin is the classic dropped webshell and reports as `HIGH`; commonly legitimate extras like `error_log` and the Wordfence WAF bootstrap report as `INFO` with an explanation). Packages that can't be verified (custom/premium plugins and themes, child themes, versions not in the archive) report as `INTEGRITY_NO_REFERENCE`, so a clean report never silently means "unchecked". Core and plugins use the checksum APIs; themes have no checksum API, so the manifest is built by hashing the official theme zip (requires the PHP zip extension). Bundled themes/plugins under `wp-content` are skipped in the core pass, and `wp-config.php` is ignored.
- **Quick checks** (`quickscan=1`) — cheap, high-signal places attackers hide: executable PHP inside `wp-content/uploads` (`UPLOADS_PHP`, HIGH), `auto_prepend_file`/`auto_append_file` directives in `.user.ini`/`php.ini`/`.htaccess` that execute a file on every request (`PHP_PREPEND` — the Wordfence WAF bootstrap is recognized and reported as INFO), an inventory of mu-plugins, which load with no activation step (`MU_PLUGIN`, INFO), and hidden dotfile PHP (`HIDDEN_PHP`).

- **Timestamps** (`scantimes=1`) — report-only heuristics for when files were touched apart from their package. Every check is an outlier *within* one package (core, a plugin, a theme), never a comparison against a site-wide date, which would drown in false positives after any migration. `TIMESTAMP_OUTLIER` flags a handful of files modified after the package's dominant install/update cluster (the classic backdoored `functions.php` or dropped loader); a large newer cluster is a legitimate update and doesn't flag. `TIMESTAMP_TIMESTOMP` flags PHP files whose mtime sits far behind their ctime — `touch -t` can back-date content time, but the inode change time can't be set without root — and only when few files in the package show it, since migrations and `rsync -a` do that to whole trees. Timestamps are leads, not proof: attackers fake them and updates rewrite them, so these findings never feed a cleanup action and a clean result does not clear a file.

### Restoring files (`restore=1`)

With `scanintegrity=1 restore=1`, every `INTEGRITY_MODIFIED` and `INTEGRITY_MISSING` file is restored from the official package zip for the exact installed version. Safety properties:

- **Take a backup first**, and preview with `dryrun=1` (reports `INTEGRITY_RESTORABLE` without writing).
- Every file is **byte-verified against the reference checksum manifest before writing** — a tampered or mismatched zip is refused (`RESTORE_FAILED`), never written.
- `EXTRA` files are **never touched**: deleting unknown files is the operator's call.
- Overwriting a backdoored file destroys evidence. Set `quarantinedir=/path` (outside the webroot) to copy each original aside as `*.quarantine` before it's overwritten; if quarantining fails, the file is left alone.
- Offline: with `checksumdir=`, package zips are read as `core-{version}.zip` / `plugin-{slug}-{version}.zip` / `theme-{slug}-{version}.zip` from the same directory. Non-`en_US` core restore isn't supported yet (plugin and theme restore are locale-independent).

### Integrity checks without network access

On hosts with no outbound network, pre-download the manifests elsewhere and pass `checksumdir=/path`:

```
core-{version}.json           from https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
plugin-{slug}-{version}.json  from https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json
```

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
