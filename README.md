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
php elderward.php help=1                   # show usage
```

**Always take a backup before cleaning.** `dryrun=1` is the safe way to see what would change first.

### Output

File cleanup prints one line per action:

```
CLEARED,/path/to/file.js,javascript_ndsw
WOULD_CLEAR,/path/to/file.js,javascript_ndsw     (dry run)
```

The log scanner prints a report per log file: each IoC found, how many times, example log lines, and the top source IPs behind the flagged requests. Noisy-by-nature signatures (e.g. `wp-login.php` POSTs) only fire above a volume threshold, so normal traffic doesn't raise alarms.

### Running over HTTP (no shell access)

Web access is disabled by default. If your host offers no shell, set a long random value for `WEB_ACCESS_TOKEN` at the top of `elderward.php`, upload it, and pass the token on every request:

```
https://example.com/elderward.php?token=YOUR_TOKEN&dryrun=1
```

Delete the file from the server when you're done.

## What it checks

- **Files** — signature-based detection and cleanup of known malware injections (e.g. the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns), across common web extensions (`php`, `js`, `html`, ...). Cleaned files are written atomically (temp file + rename) so a failed write can never truncate the original.
- **Crontab** — known persistence patterns (piped base64 decoders, pastebin downloads, tmp-dir droppers).
- **Access logs** — known attack traffic: webshell requests, PHP files served from `wp-content/uploads`, wp-file-manager / Slider Revolution / TimThumb exploit attempts, `.env` probes, directory traversal, code and PHP-CGI injection, user enumeration, and xmlrpc/wp-login brute-force floods.

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
