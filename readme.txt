=== Elderward ===
Contributors: fioa8c
Tags: malware, security, scanner, integrity, incident response
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Malware scanner and incident-response toolkit: file signatures, core/plugin/theme integrity, database, crontab and access-log checks.

== Description ==

Elderward helps you find out whether a WordPress site has been compromised, how, and what to do about it. It was written for incident responders and runs entirely on your own server: there is no account, no external service and no data leaves the site.

**One report-only scan from Tools > Elderward** runs every check and lists the findings worst-first:

* **Quick checks** - executable PHP inside `wp-content/uploads`, `auto_prepend_file`/`auto_append_file` directives in `.user.ini`, `php.ini` and `.htaccess` (code that runs on every request), an inventory of must-use plugins, hidden dotfile PHP.
* **Integrity** - WordPress core, every plugin and every theme compared with the official wordpress.org packages for the installed version: modified files, missing files, and extra files that the package does not contain (extra PHP inside core or a plugin is the classic dropped webshell). Packages that cannot be verified, such as premium plugins or child themes, are reported as such so a clean report never silently means "unchecked".
* **Timestamps** - files modified apart from the rest of their package, and files whose modification time looks back-dated. Report-only leads, never proof.
* **Crontab** - the current user's crontab checked for known persistence patterns.
* **Database** - read-only: an inventory of administrator accounts with recently created ones highlighted, non-administrator roles that were granted takeover capabilities, PHP or hidden iframes or obfuscated JavaScript in options and posts, `siteurl`/`home` hijacks, and `active_plugins` tampering. Values are pattern-matched only and never unserialized.
* **Access logs** (optional) - point it at an access log file or directory (rotated `.log.N` and `.gz` files included) to see known attack traffic: webshell requests, exploit attempts against known-vulnerable plugins, `.env` probes, code injection, brute force floods. Files modified within minutes of flagged requests are linked to that traffic.
* **Malware signatures** - signature-based detection of known injections such as the `ndsw`/`ndsx` and `wqpq` JavaScript campaigns, run in dry-run mode from the admin page.

Anything that blocks a check - an unreadable file, a failed query, a missing PHP extension - is itself reported as an `ERROR` finding, never skipped. A clean report means every scanner actually looked.

**Cleanup and restore run from the command line**, where you can take a backup first and preview with a dry run:

* `wp elderward scan --dryrun` then `wp elderward scan` removes known malware from infected files (atomic write, never truncates the original).
* `wp elderward integrity --restore --dryrun` then `wp elderward integrity --restore --quarantine-dir=/path/outside/webroot` restores modified or missing core, plugin and theme files from the official packages. Every file is byte-verified against the reference checksum before it is written; extra files are never deleted.

The same scanners are available as WP-CLI commands (`wp elderward scanall`, `quick`, `integrity`, `times`, `db`, `cron`, `log`) with text or NDJSON output and exit codes that CI and cron jobs can alert on, and as a standalone PHP script (`php bin/elderward.php`, inside the plugin folder) for a site too broken to load WordPress.

Development happens at [github.com/fioa8c/elderward](https://github.com/fioa8c/elderward); the source in this directory is the complete, unminified source.

== Installation ==

1. Upload the `elderward` folder to `/wp-content/plugins/`, or install it from the Plugins screen.
2. Activate the plugin. It creates one database table (`{prefix}elderward_findings`) to hold the latest report.
3. Open **Tools > Elderward** (Network Admin > Settings > Elderward on multisite) and click **Start scan**. The scan runs in short steps while the page is open and resumes if you reload.
4. To act on the findings, use the WP-CLI commands shown under the results, after taking a backup.

== Frequently Asked Questions ==

= Does the plugin send data anywhere? =

No. There is no telemetry, no account and no remote service. The only outbound requests are made during the integrity check, to `api.wordpress.org` (core and plugin checksum manifests) and `downloads.wordpress.org` (official plugin/theme/core packages, needed to verify themes and to restore files). The requests carry only the WordPress version, the plugin or theme slug and its version. Findings are stored in your own database and shown only to administrators.

= Will the scan modify my site? =

The admin page is report-only: it never writes, deletes or restores files and never changes the database. Cleanup (`wp elderward scan`) and restore (`wp elderward integrity --restore`) are separate, explicit commands with a `--dryrun` preview. Take a backup before running them.

= Why does the plugin use shell_exec? =

Only for the crontab check, which runs the fixed, read-only command `crontab -l` to read the current user's cron entries. No user input ever reaches a shell. When `shell_exec` is disabled by the host, the check reports `CRONTAB_UNAVAILABLE` instead of silently passing.

= Why does the plugin write files directly instead of using WP_Filesystem? =

Cleanup and restore have to write files atomically (temporary file plus rename, so a failed write can never truncate the original) and copy originals to a quarantine folder before overwriting them, which the FTP and SSH transports of WP_Filesystem cannot do. Those writes only happen from the command line, never from the admin page. The admin scan writes nothing but its own work files under `wp-content/uploads/elderward/` (a file list and downloaded official packages), which are removed when the scan ends.

= Can I run it on a site that no longer loads? =

Yes. `php bin/elderward.php scanall=1 scandirectory=/path/to/wp-root` runs the same scanners without WordPress, reading the database credentials from `wp-config.php` without executing it. Run `php bin/elderward.php help=1` for the options.

= Is a clean scan proof that the site is clean? =

No. The signatures find known malware, the integrity check only covers packages that exist on wordpress.org, and the timestamp and log checks are leads, not proof. Treat the report as a starting point for an investigation.

= Are the finding texts translated? =

The admin interface is translatable. The finding details themselves (the technical description of each issue) are in English, because they are also written to exports and tickets that other tools and people read.

== Screenshots ==

1. Tools > Elderward: start a scan and watch it progress.
2. The findings table, sorted worst-first, with severity filters and export.

== External services ==

This plugin connects to two WordPress.org services, only while an integrity check or a restore is running:

* `https://api.wordpress.org/core/checksums/` - the official checksum manifest for the installed WordPress version and locale. Sent: the version number and locale.
* `https://downloads.wordpress.org/` - the plugin checksum manifests and the official plugin, theme and core packages. Sent: the plugin or theme slug and version.

Both are operated by the WordPress Foundation; see the [WordPress.org privacy policy](https://wordpress.org/about/privacy/). No other hosts are contacted.

== Changelog ==

= 1.0.0 =
* First release as a WordPress plugin: admin page with a resumable report-only scan, WP-CLI commands, and the standalone CLI.
