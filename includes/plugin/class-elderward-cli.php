<?php
/**
 * WP-CLI commands: the same scanners as the standalone CLI, same output
 * format and exit codes, run inside WordPress ($wpdb, WordPress HTTP API).
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Scans a WordPress install for malware and signs of compromise.
 *
 * Findings print as SEVERITY,TYPE,path,detail (or NDJSON with
 * --format=json). Exit codes: 0 clean or INFO-only, 1 usage/fatal error,
 * 2 LOW/MEDIUM/ERROR findings, 3 HIGH findings.
 */
class Elderward_CLI
{
    /**
     * Runs every scanner report-only and prints one severity-sorted report.
     *
     * ## OPTIONS
     *
     * [--log=<path>]
     * : Access log file or directory to scan for IoCs and correlate with file mtimes.
     *
     * [--window=<seconds>]
     * : Correlation window around flagged requests (default 300, minimum 60).
     *
     * [--checksum-dir=<path>]
     * : Pre-downloaded manifests/packages instead of the network (offline integrity check).
     *
     * [--locale=<locale>]
     * : Core locale for the checksum lookup (default en_US).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward scanall
     *     wp elderward scanall --log=/var/log/apache2 --format=json
     *
     * @when after_wp_load
     */
    public function scanall($args, $assoc_args)
    {
        $options = array('scanall' => 1);
        $this->copy_option($assoc_args, 'log', $options, 'scanlog');
        $this->copy_option($assoc_args, 'window', $options, 'window');
        $this->copy_option($assoc_args, 'checksum-dir', $options, 'checksumdir');
        $this->copy_option($assoc_args, 'locale', $options, 'locale');
        $this->run($options, 'scanall', $assoc_args);
    }

    /**
     * Signature scan and cleanup of known malware (modifies files unless --dryrun).
     *
     * ## OPTIONS
     *
     * [<directory>]
     * : Directory to scan. Default: the WordPress root.
     *
     * [--dryrun]
     * : Report what would be cleaned without writing any file.
     *
     * [--allfiles]
     * : Scan every file, not just known-risky extensions.
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward scan --dryrun
     *     wp elderward scan
     *
     * @when after_wp_load
     */
    public function scan($args, $assoc_args)
    {
        $options = array();
        if (isset($args[0])) {
            $options['scandirectory'] = $args[0];
        }
        $this->copy_flag($assoc_args, 'dryrun', $options, 'dryrun');
        $this->copy_flag($assoc_args, 'allfiles', $options, 'allfiles');
        $this->run($options, 'signatures', $assoc_args);
    }

    /**
     * Quick high-signal checks: PHP in uploads, prepend directives, mu-plugins, hidden PHP.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function quick($args, $assoc_args)
    {
        $this->run(array('quickscan' => 1), 'quickscan', $assoc_args);
    }

    /**
     * Verifies core, plugins and themes against the official wordpress.org packages.
     *
     * ## OPTIONS
     *
     * [--restore]
     * : Restore MODIFIED and MISSING files from the official package zips (byte-verified first). Take a backup.
     *
     * [--dryrun]
     * : With --restore: report what would be restored without writing.
     *
     * [--quarantine-dir=<path>]
     * : With --restore: copy each original aside (as *.quarantine) before overwriting. Keep it outside the webroot.
     *
     * [--checksum-dir=<path>]
     * : Pre-downloaded manifests/packages instead of the network.
     *
     * [--locale=<locale>]
     * : Core locale for the checksum lookup (default en_US).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward integrity
     *     wp elderward integrity --restore --dryrun
     *     wp elderward integrity --restore --quarantine-dir=/safe/place
     *
     * @when after_wp_load
     */
    public function integrity($args, $assoc_args)
    {
        $options = array('scanintegrity' => 1);
        $this->copy_flag($assoc_args, 'restore', $options, 'restore');
        $this->copy_flag($assoc_args, 'dryrun', $options, 'dryrun');
        $this->copy_option($assoc_args, 'quarantine-dir', $options, 'quarantinedir');
        $this->copy_option($assoc_args, 'checksum-dir', $options, 'checksumdir');
        $this->copy_option($assoc_args, 'locale', $options, 'locale');
        $this->run($options, 'scanintegrity', $assoc_args);
    }

    /**
     * Timestamp anomaly report (files modified apart from their package). Report-only.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function times($args, $assoc_args)
    {
        $this->run(array('scantimes' => 1), 'scantimes', $assoc_args);
    }

    /**
     * Read-only database scan: administrators, injected options, siteurl/home, active_plugins, posts.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function db($args, $assoc_args)
    {
        $this->run(array('scandb' => 1), 'scandb', $assoc_args);
    }

    /**
     * Checks the current user's crontab for known persistence patterns.
     *
     * ## OPTIONS
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * @when after_wp_load
     */
    public function cron($args, $assoc_args)
    {
        $this->run(array('scancron' => 1), 'scancron', $assoc_args);
    }

    /**
     * Scans an access log (file or directory, .gz supported) for indicators of compromise.
     *
     * ## OPTIONS
     *
     * <path>
     * : Access log file or directory of logs.
     *
     * [--correlate]
     * : Also report files whose mtime falls within --window seconds of flagged traffic.
     *
     * [--window=<seconds>]
     * : Correlation window (default 300, minimum 60).
     *
     * [--format=<format>]
     * : text (default) or json.
     *
     * ## EXAMPLES
     *
     *     wp elderward log /var/log/apache2/access.log
     *     wp elderward log /var/log/apache2 --correlate
     *
     * @when after_wp_load
     */
    public function log($args, $assoc_args)
    {
        $options = array('scanlog' => $args[0]);
        $this->copy_flag($assoc_args, 'correlate', $options, 'correlate');
        $this->copy_option($assoc_args, 'window', $options, 'window');
        $this->run($options, 'scanlog', $assoc_args);
    }

    private function copy_option(array $assoc_args, $from, array &$options, $to)
    {
        if (isset($assoc_args[$from]) && '' !== $assoc_args[$from]) {
            $options[$to] = $assoc_args[$from];
        }
    }

    private function copy_flag(array $assoc_args, $from, array &$options, $to)
    {
        if (!empty($assoc_args[$from])) {
            $options[$to] = 1;
        }
    }

    private function run(array $options, $mode, array $assoc_args)
    {
        $json = isset($assoc_args['format']) && 'json' === strtolower($assoc_args['format']);
        if ($json) {
            $options['format'] = 'json';
        }
        $reporter = $json ? new Elderward\Engine\JsonReporter() : new Elderward\Engine\TextReporter();
        $ctx = Elderward_Plugin::make_context($options, $reporter);

        try {
            Elderward\Engine\Runner::run_mode($ctx, $mode);
        } catch (Elderward\Engine\Fatal $e) {
            if ($reporter instanceof Elderward\Engine\TextReporter) {
                $reporter->flush_buffered();
            }
            $reporter->fatal($e->getMessage());
            WP_CLI::halt(1);
        }
        WP_CLI::halt($reporter->exit_code());
    }
}
