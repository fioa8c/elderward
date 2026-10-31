<?php
////////////////
// Elderward standalone CLI.
//
// Runs the scanning engine without WordPress: upload the plugin folder (or
// just bin/ and includes/engine/) to a host and run
//
//   php bin/elderward.php scanall=1 scandirectory=/path/to/wp-root
//
// Options are key=value pairs, parsed like a URL query string. This file
// refuses to run over the web: use the WordPress admin page for that.
//////////////

if (PHP_SAPI !== 'cli') {
    if (!headers_sent()) {
        header('HTTP/1.1 403 Forbidden');
    }
    exit(1);
}

/////////////////
// Setting errors to show up
////////////////
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

////////////////
// Limiting script's runtime and memory available
///////////////
ini_set('max_execution_time', 3000);
ini_set('memory_limit', '96M');

require_once dirname(__DIR__) . '/includes/engine/load.php';

use Elderward\Engine\Context;
use Elderward\Engine\CurlHttp;
use Elderward\Engine\Fatal;
use Elderward\Engine\JsonReporter;
use Elderward\Engine\MysqliDb;
use Elderward\Engine\Runner;
use Elderward\Engine\TextReporter;

//////////////
// Accepting key=value options through the command line
/////////////
$options = array();
parse_str(implode('&', array_slice($argv, 1)), $options);

// Scan directory defaults to the current working directory.
if (!isset($options['scandirectory'])) {
    $options['scandirectory'] = getcwd();
}

////////////
// Usage / help screen
///////////
if (isset($options['help'])) {
    echo "Elderward - malware scanner and cleanup utility\n";
    echo "\n";
    echo "Usage:  php bin/elderward.php [option=value ...]\n";
    echo "        (inside WordPress: wp elderward <command>, or Tools > Elderward)\n";
    echo "\n";
    echo "Options:\n";
    echo "  scandirectory=/path   Directory to scan for malware (default: current directory)\n";
    echo "  allfiles=1            Scan every file, not just known-risky extensions\n";
    echo "  dryrun=1              Report what would be cleaned without writing any file\n";
    echo "  scancron=1            Scan the current user's crontab for known malicious entries\n";
    echo "  scanlog=/path         Scan an access log (file or directory of logs, .gz supported)\n";
    echo "                        for known indicators of compromise, then exit\n";
    echo "  correlate=1           With scanlog: also report files under scandirectory whose\n";
    echo "                        mtime falls within window (default 300s) of flagged traffic\n";
    echo "  window=seconds        Correlation window around flagged requests (min 60)\n";
    echo "  scanintegrity=1       Verify core, plugin and theme files against the official\n";
    echo "                        wordpress.org packages (themes need the PHP zip extension).\n";
    echo "                        scandirectory must be the WordPress root (default: current dir)\n";
    echo "  checksumdir=/path     Use pre-downloaded manifests and packages instead of the network\n";
    echo "                        (core-{version}.json, plugin-{slug}-{version}.json,\n";
    echo "                        theme-{slug}-{version}.zip; *.zip of core/plugins for restore)\n";
    echo "  locale=xx_XX          Core locale for the checksum lookup (default: en_US)\n";
    echo "  restore=1             With scanintegrity: restore MODIFIED and MISSING files from\n";
    echo "                        the official package zips (byte-verified against the checksum\n";
    echo "                        manifest before writing; honors dryrun=1). EXTRA files are\n";
    echo "                        never touched. Take a backup first.\n";
    echo "  quarantinedir=/path   With restore: copy each original aside (as *.quarantine)\n";
    echo "                        before overwriting, preserving evidence. Keep it outside\n";
    echo "                        the webroot.\n";
    echo "  scantimes=1           Report timestamp anomalies (files modified apart from their\n";
    echo "                        package, possible faked mtimes). Report-only heuristics.\n";
    echo "                        scandirectory must be the WordPress root (default: current dir)\n";
    echo "  scandb=1              Scan the WordPress database (read-only, credentials from\n";
    echo "                        wp-config.php): administrator inventory and recent admins,\n";
    echo "                        injected options, siteurl/home hijacks, active_plugins\n";
    echo "                        tampering, script/PHP injections in posts\n";
    echo "  quickscan=1           Quick high-signal checks: PHP in uploads, auto_prepend_file\n";
    echo "                        directives, mu-plugins inventory, hidden PHP files.\n";
    echo "                        scandirectory must be the WordPress root (default: current dir)\n";
    echo "  scanall=1             Run every scanner (report-only) against the WordPress root\n";
    echo "                        and print one severity-sorted report. Add scanlog=/path to\n";
    echo "                        include log IoCs and correlation.\n";
    echo "  format=json           Machine-readable output: one JSON event per line on stdout\n";
    echo "                        (findings and summaries); progress goes to stderr\n";
    echo "  help=1                Show this help\n";
    echo "\n";
    echo "Exit codes: 0 clean (or INFO-only findings), 1 usage/fatal error,\n";
    echo "            2 LOW/MEDIUM/ERROR findings, 3 HIGH findings\n";
    echo "\n";
    echo "Arguments are parsed like a URL query string: encode '+' as %2B and '%' as %25\n";
    echo "in paths, and quote paths containing spaces or '&'.\n";
    exit(0);
}

$json = (isset($options['format']) && 'json' === strtolower($options['format']));
$reporter = $json ? new JsonReporter() : new TextReporter();
$ctx = new Context($options, $reporter, new CurlHttp(), new MysqliDb(), dirname(__DIR__));

try {
    $mode = Runner::mode_from_options($ctx);
    Runner::run_mode($ctx, $mode);
} catch (Fatal $e) {
    // Findings buffered by scanall still get printed before the error.
    if ($reporter instanceof TextReporter) {
        $reporter->flush_buffered();
    }
    $reporter->fatal($e->getMessage());
    exit(1);
}

exit($reporter->exit_code());
