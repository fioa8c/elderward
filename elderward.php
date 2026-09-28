<?php
/////////////////
// Setting errors to show up
////////////////
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

////////////////
// Limiting script's runtime and memory avilable
///////////////
ini_set('max_execution_time', 3000);
ini_set('memory_limit','96M');

//////////////
// Accepting GET through CLI
/////////////
function isTerminal()
{
    return PHP_SAPI === 'cli';
}

if (isTerminal())  parse_str(implode('&', array_slice($argv, 1)), $_GET);

////////////
// Web access is disabled by default. To run this over HTTP (e.g. a host with
// no shell access), set a token here and pass it on every request as &token=...
///////////
define('WEB_ACCESS_TOKEN', '');

if (!isTerminal()) {
    if (WEB_ACCESS_TOKEN === ''
        || !isset($_GET['token'])
        || !hash_equals(WEB_ACCESS_TOKEN, (string) $_GET['token'])) {
        http_response_code(403);
        die("Forbidden\n");
    }
}

/////////////
// Loading defaults
// Scan Dir will get the CWD
////////////
if (! isset($_GET['scandirectory'])) {

  $_GET['scandirectory'] = getcwd();

}

////////////
// Usage / help screen
///////////
if (isset($_GET['help'])) {
    echo "Elderward - malware scanner and cleanup utility\n";
    echo "\n";
    echo "Usage (CLI):  php elderward.php [option=value ...]\n";
    echo "Usage (web):  elderward.php?token=...&option=value  (requires WEB_ACCESS_TOKEN to be set)\n";
    echo "\n";
    echo "Options:\n";
    echo "  scandirectory=/path   Directory to scan for malware (default: current directory)\n";
    echo "  scan_all=1            Scan every file, not just known-risky extensions\n";
    echo "  dryrun=1              Report what would be cleaned without writing any file\n";
    echo "  scancron=1            Scan the current user's crontab for known malicious entries\n";
    echo "  scanlog=/path         Scan an access log (file or directory of logs, .gz supported)\n";
    echo "                        for known indicators of compromise, then exit\n";
    echo "  correlate=1           With scanlog: also report files under scandirectory whose\n";
    echo "                        mtime falls within window (default 300s) of flagged traffic\n";
    echo "  window=seconds        Correlation window around flagged requests (min 60)\n";
    echo "  scanintegrity=1       Verify core and plugin files against wordpress.org checksums.\n";
    echo "                        scandirectory must be the WordPress root (default: current dir)\n";
    echo "  checksumdir=/path     Use pre-downloaded checksum manifests instead of the network\n";
    echo "                        (core-{version}.json, plugin-{slug}-{version}.json)\n";
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
    die();
}

function write_cleaned_file($file_path, $cleaned_conent)
{
    // Write to a temp file and rename over the target so the original is never
    // truncated in place by a partial write (disk full, killed mid-write).
    $tmp_path = @tempnam(dirname($file_path), basename($file_path) . '.');
    if (false === $tmp_path) {
        return (false);
    }

    $written = @file_put_contents($tmp_path, $cleaned_conent);
    if ($written !== strlen($cleaned_conent)) {
        @unlink($tmp_path);
        return (false);
    }

    // tempnam creates the file 0600; carry over the target's permissions.
    $perms = @fileperms($file_path);
    if (false !== $perms) {
        @chmod($tmp_path, $perms & 0777);
    } else {
        // No existing target (restoring a deleted file): 0600 would be
        // unreadable to the web server.
        @chmod($tmp_path, 0644);
    }

    if (!@rename($tmp_path, $file_path)) {
        @unlink($tmp_path);
        return (false);
    }
    return (true);
}

////////////////
// Unified finding format, shared by every scanner. Text mode (default):
//
//   SEVERITY,TYPE,path,detail
//
// The first three fields never contain commas; everything after the third
// comma is free-form detail. Severities: HIGH, MEDIUM, LOW, INFO, ERROR.
// Indented lines under a finding are supporting context (log examples etc).
//
// Paths and details come from a compromised host, so the attacker chooses
// them: '%', control characters, and (in the path field) commas are
// percent-encoded so a crafted filename cannot shift fields or inject
// fake finding lines into the report.
//
// format=json switches stdout to NDJSON, one event object per line:
//   {"event":"finding","severity":...,"type":...,"path":...,"detail":...}
//   {"event":"summary","scan":...,...counts...}
// Fields carry raw values (json_encode escapes them safely) and progress
// text moves to STDERR, so stdout is pure machine-readable events.
//
// The exit code reflects the worst finding: 0 clean (or INFO only),
// 1 usage/fatal error, 2 LOW/MEDIUM/ERROR findings, 3 HIGH findings.
//////////////

$FINDINGS_EXIT_CODE = 0;
// When scanall=1 runs in text mode, findings buffer here and print
// severity-sorted at the end; null means report immediately.
$SCANALL_FINDINGS = null;

function json_output()
{
    return (isset($_GET['format']) && 'json' === strtolower($_GET['format']));
}

function progress($text)
{
    // Informational text: normal output in text mode; in JSON mode it must
    // stay off stdout, so it goes to STDERR (CLI) or nowhere (web).
    if (!json_output()) {
        echo $text;
        return;
    }
    if (defined('STDERR')) {
        fwrite(STDERR, $text);
    }
}

function sanitize_finding_field($text, $encode_commas)
{
    $text = str_replace('%', '%25', (string) $text);
    if ($encode_commas) {
        $text = str_replace(',', '%2C', $text);
    }
    return preg_replace_callback('/[\x00-\x1F\x7F]/', function ($match) {
        return sprintf('%%%02X', ord($match[0]));
    }, $text);
}

function print_text_finding($finding)
{
    echo $finding['severity'] . ',' . $finding['type'] . ','
        . sanitize_finding_field($finding['path'], true) . ','
        . sanitize_finding_field($finding['detail'], false) . "\n";
    foreach ($finding['context'] as $context_line) {
        echo '    ' . sanitize_finding_field($context_line, false) . "\n";
    }
}

function report_finding($severity, $type, $path, $detail, $context = array())
{
    global $FINDINGS_EXIT_CODE, $SCANALL_FINDINGS;

    if ('HIGH' === $severity) {
        $FINDINGS_EXIT_CODE = max($FINDINGS_EXIT_CODE, 3);
    } elseif ('INFO' !== $severity) {
        $FINDINGS_EXIT_CODE = max($FINDINGS_EXIT_CODE, 2);
    }

    if (json_output()) {
        $event = array('event' => 'finding', 'severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail);
        if (!empty($context)) {
            $event['context'] = $context;
        }
        echo json_encode($event) . "\n";
        return;
    }

    $finding = array('severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail, 'context' => $context);
    if (is_array($SCANALL_FINDINGS)) {
        $SCANALL_FINDINGS[] = $finding;
        return;
    }
    print_text_finding($finding);
}

function emit_summary($scan, $data, $text)
{
    if (json_output()) {
        echo json_encode(array_merge(array('event' => 'summary', 'scan' => $scan), $data)) . "\n";
        return;
    }
    echo $text;
}

function scan_exit()
{
    global $FINDINGS_EXIT_CODE;
    exit($FINDINGS_EXIT_CODE);
}

function recursive_file_iterator($dir)
{
    // CATCH_GET_CHILD: an unreadable subdirectory is skipped instead of
    // aborting the whole walk.
    return new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );
}

function is_scannable_file($file)
{
    global $extensions_to_check;

    // Never scan (or correlate) this script itself.
    if ($file->getRealPath() === __FILE__) {
        return (false);
    }
    return isset($_GET['scan_all'])
        || in_array(strtolower($file->getExtension()), $extensions_to_check, true);
}

function require_wordpress_root($root)
{
    $root = rtrim($root, '/');
    if (!is_file($root . '/wp-includes/version.php')) {
        echo 'Error: ' . $root . " does not look like a WordPress root (wp-includes/version.php not found)\n";
        exit(1);
    }
    return ($root);
}


////////////////
// Cleanup signatures.
//
// Each entry is keyed by a unique signature name and holds:
//
//   'prefilter'  One cheap condition, checked first on every file. It counts
//                as confirmed evidence, so it does not need to be repeated
//                in the triggers.
//   'triggers'   Zero or more further conditions that must ALL also match
//                before the file is considered infected.
//   'action'     What to do with a confirmed file.
//
// A condition is array('string' => needle) (fast strpos lookup, preferred
// for the prefilter) or array('regex' => pattern). Regexes are full PCRE
// patterns: bring your own delimiters and flags.
//
// Actions:
//   array('remove_regex' => pattern)   Delete every match of the pattern
//                                      from the file. Fails (and reports)
//                                      if nothing was removed.
//   array('delete_file' => true)       Delete the whole file.
//
// Every pattern is compile-checked at startup, so a malformed regex stops
// the run with the signature's name instead of silently never matching.
//////////////


$CLEANUP_SIGNATURES = array(
    'javascript_ndsw' => array(
        'prefilter' => array('regex' => '/if\((typeof)?\s*nds.===.?undefined.?\)/'),
        'triggers'  => array(
            array('regex' => '/\w\s*=\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*/'),
        ),
        'action'    => array('remove_regex' => '/if\((typeof)?\s*nds.===.?undefined.?\)[^#]+return\s*A\s*\(\s*\)\s*;?\s*}\s*}\s*;?/s'),
    ),
    'javascript_wqpq' => array(
        'prefilter' => array('regex' => '/if\((typeof)?\s*wqpq\s*===.?undefined.?\)/'),
        'triggers'  => array(
            array('regex' => '/try{var\s*\w\s*=\s*\-?parseInt\(\w\(0x\d+,\s*.\w+/'),
        ),
        'action'    => array('remove_regex' => '/if\((typeof)?\s*\w+.?===.?undefined.?\)[^\n]+;\s*\}\s*\}\s*\(\s*\)\s*\);\s*\};/s'),
    ),
);


////////////////
//
//  Engine for custom signatures
//
//
//////////////

// Check crontab for potential malware.
$CRONTAB_SIGS = array(
	array( 'crontab.tmp.001' => '@\* \* (\/var)?\/tmp\/@'),
	array( 'crontab.tmp.002' => '@php -q [^\.]+\/\.cron@'),
    array( 'crontab.tmp.003' => '@wget\shttp[^-]*\.txt\s*\-O\s\/wp-\w+\/[^>]*\>\/dev\/null;\sfetch\s-o\s\/wp-\w+[^\>]*\.txt\s\>.dev.null\s*2>\&1;\stouch\s-t\s\d+\s\/wp-\w+[^;]*null;\schmod\s0755[^;]*null;\srm\s-f\s+[^;]*null;\stouch\s-t\s\d+\s[^>]*\>.dev.null@'),
    array( 'crontab.tmp.004' => '@&& chmod 0755 xxxd@'),
    array( 'crontab.tmp.004.02' => '@(wget|curl) .+&& \/bin\/sh \w{4,} \/[^&]+&& rm -f \w@'),
    array( 'crontab.tmp.005' => '@.php && chmod +x /@'),
    array( 'crontab.tmp.006' => '@\|\s*base64 --decode\s*>@'),
    array( 'crontab.tmp.007' => '@\.file_get_contents\(.https:\/\/bit.ly\/\w@'),
    array( 'crontab.tmp.008' => '@\|base64 -d\|gunzip -c\)@'),
    array( 'crontab.tmp.009' => '@https:\/\/pastebin.com\/raw@'),
    array( 'crontab.tmp.010' => '@eval.gzinflate.base64_decode@'),
);

function scanCronTab()
{
    global $CRONTAB_SIGS;

    if (function_exists('shell_exec')) {
        $output = @shell_exec('crontab -l 2>/dev/null');
        if (is_string($output) && is_array($CRONTAB_SIGS)) {
            $lines = explode("\n", $output);

            foreach ($lines as $line) {
                if ((trim($line) === "") || ((strlen($line) > 0) && ('#'==$line[0]))) {
                    continue;
                }

                foreach ($CRONTAB_SIGS as $item) {
                    foreach ($item as $name => $pattern) {
                        if (preg_match($pattern, $line)) {
                            report_finding('HIGH', 'CRONTAB_IOC', 'crontab', $name . ': ' . $line);
                            break 2;
                        }
                    }
                }
            }
        }
    }
}

///////////////
// Access log IoC signatures.
// Each signature matches one line of a common/combined format access log.
// "threshold" hides findings until that many hits are seen: a single POST to
// wp-login.php is normal traffic, five hundred of them is a brute force.
// Findings report as MEDIUM (attack attempts) unless the signature sets
// "severity" - traffic to a shell already on disk is HIGH.
//////////////
$ACCESS_LOG_SIGS = array(
    array(
        'name'        => 'access.uploads.php',
        'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*wp-content/uploads/[^"\s]*\.ph(?:p[34578]?|tml|ps|t)\b@i',
        'threshold'   => 1,
        'severity'    => 'HIGH',
        'description' => 'PHP file requested inside wp-content/uploads. Uploads should never contain executable PHP; this is usually a webshell dropped through an upload form.',
    ),
    array(
        'name'        => 'access.webshell.names',
        'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*(?:wso\d*|filesman|alfa(?:-rex|_data)?|b374k|c99(?:shell)?|r57|indoxploit|mini_?shell|webshell|priv8)[^"\s]*\.ph@i',
        'threshold'   => 1,
        'severity'    => 'HIGH',
        'description' => 'Request to a well-known webshell filename (WSO, FilesMan, AlfaShell, c99, r57, ...).',
    ),
    array(
        'name'        => 'access.adminer',
        'pattern'     => '@"(?:GET|POST) /[^"\s]*adminer[^"\s]*\.php@i',
        'threshold'   => 1,
        'description' => 'Request to an Adminer database client. Attackers drop it to reuse the credentials from wp-config.php against the database.',
    ),
    array(
        'name'        => 'access.wp-file-manager.rce',
        'pattern'     => '@wp-file-manager/lib/php/connector\.minimal\.php@i',
        'threshold'   => 1,
        'description' => 'Request to wp-file-manager connector.minimal.php, exploited for unauthenticated file upload (CVE-2020-25213).',
    ),
    array(
        'name'        => 'access.revslider',
        'pattern'     => '@admin-ajax\.php\?[^"\s]*action=revslider@i',
        'threshold'   => 1,
        'description' => 'Slider Revolution admin-ajax action, exploited for arbitrary file download/upload in old plugin versions.',
    ),
    array(
        'name'        => 'access.timthumb',
        'pattern'     => '@timthumb\.php\?[^"\s]*src=https?@i',
        'threshold'   => 1,
        'description' => 'TimThumb remote-source request, exploited for remote file inclusion in old theme bundles.',
    ),
    array(
        'name'        => 'access.setup-config',
        'pattern'     => '@"(?:GET|POST) /[^"\s]*wp-admin/(?:setup-config|install)\.php@i',
        'threshold'   => 1,
        'description' => 'Access to the WordPress installer/setup-config, used to take over half-finished or broken installs.',
    ),
    array(
        'name'        => 'access.env.probe',
        'pattern'     => '@"(?:GET|POST) /[^"\s]*\.env(?:\.\w+)?["\s]@i',
        'threshold'   => 1,
        'description' => 'Probe for a .env file, hunting for exposed credentials.',
    ),
    array(
        'name'        => 'access.traversal',
        'pattern'     => '@"(?:GET|POST|HEAD) /[^"]*\.\./\.\./@',
        'threshold'   => 1,
        'description' => 'Directory traversal attempt (../../) in the request path or query string.',
    ),
    array(
        'name'        => 'access.query.code-injection',
        'pattern'     => '@"(?:GET|POST) /[^"]*(?:eval\(|base64_decode|gzinflate|call_user_func|assert\()@i',
        'threshold'   => 1,
        'description' => 'PHP code passed in the request, a code injection attempt against a vulnerable plugin or theme.',
    ),
    array(
        'name'        => 'access.query.php-ini-injection',
        'pattern'     => '@(?:auto_prepend_file|allow_url_include|disable_functions)=@i',
        'threshold'   => 1,
        'description' => 'php.ini directives in the query string, a PHP-CGI argument injection attempt (CVE-2012-1823 / CVE-2024-4577).',
    ),
    array(
        'name'        => 'access.user.enumeration',
        'pattern'     => '@"GET /[^"\s]*(?:wp-json/wp/v2/users|\?author=\d)@i',
        'threshold'   => 10,
        'description' => 'Username enumeration through the REST API or ?author= redirects, usually reconnaissance before a brute force.',
    ),
    array(
        'name'        => 'access.xmlrpc.flood',
        'pattern'     => '@"POST /[^"\s]*xmlrpc\.php@i',
        'threshold'   => 50,
        'description' => 'High volume of xmlrpc.php POSTs, typically credential brute forcing via system.multicall or pingback abuse.',
    ),
    array(
        'name'        => 'access.wp-login.bruteforce',
        'pattern'     => '@"POST /[^"\s]*wp-login\.php@i',
        'threshold'   => 50,
        'description' => 'High volume of wp-login.php POSTs, a login brute force.',
    ),
);

function parse_log_timestamp($line)
{
    // Common/combined log format: [20/Sep/2026:10:05:01 +0000]
    if (!preg_match('@\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]@', $line, $matches)) {
        return (null);
    }
    $parsed = DateTime::createFromFormat('d/M/Y:H:i:s O', $matches[1]);
    return (false === $parsed) ? null : $parsed->getTimestamp();
}

function merge_flagged_minutes(&$into, $from)
{
    foreach ($from as $minute => $bucket) {
        if (!isset($into[$minute])) {
            $into[$minute] = $bucket;
            continue;
        }
        $into[$minute]['count'] += $bucket['count'];
        $into[$minute]['names'] = array_merge($into[$minute]['names'], $bucket['names']);
    }
}

function read_log_line($fh, $is_gzipped)
{
    ///////////////
    // Return one whole logical line so a signature can never be evaded by
    // padding a request until the match straddles a read boundary. Lines
    // beyond 64KB are scanned truncated and the remainder discarded, so an
    // absurd line still cannot balloon memory.
    //////////////
    $max_line_length = 65536;
    $line = '';
    while (true) {
        $chunk = $is_gzipped ? gzgets($fh, 8192) : fgets($fh, 8192);
        if (false === $chunk) {
            return ('' === $line) ? false : $line;
        }
        $line .= $chunk;
        if ("\n" === substr($chunk, -1)) {
            return ($line);
        }
        if (strlen($line) >= $max_line_length) {
            // Discard the rest of this oversized line.
            while (true) {
                $chunk = $is_gzipped ? gzgets($fh, 8192) : fgets($fh, 8192);
                if (false === $chunk || "\n" === substr($chunk, -1)) {
                    return ($line);
                }
            }
        }
    }
}

function new_log_accumulator()
{
    // Hits accumulate ACROSS log files, so a brute force split over rotated
    // logs still crosses its signature's reporting threshold.
    return array('counts' => array(), 'examples' => array(), 'ips' => array(), 'minutes' => array());
}

function scanAccessLog($log_path, &$acc)
{
    global $ACCESS_LOG_SIGS;

    ///////////////
    // Logs are streamed line by line (never loaded whole) so rotated
    // multi-hundred-MB logs stay within the memory limit. Gzipped
    // rotations are read through zlib when available.
    //////////////
    $is_gzipped = ('gz' === strtolower(pathinfo($log_path, PATHINFO_EXTENSION)));
    if ($is_gzipped && !function_exists('gzopen')) {
        progress('Error: zlib not available, skipping compressed log ' . $log_path . "\n");
        return;
    }

    $fh = $is_gzipped ? @gzopen($log_path, 'r') : @fopen($log_path, 'r');
    if (false === $fh) {
        progress('Error reading ' . $log_path . "\n");
        return;
    }

    $max_examples = 5;
    $max_example_length = 300;
    $hit_counts = &$acc['counts'];
    $hit_examples = &$acc['examples'];
    $hit_ips = &$acc['ips'];
    // Per-signature, per-minute buckets of matched lines, kept for the
    // correlate mode. Minute granularity bounds memory on flooded logs.
    $hit_minutes = &$acc['minutes'];

    while (true) {
        $line = read_log_line($fh, $is_gzipped);
        if (false === $line) {
            break;
        }

        foreach ($ACCESS_LOG_SIGS as $signature) {
            // Only an explicit 1 counts as a match; false (engine error) must not flag.
            if (preg_match($signature['pattern'], $line) !== 1) {
                continue;
            }

            $name = $signature['name'];
            $hit_counts[$name] = isset($hit_counts[$name]) ? $hit_counts[$name] + 1 : 1;

            if (!isset($hit_examples[$name])) {
                $hit_examples[$name] = array();
                $hit_ips[$name] = array();
            }
            if (count($hit_examples[$name]) < $max_examples) {
                $hit_examples[$name][] = substr(trim($line), 0, $max_example_length);
            }

            // Common/combined log lines start with the client IP.
            $ip = strtok(trim($line), ' ');
            if (false !== filter_var($ip, FILTER_VALIDATE_IP)) {
                $hit_ips[$name][$ip] = isset($hit_ips[$name][$ip]) ? $hit_ips[$name][$ip] + 1 : 1;
            }

            $timestamp = parse_log_timestamp($line);
            if (null !== $timestamp) {
                $minute = $timestamp - ($timestamp % 60);
                if (!isset($hit_minutes[$name][$minute])) {
                    $hit_minutes[$name][$minute] = array(
                        'count'   => 0,
                        'names'   => array($name => true),
                        'example' => substr(trim($line), 0, $max_example_length),
                    );
                }
                $hit_minutes[$name][$minute]['count']++;
            }

            // First matching IoC wins for this line.
            break;
        }
    }
    $is_gzipped ? gzclose($fh) : fclose($fh);
}

function report_log_findings($acc, $target_label)
{
    global $ACCESS_LOG_SIGS;

    $hit_counts = $acc['counts'];
    $hit_examples = $acc['examples'];
    $hit_ips = $acc['ips'];
    $hit_minutes = $acc['minutes'];

    ///////////////
    // Report: every signature at or over its threshold, with example lines,
    // then the source IPs behind the reported hits.
    //////////////
    progress("== Access log IoC report: " . $target_label . " ==\n");

    $reported = 0;
    $reported_ips = array();
    $flagged_minutes = array();
    foreach ($ACCESS_LOG_SIGS as $signature) {
        $name = $signature['name'];
        if (!isset($hit_counts[$name]) || $hit_counts[$name] < $signature['threshold']) {
            continue;
        }
        $reported++;
        if (isset($hit_minutes[$name])) {
            merge_flagged_minutes($flagged_minutes, $hit_minutes[$name]);
        }

        $severity = isset($signature['severity']) ? $signature['severity'] : 'MEDIUM';
        $context = array();
        foreach ($hit_examples[$name] as $example) {
            $context[] = 'e.g. ' . $example;
        }
        report_finding($severity, 'LOG_IOC', $target_label, $name . ': ' . $hit_counts[$name] . ' hit(s) - ' . $signature['description'], $context);

        foreach ($hit_ips[$name] as $ip => $count) {
            $reported_ips[$ip] = isset($reported_ips[$ip]) ? $reported_ips[$ip] + $count : $count;
        }
    }

    if (0 === $reported) {
        emit_summary('scanlog', array('flagged_signatures' => 0), "No known IoCs found.\n");
        return (array());
    }

    arsort($reported_ips);
    $top_ips = array_slice($reported_ips, 0, 10, true);
    $text = "Top source IPs on flagged requests:\n";
    foreach ($top_ips as $ip => $count) {
        $text .= "    " . $ip . " (" . $count . " hits)\n";
    }
    emit_summary('scanlog', array('flagged_signatures' => $reported, 'top_ips' => $top_ips), $text);

    return ($flagged_minutes);
}

function scanLogTarget($target)
{
    $acc = new_log_accumulator();

    if (is_file($target)) {
        scanAccessLog($target, $acc);
        return (report_log_findings($acc, $target));
    }

    if (!is_dir($target) || !is_readable($target)) {
        echo 'Error: cannot open log target ' . $target . "\n";
        exit(1);
    }

    ///////////////
    // A directory target scans everything in it that looks like an access
    // log (access*, *.log, rotated *.log.N and *.log.N.gz) into ONE shared
    // accumulator, so thresholds apply to the traffic as a whole rather
    // than per rotation. Error logs have a different format: skipped.
    //////////////
    $files = recursive_file_iterator($target);

    $logs_found = 0;
    foreach ($files as $file) {
        $basename = $file->getFilename();
        if (preg_match('@error@i', $basename)) {
            continue;
        }
        if (preg_match('@(?:access[^/]*|\.log(?:\.\d+)?(?:\.gz)?)$@i', $basename) !== 1) {
            continue;
        }
        progress('Scanning ' . $file->getPathname() . "\n");
        scanAccessLog($file->getPathname(), $acc);
        $logs_found++;
    }

    if (0 === $logs_found) {
        progress('No access log files found in ' . $target . "\n");
        return (array());
    }
    return (report_log_findings($acc, $target));
}

function correlate_files($root, $flagged_minutes, $window)
{
    ///////////////
    // The IR smoking gun: a file whose mtime falls inside the window around
    // flagged attack traffic. Report-only - a hit is a strong lead, but a
    // miss clears nothing (later edits and faked mtimes erase the link).
    //////////////
    if (empty($flagged_minutes)) {
        progress("Correlation: no flagged log traffic to correlate against.\n");
        return;
    }
    if (!is_dir($root) || !is_readable($root)) {
        echo 'Error: cannot open correlation directory ' . $root . "\n";
        exit(1);
    }

    $files = recursive_file_iterator($root);

    $correlated = 0;
    foreach ($files as $file) {
        if (!is_scannable_file($file)) {
            continue;
        }

        // filemtime, not SplFileInfo::getMTime - the latter throws (even
        // through @) when the file vanishes between listing and stat.
        $mtime = @filemtime($file->getPathname());
        if (false === $mtime) {
            continue;
        }

        // Walk the minute buckets covering [mtime - window, mtime + window].
        $in_window = array('count' => 0, 'names' => array(), 'example' => '');
        $start = ($mtime - $window) - (($mtime - $window) % 60);
        for ($minute = $start; $minute <= ($mtime + $window); $minute += 60) {
            if (!isset($flagged_minutes[$minute])) {
                continue;
            }
            $in_window['count'] += $flagged_minutes[$minute]['count'];
            $in_window['names'] += $flagged_minutes[$minute]['names'];
            if ('' === $in_window['example']) {
                $in_window['example'] = $flagged_minutes[$minute]['example'];
            }
        }
        if (0 === $in_window['count']) {
            continue;
        }

        $path = $file->getPathname();
        $severity = is_php_file($path) ? 'HIGH' : 'MEDIUM';
        report_finding($severity, 'LOG_FILE_CORRELATION', $path,
            'modified ' . date('Y-m-d H:i:s', $mtime) . ' within ' . $window . 's of flagged traffic: '
            . implode(' ', array_keys($in_window['names'])) . ' (' . $in_window['count'] . ' flagged requests in window)',
            array('e.g. ' . $in_window['example']));
        $correlated++;
    }

    emit_summary('correlate', array('correlated' => $correlated, 'window_seconds' => $window),
        'Correlation complete: ' . $correlated . ' file(s) modified within ' . $window
        . "s of flagged traffic. Later edits or faked mtimes erase this link - a miss clears nothing.\n");
}

////////////////
//
// Integrity checking against wordpress.org reference checksums
//
//////////////

function http_get($url)
{
    // This tool runs on already-compromised hosts: never disable TLS
    // verification, or the "all clean" answer can be attacker-supplied.
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'elderward',
        ));
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return array((false === $body) ? 0 : $status, (string) $body);
    }

    $context = stream_context_create(array('http' => array(
        'timeout'       => 60,
        'user_agent'    => 'elderward',
        'ignore_errors' => true,
    )));
    $body = @file_get_contents($url, false, $context);
    $status = isset($http_response_header) ? status_from_response_headers($http_response_header) : 0;
    return array($status, (false === $body) ? '' : $body);
}

function status_from_response_headers($headers)
{
    // With redirects the array holds several header blocks; the last
    // status line is the one for the final response.
    $status = 0;
    if (is_array($headers)) {
        foreach ($headers as $header_line) {
            if (preg_match('@^HTTP/\S+\s(\d{3})@', $header_line, $matches)) {
                $status = (int) $matches[1];
            }
        }
    }
    return ($status);
}

function fetch_reference_checksums($url, $offline_name)
{
    ///////////////
    // checksumdir=/path switches to pre-downloaded manifests for hosts with
    // no outbound network: {checksumdir}/{offline_name} holds the same JSON
    // the wordpress.org API would have returned.
    //////////////
    if (isset($_GET['checksumdir'])) {
        $offline_path = rtrim($_GET['checksumdir'], '/') . '/' . $offline_name;
        if (!is_file($offline_path)) {
            return array('notfound', null);
        }
        $body = @file_get_contents($offline_path);
        if (false === $body) {
            return array('error', null);
        }
    } else {
        list($status, $body) = http_get($url);
        if (404 === $status) {
            return array('notfound', null);
        }
        if (200 !== $status || '' === $body) {
            return array('error', null);
        }
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        return array('error', null);
    }
    return array('ok', $decoded);
}

function is_php_file($path)
{
    return (preg_match('@\.(?:ph(?:p[34578]?|t|tml|ps)|inc)$@i', $path) === 1);
}

function md5_in_list($actual_md5, $expected)
{
    // The plugin checksum API returns a string, or an array of valid
    // checksums when a release was ever repackaged.
    foreach ((array) $expected as $candidate) {
        if (null !== $candidate && hash_equals(strtolower((string) $candidate), $actual_md5)) {
            return (true);
        }
    }
    return (false);
}

function list_files_recursive($dir, $base)
{
    $relative_paths = array();
    $walker = recursive_file_iterator($dir);
    $base_length = strlen(rtrim($base, '/')) + 1;
    foreach ($walker as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $relative_paths[] = str_replace('\\', '/', substr($file->getPathname(), $base_length));
    }
    return $relative_paths;
}

///////////////
// Extra files that are commonly legitimate, keyed by basename. They still
// report (an attacker can hide behind a known name) but as INFO with the
// reason, so HIGH/MEDIUM triage stays clean.
//////////////
$INTEGRITY_KNOWN_BENIGN = array(
    'error_log'         => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
    'php_errorlog'      => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
    'wordfence-waf.php' => 'Wordfence extended protection bootstrap (auto_prepend_file) - verify it only loads wordfence/waf/bootstrap.php',
);

function verify_against_manifest($base_dir, $manifest, $label, $present_files, &$totals)
{
    global $INTEGRITY_KNOWN_BENIGN;
    ///////////////
    // $manifest maps package-relative paths to expected md5(s). Report
    // mismatches (MODIFIED), files gone from disk (MISSING), and files on
    // disk that the official package does not contain (EXTRA). Extra or
    // modified PHP is the classic dropped/backdoored webshell: HIGH.
    //////////////
    $restorable = array();
    foreach ($manifest as $relative_path => $expected) {
        $full_path = $base_dir . '/' . $relative_path;
        if (!is_file($full_path)) {
            report_finding('LOW', 'INTEGRITY_MISSING', $full_path, $label . ': file from the official package is missing');
            $totals['MISSING']++;
            $restorable[] = array('rel' => $relative_path, 'expected' => $expected);
            continue;
        }

        // A file we cannot read is UNVERIFIED, not modified: saying
        // "checksum does not match" would be false, and restoring would
        // overwrite content the tool never saw.
        $actual_md5 = @md5_file($full_path);
        if (false === $actual_md5) {
            report_finding('ERROR', 'INTEGRITY_UNREADABLE', $full_path, $label . ': cannot read the file to verify its checksum');
            $totals['UNREADABLE']++;
            continue;
        }

        if (null === $expected || !md5_in_list($actual_md5, $expected)) {
            $severity = is_php_file($relative_path) ? 'HIGH' : 'MEDIUM';
            report_finding($severity, 'INTEGRITY_MODIFIED', $full_path, $label . ': checksum does not match the official package');
            $totals['MODIFIED']++;
            $restorable[] = array('rel' => $relative_path, 'expected' => $expected);
        }
    }

    foreach ($present_files as $relative_path) {
        if (!isset($manifest[$relative_path])) {
            $basename = basename($relative_path);
            $known_benign = isset($INTEGRITY_KNOWN_BENIGN[$basename]);
            // wordfence-waf.php is only expected where Wordfence is installed;
            // anywhere else the name is camouflage.
            if ($known_benign && 'wordfence-waf.php' === $basename && !is_dir($base_dir . '/wp-content/plugins/wordfence')) {
                $known_benign = false;
            }

            if ($known_benign) {
                report_finding('INFO', 'INTEGRITY_EXTRA', $base_dir . '/' . $relative_path, $label . ': ' . $INTEGRITY_KNOWN_BENIGN[$basename]);
            } else {
                $detail = $label . ': file is not part of the official package';
                // Hex-named PHP at the docroot is used both by dropped
                // webshells and by migration/backup tooling: say so.
                if (preg_match('/^[0-9a-f]{32,64}\.php$/i', $basename)) {
                    $detail .= ' (hex-named PHP is dropped by webshells AND by migration/backup tools such as BlogVault/MalCare or Duplicator - inspect the contents)';
                }
                $severity = is_php_file($relative_path) ? 'HIGH' : 'LOW';
                report_finding($severity, 'INTEGRITY_EXTRA', $base_dir . '/' . $relative_path, $detail);
            }
            $totals['EXTRA']++;
        }
    }

    // MODIFIED and MISSING files can be restored from the official package
    // zip; EXTRA files are never touched - deleting unknown files is the
    // operator's call, not this tool's.
    return ($restorable);
}

function http_get_file($url, $dest)
{
    // Package zips can be tens of MB: stream to disk instead of buffering.
    // Returns the HTTP status code (0 on transport failure).
    if (function_exists('curl_init')) {
        $fh = @fopen($dest, 'w');
        if (false === $fh) {
            return (0);
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_FILE           => $fh,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 300,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => 'elderward',
        ));
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        fclose($fh);
        return ((false !== $ok) ? $status : 0);
    }

    // No curl: stream through fopen so the zip never sits in memory.
    $context = stream_context_create(array('http' => array(
        'timeout'       => 300,
        'user_agent'    => 'elderward',
        'ignore_errors' => true,
    )));
    $src = @fopen($url, 'r', false, $context);
    if (false === $src) {
        return (0);
    }
    $status = isset($http_response_header) ? status_from_response_headers($http_response_header) : 0;
    $dst = @fopen($dest, 'w');
    if (false === $dst) {
        fclose($src);
        return (0);
    }
    $copied = @stream_copy_to_stream($src, $dst);
    fclose($src);
    fclose($dst);
    return ((false === $copied) ? 0 : $status);
}

function acquire_package_zip($zip_url, $offline_zip_name)
{
    ///////////////
    // Returns array($zip_path_or_null, $is_temp, $status) with $status one
    // of 'ok', 'notfound', 'error'. With checksumdir= the zip is read from
    // there instead of the network, mirroring the manifest naming.
    //////////////
    if (isset($_GET['checksumdir'])) {
        $zip_path = rtrim($_GET['checksumdir'], '/') . '/' . $offline_zip_name;
        if (is_file($zip_path)) {
            return array($zip_path, false, 'ok');
        }
        return array(null, false, 'notfound');
    }

    $zip_path = @tempnam(sys_get_temp_dir(), 'elderward-zip');
    if (false === $zip_path) {
        return array(null, false, 'error');
    }
    $status = http_get_file($zip_url, $zip_path);
    if (200 !== $status) {
        @unlink($zip_path);
        return array(null, false, (404 === $status) ? 'notfound' : 'error');
    }
    return array($zip_path, true, 'ok');
}

function manifest_from_zip($zip_path, $zip_prefix)
{
    ///////////////
    // Themes have no checksum API, so the reference manifest is built by
    // hashing the official package zip's own contents.
    //////////////
    if (!class_exists('ZipArchive')) {
        return (null);
    }
    $zip = new ZipArchive();
    if (true !== $zip->open($zip_path)) {
        return (null);
    }

    $manifest = array();
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $entry_name = $zip->getNameIndex($i);
        if (0 !== strpos($entry_name, $zip_prefix) || '/' === substr($entry_name, -1)) {
            continue;
        }
        $content = $zip->getFromIndex($i);
        if (false === $content) {
            continue;
        }
        $manifest[substr($entry_name, strlen($zip_prefix))] = md5($content);
    }
    $zip->close();
    return ($manifest);
}

function quarantine_original($target, $relative_path, $label)
{
    ///////////////
    // Overwriting a backdoored file destroys the evidence an IR needs.
    // With quarantinedir= set, the original is copied there first, with a
    // .quarantine suffix so nothing serves or executes it.
    //////////////
    $quarantine_root = rtrim($_GET['quarantinedir'], '/') . '/' . str_replace(' ', '-', $label);
    $dest = $quarantine_root . '/' . $relative_path . '.quarantine';
    $dest_dir = dirname($dest);
    if (!is_dir($dest_dir) && !@mkdir($dest_dir, 0700, true)) {
        return (false);
    }
    return (@copy($target, $dest));
}

function restore_package_files($base_dir, $zip_url, $offline_zip_name, $zip_prefix, $items, $label)
{
    if (!class_exists('ZipArchive')) {
        report_finding('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': PHP zip extension not available, cannot restore');
        return;
    }

    list($zip_path, $is_temp, $status) = acquire_package_zip($zip_url, $offline_zip_name);
    if ('ok' !== $status) {
        report_finding('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': could not obtain the official package (' . $status . ')');
        return;
    }

    restore_items_from_zip($zip_path, $zip_prefix, $base_dir, $items, $label);

    if ($is_temp) {
        @unlink($zip_path);
    }
}

function restore_items_from_zip($zip_path, $zip_prefix, $base_dir, $items, $label)
{
    $zip = new ZipArchive();
    if (true !== $zip->open($zip_path)) {
        report_finding('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': could not open the package zip');
        return;
    }

    foreach ($items as $item) {
        $target = $base_dir . '/' . $item['rel'];

        $content = $zip->getFromName($zip_prefix . $item['rel']);
        if (false === $content) {
            report_finding('ERROR', 'RESTORE_FAILED', $target, $label . ': file not found inside the package zip');
            continue;
        }

        ///////////////
        // Only byte-verified content is ever written: the packaged file must
        // match the reference manifest, so a tampered zip (or a manifest/zip
        // version mix-up) can never plant content.
        //////////////
        if (!md5_in_list(md5($content), $item['expected'])) {
            report_finding('ERROR', 'RESTORE_FAILED', $target, $label . ': packaged file does not match the reference checksum, refusing to restore');
            continue;
        }

        if (isset($_GET['dryrun'])) {
            report_finding('INFO', 'INTEGRITY_RESTORABLE', $target, $label . ' (dry run: not restored)');
            continue;
        }

        if (isset($_GET['quarantinedir']) && is_file($target) && !quarantine_original($target, $item['rel'], $label)) {
            report_finding('ERROR', 'RESTORE_FAILED', $target, $label . ': could not quarantine the original, refusing to overwrite it');
            continue;
        }

        $target_dir = dirname($target);
        if (!is_dir($target_dir) && !@mkdir($target_dir, 0755, true)) {
            report_finding('ERROR', 'RESTORE_FAILED', $target, $label . ': could not create the target directory');
            continue;
        }
        if (!write_cleaned_file($target, $content)) {
            report_finding('ERROR', 'RESTORE_FAILED', $target, $label . ': could not write the restored file');
            continue;
        }
        report_finding('INFO', 'INTEGRITY_RESTORED', $target, $label . ': pristine copy restored from the official package');
    }

    $zip->close();
}

function read_theme_version($theme_dir)
{
    $header = @file_get_contents($theme_dir . '/style.css', false, null, 0, 8192);
    if (false === $header || false === stripos($header, 'Theme Name:')) {
        return (null);
    }
    if (preg_match('/^[ \t\/*#@]*Version:\s*(\S+)/mi', $header, $matches)) {
        return trim($matches[1]);
    }
    return (null);
}

function read_plugin_version($plugin_dir)
{
    // The main plugin file is whichever top-level PHP file carries the
    // "Plugin Name:" header; its "Version:" header is the installed version.
    foreach ((array) @glob($plugin_dir . '/*.php') as $candidate) {
        $header = @file_get_contents($candidate, false, null, 0, 8192);
        if (false === $header || false === stripos($header, 'Plugin Name:')) {
            continue;
        }
        if (preg_match('/^[ \t\/*#@]*Version:\s*(\S+)/mi', $header, $matches)) {
            return trim($matches[1]);
        }
    }
    return (null);
}

function scanIntegrity($root)
{
    $root = require_wordpress_root($root);
    $version_file = $root . '/wp-includes/version.php';

    $totals = array('MODIFIED' => 0, 'MISSING' => 0, 'EXTRA' => 0, 'NO_REFERENCE' => 0, 'UNREADABLE' => 0);

    if (isset($_GET['quarantinedir'])) {
        $quarantine_real = @realpath($_GET['quarantinedir']);
        $root_real = @realpath($root);
        if (false !== $quarantine_real && false !== $root_real && 0 === strpos($quarantine_real . '/', $root_real . '/')) {
            progress("Warning: quarantinedir is inside the scanned tree - move it outside the webroot so quarantined files cannot be served.\n");
        }
    }

    ///////////////
    // Core: checksums come per version+locale. Bundled themes/plugins under
    // wp-content are legitimately deleted all the time, so core manifest
    // entries there are skipped (plugins are verified separately below).
    // Extra-file detection covers wp-admin and wp-includes entirely, plus
    // root-level PHP files (a classic dropper spot) except wp-config.php.
    //////////////
    $wp_version = null;
    if (preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', (string) @file_get_contents($version_file), $matches)) {
        $wp_version = $matches[1];
    }
    if (null === $wp_version) {
        report_finding('ERROR', 'INTEGRITY_NO_REFERENCE', $version_file, 'could not read the core version');
        $totals['NO_REFERENCE']++;
    } else {
        $locale = isset($_GET['locale']) ? $_GET['locale'] : 'en_US';
        list($status, $data) = fetch_reference_checksums(
            'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($wp_version) . '&locale=' . rawurlencode($locale),
            'core-' . $wp_version . '.json'
        );
        if ('ok' !== $status || empty($data['checksums']) || !is_array($data['checksums'])) {
            report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $root, 'core ' . $wp_version . ' (' . $locale . '): no reference checksums available (' . $status . ')');
            $totals['NO_REFERENCE']++;
        } else {
            progress('Checking core ' . $wp_version . ' (' . count($data['checksums']) . " files)\n");
            $manifest = array();
            foreach ($data['checksums'] as $relative_path => $expected) {
                if (0 === strpos($relative_path, 'wp-content/')) {
                    continue;
                }
                $manifest[$relative_path] = $expected;
            }

            $present = array();
            foreach (array('wp-admin', 'wp-includes') as $core_dir) {
                if (is_dir($root . '/' . $core_dir)) {
                    $present = array_merge($present, list_files_recursive($root . '/' . $core_dir, $root));
                }
            }
            foreach ((array) @glob($root . '/*.php') as $root_file) {
                if ('wp-config.php' !== basename($root_file)) {
                    $present[] = basename($root_file);
                }
            }
            $restorable = verify_against_manifest($root, $manifest, 'core ' . $wp_version, $present, $totals);
            if (isset($_GET['restore']) && count($restorable) > 0) {
                if ('en_US' !== $locale) {
                    progress("Restore of non-en_US core packages is not supported yet; skipping core restore.\n");
                } else {
                    restore_package_files($root,
                        'https://wordpress.org/wordpress-' . rawurlencode($wp_version) . '.zip',
                        'core-' . $wp_version . '.zip',
                        'wordpress/', $restorable, 'core ' . $wp_version);
                }
            }
        }
    }

    ///////////////
    // Plugins: one manifest per slug+version. A 404 means the plugin or the
    // version is not in the wordpress.org archive (custom/premium plugin):
    // reported as NO_REFERENCE so "clean" never silently means "unchecked".
    //////////////
    $plugins_dir = $root . '/wp-content/plugins';
    foreach ((array) @glob($plugins_dir . '/*', GLOB_ONLYDIR) as $plugin_dir) {
        $slug = basename($plugin_dir);
        $version = read_plugin_version($plugin_dir);
        if (null === $version) {
            report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ': could not determine the installed version');
            $totals['NO_REFERENCE']++;
            continue;
        }

        list($status, $data) = fetch_reference_checksums(
            'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json',
            'plugin-' . $slug . '-' . $version . '.json'
        );
        if ('notfound' === $status) {
            report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ' ' . $version . ': not in the wordpress.org checksum archive (custom/premium plugin, or version not archived)');
            $totals['NO_REFERENCE']++;
            continue;
        }
        if ('ok' !== $status || empty($data['files']) || !is_array($data['files'])) {
            report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ' ' . $version . ': could not fetch reference checksums');
            $totals['NO_REFERENCE']++;
            continue;
        }

        progress('Checking plugin ' . $slug . ' ' . $version . ' (' . count($data['files']) . " files)\n");
        $manifest = array();
        foreach ($data['files'] as $relative_path => $sums) {
            $manifest[$relative_path] = isset($sums['md5']) ? $sums['md5'] : null;
        }
        $restorable = verify_against_manifest($plugin_dir, $manifest, 'plugin ' . $slug . ' ' . $version, list_files_recursive($plugin_dir, $plugin_dir), $totals);
        if (isset($_GET['restore']) && count($restorable) > 0) {
            restore_package_files($plugin_dir,
                'https://downloads.wordpress.org/plugin/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip',
                'plugin-' . $slug . '-' . $version . '.zip',
                $slug . '/', $restorable, 'plugin ' . $slug . ' ' . $version);
        }
    }

    ///////////////
    // Themes: wordpress.org publishes no theme checksums, so the reference
    // manifest is built by hashing the official package zip's contents.
    // Custom, premium, and child themes 404 there: NO_REFERENCE.
    //////////////
    $themes_dir = $root . '/wp-content/themes';
    $theme_dirs = (array) @glob($themes_dir . '/*', GLOB_ONLYDIR);
    if (count($theme_dirs) > 0 && !class_exists('ZipArchive')) {
        report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $themes_dir, 'themes: PHP zip extension not available, cannot verify themes');
        $totals['NO_REFERENCE']++;
    } elseif (count($theme_dirs) > 0) {
        foreach ($theme_dirs as $theme_dir) {
            $slug = basename($theme_dir);
            $version = read_theme_version($theme_dir);
            if (null === $version) {
                report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ': could not determine the installed version');
                $totals['NO_REFERENCE']++;
                continue;
            }

            list($zip_path, $is_temp, $status) = acquire_package_zip(
                'https://downloads.wordpress.org/theme/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip',
                'theme-' . $slug . '-' . $version . '.zip'
            );
            if ('notfound' === $status) {
                report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': not in the wordpress.org theme directory (custom/premium/child theme, or version not archived)');
                $totals['NO_REFERENCE']++;
                continue;
            }
            if ('ok' !== $status) {
                report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': could not fetch the official theme package');
                $totals['NO_REFERENCE']++;
                continue;
            }

            $manifest = manifest_from_zip($zip_path, $slug . '/');
            if (null === $manifest || 0 === count($manifest)) {
                report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': could not read the official theme package');
                $totals['NO_REFERENCE']++;
            } else {
                progress('Checking theme ' . $slug . ' ' . $version . ' (' . count($manifest) . " files)\n");
                $restorable = verify_against_manifest($theme_dir, $manifest, 'theme ' . $slug . ' ' . $version, list_files_recursive($theme_dir, $theme_dir), $totals);
                if (isset($_GET['restore']) && count($restorable) > 0) {
                    restore_items_from_zip($zip_path, $slug . '/', $theme_dir, $restorable, 'theme ' . $slug . ' ' . $version);
                }
            }
            if ($is_temp) {
                @unlink($zip_path);
            }
        }
    }

    // Single-file plugins (e.g. hello.php) sit directly in the plugins dir
    // and carry no per-directory manifest.
    foreach ((array) @glob($plugins_dir . '/*.php') as $loose_plugin) {
        if ('index.php' === basename($loose_plugin)) {
            continue;
        }
        report_finding('INFO', 'INTEGRITY_NO_REFERENCE', $loose_plugin, 'single-file plugin: no checksum manifest to verify against');
        $totals['NO_REFERENCE']++;
    }

    emit_summary('integrity', $totals,
        'Integrity scan complete: ' . $totals['MODIFIED'] . ' modified, ' . $totals['MISSING'] . ' missing, '
        . $totals['EXTRA'] . ' extra, ' . $totals['UNREADABLE'] . ' unreadable, '
        . $totals['NO_REFERENCE'] . " without reference checksums\n");
}

////////////////
//
// Quick checks: cheap, high-signal places attackers hide
//
//////////////

////////////////
//
// Database scanning (report-only, SELECT-only)
//
// A large share of WordPress compromises live partly or entirely in the
// database: rogue administrators, script injections in options and posts,
// hijacked siteurl/home. Everything read from the DB is hostile data -
// values are pattern-matched only, NEVER unserialize()d (PHP object
// injection) and never executed.
//////////////

// An administrator registered this recently on a compromised site is the
// classic takeover artifact.
define('RECENT_ADMIN_DAYS', 30);
// Only the first 256KB of a value is scanned, so a giant transient or post
// cannot balloon memory.
define('DB_VALUE_SCAN_CAP', 262144);

$DB_OPTION_SIGS = array(
    array(
        'name'        => 'db.option.php-exec',
        'pattern'     => '@(?:eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|assert\s*\(|create_function\s*\()@i',
        'severity'    => 'HIGH',
        'description' => 'PHP execution/decoding functions inside an option value - options should hold settings, never code',
    ),
    array(
        'name'        => 'db.option.php-tag',
        'pattern'     => '@<\?php@i',
        'severity'    => 'HIGH',
        'description' => 'PHP tag inside an option value',
    ),
    array(
        'name'        => 'db.option.hidden-iframe',
        'pattern'     => '@<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width=["\']?0["\']?[\s>]|height=["\']?0["\']?[\s>])@i',
        'severity'    => 'HIGH',
        'description' => 'Hidden iframe inside an option value - a classic drive-by injection',
    ),
    array(
        'name'        => 'db.option.js-obfuscation',
        'pattern'     => '@(?:String\.fromCharCode\s*\(|atob\s*\(|unescape\s*\(\s*[\'"]%)@i',
        'severity'    => 'MEDIUM',
        'description' => 'Obfuscated JavaScript inside an option value',
    ),
    array(
        'name'        => 'db.option.script-src',
        'pattern'     => '@<script[^>]+src\s*=@i',
        'severity'    => 'MEDIUM',
        'description' => 'Remote script tag inside an option value - theme/plugin settings can legitimately hold analytics snippets, verify the source',
    ),
);

$DB_POST_SIGS = array(
    array(
        'name'        => 'db.post.php-tag',
        'pattern'     => '@<\?php@',
        'severity'    => 'HIGH',
        'description' => 'PHP tag inside post content - WordPress never stores executable PHP in posts',
    ),
    array(
        'name'        => 'db.post.hidden-iframe',
        'pattern'     => '@<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden)@i',
        'severity'    => 'HIGH',
        'description' => 'Hidden iframe inside post content',
    ),
    array(
        'name'        => 'db.post.js-obfuscation',
        'pattern'     => '@(?:String\.fromCharCode\s*\(|atob\s*\(|unescape\s*\(\s*[\'"]%|eval\s*\()@i',
        'severity'    => 'MEDIUM',
        'description' => 'Obfuscated JavaScript inside post content',
    ),
);

function parse_wp_config($root)
{
    ///////////////
    // The config is parsed with regexes, never include()d - it sits on a
    // compromised host and must not get to run code inside the scanner.
    // wp-config.php commonly lives one directory above the WP root too.
    //////////////
    $config_path = null;
    foreach (array($root . '/wp-config.php', dirname($root) . '/wp-config.php') as $candidate) {
        if (is_file($candidate)) {
            $config_path = $candidate;
            break;
        }
    }
    if (null === $config_path) {
        return (null);
    }

    $content = @file_get_contents($config_path);
    if (false === $content) {
        return (null);
    }

    $config = array('path' => $config_path, 'prefix' => 'wp_');
    foreach (array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST') as $constant) {
        if (preg_match('/define\s*\(\s*[\'"]' . $constant . '[\'"]\s*,\s*([\'"])(.*?)\1\s*\)/', $content, $matches)) {
            $config[$constant] = $matches[2];
        }
    }
    if (preg_match('/\$table_prefix\s*=\s*[\'"]([A-Za-z0-9_]+)[\'"]/', $content, $matches)) {
        $config['prefix'] = $matches[1];
    }

    if (!isset($config['DB_NAME'], $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_HOST'])) {
        return (null);
    }
    // The prefix goes into query strings: anything but [A-Za-z0-9_] is
    // either broken or an injection attempt from a tampered config.
    if (preg_match('/^[A-Za-z0-9_]+$/', $config['prefix']) !== 1) {
        return (null);
    }
    return ($config);
}

function db_connect($config)
{
    // PHP 8.1+ throws mysqli exceptions by default; this engine handles
    // errors fail-closed on return values instead.
    mysqli_report(MYSQLI_REPORT_OFF);

    // DB_HOST can be "host", "host:port", or "host:/path/to/socket".
    $host = $config['DB_HOST'];
    $port = null;
    $socket = null;
    if (false !== strpos($host, ':')) {
        list($host, $port_or_socket) = explode(':', $host, 2);
        if (0 === strpos($port_or_socket, '/')) {
            $socket = $port_or_socket;
        } else {
            $port = (int) $port_or_socket;
        }
    }

    $db = @mysqli_connect($host, $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_NAME'], $port, $socket);
    if (false === $db || null === $db) {
        return (null);
    }
    @mysqli_set_charset($db, 'utf8mb4');
    return ($db);
}

function scan_db_admins($db, $prefix, &$counts)
{
    $sql = 'SELECT u.ID, u.user_login, u.user_email, u.user_registered'
        . ' FROM ' . $prefix . 'users u'
        . ' JOIN ' . $prefix . 'usermeta m ON m.user_id = u.ID'
        . " WHERE m.meta_key = '" . $prefix . "capabilities' AND m.meta_value LIKE '%administrator%'";
    $result = @mysqli_query($db, $sql);
    if (false === $result) {
        progress('Error querying users: ' . mysqli_error($db) . "\n");
        return;
    }

    $recent_cutoff = time() - (RECENT_ADMIN_DAYS * 86400);
    while ($row = mysqli_fetch_assoc($result)) {
        $counts['ADMINS']++;
        $registered = strtotime($row['user_registered']);
        $where = 'db:' . $prefix . 'users:ID=' . $row['ID'];
        $who = '"' . $row['user_login'] . '" <' . $row['user_email'] . '> registered ' . $row['user_registered'];

        if (false !== $registered && $registered >= $recent_cutoff) {
            report_finding('MEDIUM', 'DB_NEW_ADMIN', $where, 'administrator ' . $who . ' - created within the last ' . RECENT_ADMIN_DAYS . ' days, the classic takeover artifact; verify who created it');
        } else {
            report_finding('INFO', 'DB_ADMIN_USER', $where, 'administrator ' . $who . ' - confirm this account is known');
        }
    }
    mysqli_free_result($result);
}

function scan_db_options($db, $prefix, $root, &$counts)
{
    global $DB_OPTION_SIGS;

    // MYSQLI_USE_RESULT streams rows; SUBSTRING caps each value read.
    $sql = 'SELECT option_name, SUBSTRING(option_value, 1, ' . DB_VALUE_SCAN_CAP . ') FROM ' . $prefix . 'options';
    $result = @mysqli_query($db, $sql, MYSQLI_USE_RESULT);
    if (false === $result) {
        progress('Error querying options: ' . mysqli_error($db) . "\n");
        return;
    }

    while ($row = mysqli_fetch_row($result)) {
        $counts['OPTIONS']++;
        $option_name = $row[0];
        $value = (string) $row[1];
        $where = 'db:' . $prefix . 'options:' . $option_name;

        ///////////////
        // siteurl/home hijacks redirect every visitor; report the values
        // as inventory even when they look sane.
        //////////////
        if ('siteurl' === $option_name || 'home' === $option_name) {
            if (preg_match('@^https?://[^\s<>\'"]+$@', $value) === 1) {
                report_finding('INFO', 'DB_SITE_URL', $where, $option_name . ' = ' . $value . ' - confirm this is the real site address');
            } else {
                report_finding('HIGH', 'DB_SITE_URL', $where, $option_name . ' does not look like a plain URL (hijack or injection): ' . substr($value, 0, 200));
                $counts['FLAGGED_OPTIONS']++;
            }
            continue;
        }

        ///////////////
        // active_plugins is serialized PHP; extract the .php entries with a
        // regex (NEVER unserialize hostile data) and sanity-check each.
        //////////////
        if ('active_plugins' === $option_name) {
            if (preg_match_all('@"((?:[^"\\\\]|\\\\.)*?\.php)"@', $value, $matches)) {
                foreach ($matches[1] as $plugin_entry) {
                    if (false !== strpos($plugin_entry, '..')) {
                        report_finding('HIGH', 'DB_ACTIVE_PLUGIN', $where, 'active plugin path escapes the plugins directory: ' . $plugin_entry);
                        $counts['FLAGGED_OPTIONS']++;
                    } elseif (!is_file($root . '/wp-content/plugins/' . $plugin_entry)) {
                        report_finding('LOW', 'DB_ACTIVE_PLUGIN', $where, 'active plugin file missing on disk: ' . $plugin_entry);
                    }
                }
            }
            continue;
        }

        foreach ($DB_OPTION_SIGS as $signature) {
            if (preg_match($signature['pattern'], $value) !== 1) {
                continue;
            }
            report_finding($signature['severity'], 'DB_OPTION_IOC', $where,
                $signature['name'] . ': ' . $signature['description'],
                array('e.g. ' . substr($value, max(0, strpos($value, '<') === false ? 0 : strpos($value, '<')), 200)));
            $counts['FLAGGED_OPTIONS']++;
            break;
        }
    }
    mysqli_free_result($result);
}

function scan_db_posts($db, $prefix, &$counts)
{
    global $DB_POST_SIGS;

    ///////////////
    // The posts table can be huge: a LIKE prefilter runs server-side and
    // only candidates come back (streamed, value capped) for the real
    // pattern check.
    //////////////
    $sql = 'SELECT ID, post_title, post_type, SUBSTRING(post_content, 1, ' . DB_VALUE_SCAN_CAP . ')'
        . ' FROM ' . $prefix . 'posts'
        . " WHERE post_content LIKE '%<?php%' OR post_content LIKE '%eval(%'"
        . " OR post_content LIKE '%fromCharCode%' OR post_content LIKE '%atob(%'"
        . " OR post_content LIKE '%unescape(%' OR post_content LIKE '%<iframe%'";
    $result = @mysqli_query($db, $sql, MYSQLI_USE_RESULT);
    if (false === $result) {
        progress('Error querying posts: ' . mysqli_error($db) . "\n");
        return;
    }

    $max_reported = 100;
    $suppressed = 0;
    while ($row = mysqli_fetch_row($result)) {
        $content = (string) $row[3];
        foreach ($DB_POST_SIGS as $signature) {
            if (preg_match($signature['pattern'], $content) !== 1) {
                continue;
            }
            $counts['FLAGGED_POSTS']++;
            if ($counts['FLAGGED_POSTS'] > $max_reported) {
                $suppressed++;
            } else {
                report_finding($signature['severity'], 'DB_POST_IOC', 'db:' . $prefix . 'posts:ID=' . $row[0],
                    $signature['name'] . ' in ' . $row[2] . ' "' . $row[1] . '": ' . $signature['description']);
            }
            break;
        }
    }
    mysqli_free_result($result);

    if ($suppressed > 0) {
        progress('...and ' . $suppressed . " more flagged posts not listed\n");
    }
}

function scanDatabase($root, $fatal_on_error)
{
    $root = rtrim($root, '/');

    $failure = null;
    if (!function_exists('mysqli_connect')) {
        $failure = 'PHP mysqli extension not available, cannot scan the database';
    }

    $config = null;
    if (null === $failure) {
        $config = parse_wp_config($root);
        if (null === $config) {
            $failure = 'could not read DB credentials from wp-config.php (looked in ' . $root . ' and its parent)';
        }
    }

    $db = null;
    if (null === $failure) {
        $db = db_connect($config);
        if (null === $db) {
            $failure = 'could not connect to the database as ' . $config['DB_USER'] . '@' . $config['DB_HOST'];
        }
    }

    if (null !== $failure) {
        if ($fatal_on_error) {
            echo 'Error: ' . $failure . "\n";
            exit(1);
        }
        progress('Skipping database scan: ' . $failure . "\n");
        return;
    }

    progress('Scanning database ' . $config['DB_NAME'] . ' (prefix ' . $config['prefix'] . ") - read-only\n");
    $counts = array('ADMINS' => 0, 'OPTIONS' => 0, 'FLAGGED_OPTIONS' => 0, 'FLAGGED_POSTS' => 0);

    scan_db_admins($db, $config['prefix'], $counts);
    scan_db_options($db, $config['prefix'], $root, $counts);
    scan_db_posts($db, $config['prefix'], $counts);

    mysqli_close($db);

    emit_summary('database', $counts,
        'Database scan complete: ' . $counts['ADMINS'] . ' administrator(s), ' . $counts['OPTIONS'] . ' options scanned, '
        . $counts['FLAGGED_OPTIONS'] . ' flagged options, ' . $counts['FLAGGED_POSTS'] . " flagged posts\n");
}

function check_prepend_directives($root, $config_path, &$counts)
{
    ///////////////
    // auto_prepend_file / auto_append_file make PHP execute a file on EVERY
    // request - the mechanism behind both Wordfence's WAF and a whole class
    // of persistent backdoors.
    //////////////
    $content = @file_get_contents($config_path, false, null, 0, 65536);
    if (false === $content) {
        return;
    }
    // Leading [^;#] skips ini/htaccess comment lines.
    if (!preg_match_all('/^[^;#\r\n]*auto_(?:prepend|append)_file[^\r\n]*/mi', $content, $matches)) {
        return;
    }

    foreach ($matches[0] as $directive_line) {
        $directive_line = trim($directive_line);
        $target = '';
        if (preg_match('/auto_(?:prepend|append)_file(?:\s*=|\s)\s*["\']?([^"\'\s]+)/i', $directive_line, $target_match)) {
            $target = $target_match[1];
        }
        if ('' === $target || 'none' === strtolower($target)) {
            continue;
        }

        if ('wordfence-waf.php' === basename($target) && is_dir($root . '/wp-content/plugins/wordfence')) {
            report_finding('INFO', 'PHP_PREPEND', $config_path, 'Wordfence WAF bootstrap prepend: ' . $directive_line . ' - verify the target only loads wordfence/waf/bootstrap.php');
        } else {
            report_finding('MEDIUM', 'PHP_PREPEND', $config_path, $target . ' is executed on EVERY php request via: ' . $directive_line . ' - verify this file');
        }
        $counts['PHP_PREPEND']++;
    }
}

function scanQuick($root)
{
    $root = require_wordpress_root($root);

    $counts = array('UPLOADS_PHP' => 0, 'PHP_PREPEND' => 0, 'MU_PLUGIN' => 0, 'HIDDEN_PHP' => 0);
    $files = recursive_file_iterator($root);

    foreach ($files as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $path = $file->getPathname();
        $basename = $file->getFilename();

        // Uploads hold media, never code: PHP there is the classic dropped
        // webshell (plugins do scatter "Silence is golden" index.php files).
        if (false !== strpos($path, '/wp-content/uploads/') && is_php_file($basename) && 'index.php' !== $basename) {
            report_finding('HIGH', 'UPLOADS_PHP', $path, 'executable PHP inside wp-content/uploads - usually a webshell dropped through an upload form');
            $counts['UPLOADS_PHP']++;
            continue;
        }

        if (in_array($basename, array('.user.ini', 'php.ini', '.htaccess'), true)) {
            check_prepend_directives($root, $path, $counts);
            continue;
        }

        // mu-plugins load on every request with no activation step: a
        // favorite persistence spot. Inventory, not accusation.
        if (false !== strpos($path, '/wp-content/mu-plugins/') && is_php_file($basename)) {
            report_finding('INFO', 'MU_PLUGIN', $path, 'must-use plugin: loads on every request with no activation step - confirm it is intentional');
            $counts['MU_PLUGIN']++;
            continue;
        }

        if ('.' === $basename[0] && is_php_file($basename)) {
            report_finding('MEDIUM', 'HIDDEN_PHP', $path, 'hidden PHP file (dotfile) - rarely legitimate');
            $counts['HIDDEN_PHP']++;
        }
    }

    emit_summary('quickscan', $counts,
        'Quick scan complete: ' . $counts['UPLOADS_PHP'] . ' php-in-uploads, ' . $counts['PHP_PREPEND']
        . ' prepend/append directives, ' . $counts['MU_PLUGIN'] . ' mu-plugins, ' . $counts['HIDDEN_PHP'] . " hidden php files\n");
}

////////////////
//
// Timestamp anomaly heuristics (report-only)
//
// Timestamps are leads, not proof: attackers fake mtimes (touch -t) and
// legitimate migrations rewrite them wholesale. Nothing here ever feeds a
// cleanup action, and every check looks for outliers WITHIN one package
// (core, a plugin, a theme) - never comparisons against a site-wide date,
// which drown in false positives after any migration or update.
//////////////

// mtimes closer together than this belong to one install/update event.
define('TIME_CLUSTER_TOLERANCE', 7200);
// Groups smaller than this carry no statistics and are skipped.
define('TIME_MIN_GROUP_FILES', 10);
// mtime this far before ctime suggests a faked mtime: touch can back-date
// the content time, but the inode change time cannot be set without root.
define('TIMESTOMP_MIN_GAP', 2592000);

function timestamp_outlier_limit($group_size)
{
    // An install or update touches most of a package at once. A handful of
    // files changing on their own is the anomaly worth reporting.
    return (int) max(2, ceil($group_size * 0.05));
}

function list_files_absolute($dir)
{
    $absolute_paths = array();
    foreach (list_files_recursive($dir, $dir) as $relative_path) {
        $absolute_paths[] = $dir . '/' . $relative_path;
    }
    return $absolute_paths;
}

function analyze_time_group($group_label, $file_paths, &$totals)
{
    $entries = array();
    foreach ($file_paths as $path) {
        $stat = @stat($path);
        if (false === $stat) {
            continue;
        }
        $entries[] = array('path' => $path, 'mtime' => $stat['mtime'], 'ctime' => $stat['ctime']);
    }
    if (count($entries) < TIME_MIN_GROUP_FILES) {
        return;
    }

    ///////////////
    // Cluster the group's mtimes: sorted times closer than the tolerance
    // merge into one cluster. The dominant (largest) cluster is the last
    // legitimate install/update event for most of the package.
    //////////////
    usort($entries, function ($a, $b) {
        return $a['mtime'] - $b['mtime'];
    });

    $clusters = array();
    $current = array($entries[0]);
    $entry_count = count($entries);
    for ($i = 1; $i < $entry_count; $i++) {
        if (($entries[$i]['mtime'] - $entries[$i - 1]['mtime']) <= TIME_CLUSTER_TOLERANCE) {
            $current[] = $entries[$i];
        } else {
            $clusters[] = $current;
            $current = array($entries[$i]);
        }
    }
    $clusters[] = $current;

    $dominant_index = 0;
    foreach ($clusters as $i => $cluster) {
        if (count($cluster) > count($clusters[$dominant_index])) {
            $dominant_index = $i;
        }
    }
    $dominant = $clusters[$dominant_index];
    $dominant_time = $dominant[count($dominant) - 1]['mtime'];
    $outlier_limit = timestamp_outlier_limit($entry_count);

    ///////////////
    // Files modified AFTER the dominant cluster, in numbers too small to be
    // an update, are the classic post-install edit (backdoored functions.php,
    // dropped loader). Older stragglers are not flagged here: preserved
    // mtimes from uploads/migrations are routine, and faked-old mtimes are
    // the timestomp check's job.
    //////////////
    foreach ($clusters as $i => $cluster) {
        if ($i <= $dominant_index || count($cluster) > $outlier_limit) {
            continue;
        }
        foreach ($cluster as $entry) {
            $severity = is_php_file($entry['path']) ? 'MEDIUM' : 'LOW';
            report_finding($severity, 'TIMESTAMP_OUTLIER', $entry['path'],
                $group_label . ': modified ' . date('Y-m-d H:i', $entry['mtime'])
                . ' but ' . count($dominant) . ' of ' . $entry_count . ' files cluster around ' . date('Y-m-d H:i', $dominant_time));
            $totals['OUTLIER']++;
        }
    }

    ///////////////
    // Timestomp: mtime far behind ctime. Migrations and rsync/cp -p make
    // that true for a whole tree at once, so it only means something when
    // few files in the group show it. PHP files only - a back-dated image
    // is not a lead worth the noise.
    //////////////
    $diverged = array();
    foreach ($entries as $entry) {
        if (($entry['ctime'] - $entry['mtime']) > TIMESTOMP_MIN_GAP) {
            $diverged[] = $entry;
        }
    }
    if (count($diverged) > 0 && count($diverged) <= $outlier_limit) {
        foreach ($diverged as $entry) {
            if (!is_php_file($entry['path'])) {
                continue;
            }
            report_finding('MEDIUM', 'TIMESTAMP_TIMESTOMP', $entry['path'],
                $group_label . ': content claims to be from ' . date('Y-m-d H:i', $entry['mtime'])
                . ' but the inode changed ' . date('Y-m-d H:i', $entry['ctime']) . ' - the mtime may have been faked (touch -t)');
            $totals['TIMESTOMP']++;
        }
    }
}

function scanTimestamps($root)
{
    $root = require_wordpress_root($root);

    $totals = array('OUTLIER' => 0, 'TIMESTOMP' => 0);

    ///////////////
    // Core is one group: wp-admin, wp-includes, and root-level PHP files.
    // wp-config.php is excluded - editing it legitimately is routine and it
    // would flag on almost every site.
    //////////////
    $core_files = array();
    foreach (array('wp-admin', 'wp-includes') as $core_dir) {
        if (is_dir($root . '/' . $core_dir)) {
            $core_files = array_merge($core_files, list_files_absolute($root . '/' . $core_dir));
        }
    }
    foreach ((array) @glob($root . '/*.php') as $root_file) {
        if ('wp-config.php' !== basename($root_file)) {
            $core_files[] = $root_file;
        }
    }
    analyze_time_group('core', $core_files, $totals);

    foreach (array('plugins', 'themes') as $package_type) {
        foreach ((array) @glob($root . '/wp-content/' . $package_type . '/*', GLOB_ONLYDIR) as $package_dir) {
            $label = rtrim($package_type, 's') . ' ' . basename($package_dir);
            analyze_time_group($label, list_files_absolute($package_dir), $totals);
        }
    }

    emit_summary('timestamps', $totals,
        'Timestamp scan complete: ' . $totals['OUTLIER'] . ' outliers, ' . $totals['TIMESTOMP']
        . " possible timestomps. Timestamps are leads, not proof - a clean result does not clear a file.\n");
}

function pattern_matches($condition, $file_buffer)
{
    // A condition is array('string' => needle) or array('regex' => pattern).
    if ( isset($condition['string']) )
    {
        return (false !== strpos($file_buffer, $condition['string']));
    }
    if ( isset($condition['regex']) )
    {
        // preg_match returns false on engine errors (e.g. backtrack limit);
        // only an explicit 1 counts as a match so errors never flag a file.
        return (preg_match($condition['regex'], $file_buffer) === 1);
    }
    // Unknown condition types never match, so a typo'd signature fails
    // closed instead of flagging files.
    return (false);
}

function signature_matches($file_buffer, $signature)
{
    // The prefilter is the cheap first check and counts as confirmed
    // evidence; every additional trigger must ALSO match.
    if ( !pattern_matches($signature['prefilter'], $file_buffer) )
    {
        return (false);
    }
    foreach ( $signature['triggers'] as $trigger )
    {
        if ( !pattern_matches($trigger, $file_buffer) )
        {
            return (false);
        }
    }
    return (true);
}

function apply_action($file_buffer, $file_path, $signature_name, $action)
{
    if ( isset($action['remove_regex']) )
    {
        // $file_buffer already holds the whole file: files larger than
        // the read cap are skipped before ever being scanned.
        $cleared_file = preg_replace($action['remove_regex'], '', $file_buffer);
        if ( $cleared_file === null || ( strlen($file_buffer) === strlen($cleared_file) ) )
        {
            report_finding('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': cleanup regex removed nothing: ' . $action['remove_regex']);
            return;
        }
        // Dry run: the cleanup regex was applied and verified to change
        // the file, but nothing is written or deleted.
        if ( isset($_GET['dryrun']) )
        {
            report_finding('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not modified)');
            return;
        }
        if ( !write_cleaned_file($file_path, $cleared_file) )
        {
            report_finding('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not write cleaned file');
            return;
        }
        report_finding('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name);
        return;
    }

    if ( isset($action['delete_file']) )
    {
        if ( isset($_GET['dryrun']) )
        {
            report_finding('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not deleted)');
            return;
        }
        if ( false === unlink($file_path) )
        {
            report_finding('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not delete file');
            return;
        }
        report_finding('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name . ' (file deleted)');
        return;
    }

    report_finding('ERROR', 'CLEANUP_FAILED', $file_path, 'unknown action for signature ' . $signature_name);
}

function cleanup_util($file_buffer, $file_path)
{
    global $CLEANUP_SIGNATURES;

    ///////////////
    // First confirmed signature wins: apply its action, then stop.
    //////////////
    foreach ( $CLEANUP_SIGNATURES as $signature_name => $signature )
    {
        if ( signature_matches($file_buffer, $signature) )
        {
            apply_action($file_buffer, $file_path, $signature_name, $signature['action']);
            return;
        }
    }
}

function lint_signatures()
{
    global $CLEANUP_SIGNATURES, $CRONTAB_SIGS, $ACCESS_LOG_SIGS, $DB_OPTION_SIGS, $DB_POST_SIGS;

    ///////////////
    // A malformed signature would otherwise silently never match. Stop the
    // run and name the broken signature instead.
    //////////////
    foreach ( $CLEANUP_SIGNATURES as $name => $signature )
    {
        if ( !isset($signature['prefilter'], $signature['triggers'], $signature['action']) )
        {
            echo 'Invalid cleanup signature ' . $name . ": prefilter, triggers and action are required\n";
            exit(1);
        }

        $conditions = array_merge(array($signature['prefilter'], $signature['action']), $signature['triggers']);
        foreach ( $conditions as $condition )
        {
            $pattern = null;
            if ( isset($condition['regex']) )
            {
                $pattern = $condition['regex'];
            }
            elseif ( isset($condition['remove_regex']) )
            {
                $pattern = $condition['remove_regex'];
            }
            if ( null !== $pattern && false === @preg_match($pattern, '') )
            {
                echo 'Invalid regex in cleanup signature ' . $name . ': ' . $pattern . "\n";
                exit(1);
            }
        }
    }

    foreach ( $CRONTAB_SIGS as $item )
    {
        foreach ( $item as $name => $pattern )
        {
            if ( false === @preg_match($pattern, '') )
            {
                echo 'Invalid regex in crontab signature ' . $name . ': ' . $pattern . "\n";
                exit(1);
            }
        }
    }

    foreach ( $ACCESS_LOG_SIGS as $signature )
    {
        if ( false === @preg_match($signature['pattern'], '') )
        {
            echo 'Invalid regex in access log signature ' . $signature['name'] . ': ' . $signature['pattern'] . "\n";
            exit(1);
        }
    }

    foreach ( array_merge($DB_OPTION_SIGS, $DB_POST_SIGS) as $signature )
    {
        if ( false === @preg_match($signature['pattern'], '') )
        {
            echo 'Invalid regex in database signature ' . $signature['name'] . ': ' . $signature['pattern'] . "\n";
            exit(1);
        }
    }
}

////////////
// Defining our variables
//    - $filesize_limit : Filesize limit to read is 2MB, but it can be better configured if we have an idea of how big are the php files we backup
//    - $extensions_to_check : list of extensions we'll check for malware (also
//      the files considered by the correlate mode)
///////////

$filesize_limit = 2097152;
$extensions_to_check = array(
    'asa',
    'asp',
    'aspx',
    'cfm',
    'cgi',
    'cin',
    'conf',
    'cron',
    'css',
    'ejl',
    'htm',
    'html',
    'inc',
    'izo',
    'js',
    'local',
    'mod',
    'php',
    'php3',
    'php4',
    'php5',
    'php7',
    'php8',
    'phps',
    'pht',
    'phtml',
    'pl',
    'py',
    'sct',
    'sh',
    'shtml',
    'tmpl',
    'tpl',
);

lint_signatures();

////////////
// Standalone scan modes: each runs alone and exits before the directory
// validation below. Combining them would silently run only the first, so
// asking for more than one is an error instead.
///////////
$requested_modes = array();
foreach (array('scanall', 'scancron', 'scanlog', 'scanintegrity', 'scantimes', 'quickscan', 'scandb') as $mode) {
    if (isset($_GET[$mode])) {
        $requested_modes[] = $mode;
    }
}
// scanall consumes scanlog as its log input; every other combination would
// silently run only one mode, so it is an error instead.
if (count($requested_modes) > 1 && $requested_modes !== array('scanall', 'scanlog')) {
    echo 'Error: scan modes are mutually exclusive, run them one at a time: ' . implode(', ', $requested_modes) . "\n";
    exit(1);
}

if ( isset($_GET['correlate']) && !isset($_GET['scanlog']) ) {
    echo "Error: correlate=1 needs scanlog=/path to know which traffic to correlate against\n";
    exit(1);
}

if ( isset($_GET['scanall']) ) {
    scanAll();
    scan_exit();
}

if ( isset($_GET['scancron']) ) {
    scanCronTab();
    scan_exit();
}

if ( isset($_GET['scanlog']) ) {
    $flagged_minutes = scanLogTarget($_GET['scanlog']);
    if ( isset($_GET['correlate']) ) {
        correlate_files($_GET['scandirectory'], $flagged_minutes, correlation_window());
    }
    scan_exit();
}

if ( isset($_GET['scanintegrity']) ) {
    scanIntegrity($_GET['scandirectory']);
    scan_exit();
}

if ( isset($_GET['scantimes']) ) {
    scanTimestamps($_GET['scandirectory']);
    scan_exit();
}

if ( isset($_GET['quickscan']) ) {
    scanQuick($_GET['scandirectory']);
    scan_exit();
}

if ( isset($_GET['scandb']) ) {
    scanDatabase(require_wordpress_root($_GET['scandirectory']), true);
    scan_exit();
}

////////////
// Default mode: recursive signature scan/cleanup of scandirectory.
///////////
run_signature_scan($_GET['scandirectory']);
scan_exit();

function run_signature_scan($scan_dir)
{
    global $filesize_limit;

    if (!is_dir($scan_dir) || !is_readable($scan_dir)) {
        echo 'Error: cannot open scan directory ' . $scan_dir . "\n";
        exit(1);
    }

    $files = recursive_file_iterator($scan_dir);

    ///////////
    // iterating through the files collected
    //////////
    foreach ($files as $file) {
        $target_file = $file->getPathname();

        //////////
        //// Skip this script itself and anything outside the risky-extension
        //// list (scan_all=1 overrides) - shared with the correlate walk.
        /////////
        if ( !is_scannable_file($file) ) {
            continue;
        }
        ///////////
        // Another condition is the filesize.
        //////////
        $filesize = @filesize($target_file);
        if ( $filesize > $filesize_limit ) {
            continue;
        }
        /////////
        // Starting the scanning process by opening the file and reading a limited buffer
        ///////
        $fh = @fopen($target_file, 'r');
        if (false === $fh) {
            progress('Error reading ' . $target_file . "\n");
            continue;
        }
        $buffer = @fread($fh, $filesize_limit);
        @fclose($fh);
        if (false === $buffer) {
            progress('Error reading ' . $target_file . "\n");
            continue;
        }

        //////////
        //  Performing the cleanup
        //////////
        cleanup_util($buffer, $target_file);
    }
}

function correlation_window()
{
    return isset($_GET['window']) ? max(60, (int) $_GET['window']) : 300;
}

function scanAll()
{
    global $SCANALL_FINDINGS;

    ///////////////
    // One command for the first look: every scanner in sequence against the
    // WordPress root, report-only (the signature pass is forced into dry
    // run and restore is ignored). In text mode findings buffer and print
    // severity-sorted at the end; format=json streams events as usual.
    //////////////
    $root = require_wordpress_root($_GET['scandirectory']);
    $_GET['scandirectory'] = $root;
    $_GET['dryrun'] = 1;
    if (isset($_GET['restore'])) {
        progress("scanall is report-only: ignoring restore=1 (run scanintegrity=1 restore=1 separately)\n");
        unset($_GET['restore']);
    }
    if (!json_output()) {
        $SCANALL_FINDINGS = array();
    }

    progress("== Quick checks ==\n");
    scanQuick($root);
    progress("== Integrity ==\n");
    scanIntegrity($root);
    progress("== Timestamps ==\n");
    scanTimestamps($root);
    progress("== Crontab ==\n");
    scanCronTab();
    progress("== Database ==\n");
    scanDatabase($root, false);
    if (isset($_GET['scanlog'])) {
        progress("== Access logs ==\n");
        $flagged_minutes = scanLogTarget($_GET['scanlog']);
        correlate_files($root, $flagged_minutes, correlation_window());
    }
    progress("== Malware signatures (dry run) ==\n");
    run_signature_scan($root);

    if (!is_array($SCANALL_FINDINGS)) {
        return;
    }

    ///////////////
    // Flush the buffered findings worst-first. ERROR sits right after HIGH:
    // something that blocked verification needs eyes too.
    //////////////
    $buffered = $SCANALL_FINDINGS;
    $SCANALL_FINDINGS = null;

    echo "\n== Findings by severity (" . count($buffered) . ") ==\n";
    foreach (array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO') as $severity_group) {
        foreach ($buffered as $finding) {
            if ($finding['severity'] === $severity_group) {
                print_text_finding($finding);
            }
        }
    }
}
