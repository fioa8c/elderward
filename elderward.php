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
    echo "  scanintegrity=1       Verify core and plugin files against wordpress.org checksums.\n";
    echo "                        scandirectory must be the WordPress root (default: current dir)\n";
    echo "  checksumdir=/path     Use pre-downloaded checksum manifests instead of the network\n";
    echo "                        (core-{version}.json, plugin-{slug}-{version}.json)\n";
    echo "  locale=xx_XX          Core locale for the checksum lookup (default: en_US)\n";
    echo "  help=1                Show this help\n";
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
    }

    if (!@rename($tmp_path, $file_path)) {
        @unlink($tmp_path);
        return (false);
    }
    return (true);
}

////////////////
// Unified finding format, shared by every scanner:
//
//   SEVERITY,TYPE,path,detail
//
// The first three fields never contain commas; everything after the third
// comma is free-form detail. Severities: HIGH, MEDIUM, LOW, INFO, ERROR.
// Indented lines under a finding are supporting context (log examples etc).
//////////////
function report_finding($severity, $type, $path, $detail)
{
    echo $severity . ',' . $type . ',' . $path . ',' . $detail . "\n";
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

function scanAccessLog($log_path)
{
    global $ACCESS_LOG_SIGS;

    ///////////////
    // Logs are streamed line by line (never loaded whole) so rotated
    // multi-hundred-MB logs stay within the memory limit. Gzipped
    // rotations are read through zlib when available.
    //////////////
    $is_gzipped = ('gz' === strtolower(pathinfo($log_path, PATHINFO_EXTENSION)));
    if ($is_gzipped && !function_exists('gzopen')) {
        echo 'Error: zlib not available, skipping compressed log ' . $log_path . "\n";
        return;
    }

    $fh = $is_gzipped ? @gzopen($log_path, 'r') : @fopen($log_path, 'r');
    if (false === $fh) {
        echo 'Error reading ' . $log_path . "\n";
        return;
    }

    $max_examples = 5;
    $max_example_length = 300;
    $hit_counts = array();
    $hit_examples = array();
    $hit_ips = array();

    while (true) {
        // 8KB cap per read: an absurdly long line is scanned in chunks
        // instead of ballooning memory.
        $line = $is_gzipped ? gzgets($fh, 8192) : fgets($fh, 8192);
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

            // First matching IoC wins for this line.
            break;
        }
    }
    $is_gzipped ? gzclose($fh) : fclose($fh);

    ///////////////
    // Report: every signature at or over its threshold, with example lines,
    // then the source IPs behind the reported hits.
    //////////////
    echo "== Access log IoC report: " . $log_path . " ==\n";

    $reported = 0;
    $reported_ips = array();
    foreach ($ACCESS_LOG_SIGS as $signature) {
        $name = $signature['name'];
        if (!isset($hit_counts[$name]) || $hit_counts[$name] < $signature['threshold']) {
            continue;
        }
        $reported++;

        $severity = isset($signature['severity']) ? $signature['severity'] : 'MEDIUM';
        report_finding($severity, 'LOG_IOC', $log_path, $name . ': ' . $hit_counts[$name] . ' hit(s) - ' . $signature['description']);
        foreach ($hit_examples[$name] as $example) {
            echo "    e.g. " . $example . "\n";
        }

        foreach ($hit_ips[$name] as $ip => $count) {
            $reported_ips[$ip] = isset($reported_ips[$ip]) ? $reported_ips[$ip] + $count : $count;
        }
    }

    if (0 === $reported) {
        echo "No known IoCs found.\n";
        return;
    }

    arsort($reported_ips);
    echo "Top source IPs on flagged requests:\n";
    foreach (array_slice($reported_ips, 0, 10, true) as $ip => $count) {
        echo "    " . $ip . " (" . $count . " hits)\n";
    }
}

function scanLogTarget($target)
{
    if (is_file($target)) {
        scanAccessLog($target);
        return;
    }

    if (!is_dir($target) || !is_readable($target)) {
        echo 'Error: cannot open log target ' . $target . "\n";
        exit(1);
    }

    ///////////////
    // A directory target scans everything in it that looks like an access
    // log (access*, *.log, rotated *.log.N and *.log.N.gz). Error logs have
    // a different format and are skipped.
    //////////////
    $dir = new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS);
    $files = new RecursiveIteratorIterator($dir, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);

    $logs_found = 0;
    foreach ($files as $file) {
        $basename = $file->getFilename();
        if (preg_match('@error@i', $basename)) {
            continue;
        }
        if (preg_match('@(?:access[^/]*|\.log(?:\.\d+)?(?:\.gz)?)$@i', $basename) !== 1) {
            continue;
        }
        scanAccessLog($file->getPathname());
        $logs_found++;
    }

    if (0 === $logs_found) {
        echo 'No access log files found in ' . $target . "\n";
    }
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
    $status = 0;
    if (isset($http_response_header) && is_array($http_response_header)) {
        // With redirects the array holds several header blocks; the last
        // status line is the one for the final response.
        foreach ($http_response_header as $header_line) {
            if (preg_match('@^HTTP/\S+\s(\d{3})@', $header_line, $matches)) {
                $status = (int) $matches[1];
            }
        }
    }
    return array($status, (false === $body) ? '' : $body);
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

function file_checksum_matches($file_path, $expected)
{
    $actual = @md5_file($file_path);
    if (false === $actual) {
        return (false);
    }
    // The plugin checksum API returns a string, or an array of valid
    // checksums when a release was ever repackaged.
    foreach ((array) $expected as $candidate) {
        if (hash_equals(strtolower((string) $candidate), $actual)) {
            return (true);
        }
    }
    return (false);
}

function list_files_recursive($dir, $base)
{
    $relative_paths = array();
    $walker = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );
    $base_length = strlen(rtrim($base, '/')) + 1;
    foreach ($walker as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $relative_paths[] = str_replace('\\', '/', substr($file->getPathname(), $base_length));
    }
    return $relative_paths;
}

function verify_against_manifest($base_dir, $manifest, $label, $present_files, &$totals)
{
    ///////////////
    // $manifest maps package-relative paths to expected md5(s). Report
    // mismatches (MODIFIED), files gone from disk (MISSING), and files on
    // disk that the official package does not contain (EXTRA). Extra or
    // modified PHP is the classic dropped/backdoored webshell: HIGH.
    //////////////
    foreach ($manifest as $relative_path => $expected) {
        $full_path = $base_dir . '/' . $relative_path;
        if (!is_file($full_path)) {
            report_finding('LOW', 'INTEGRITY_MISSING', $full_path, $label . ': file from the official package is missing');
            $totals['MISSING']++;
            continue;
        }
        if (null === $expected || !file_checksum_matches($full_path, $expected)) {
            $severity = is_php_file($relative_path) ? 'HIGH' : 'MEDIUM';
            report_finding($severity, 'INTEGRITY_MODIFIED', $full_path, $label . ': checksum does not match the official package');
            $totals['MODIFIED']++;
        }
    }

    foreach ($present_files as $relative_path) {
        if (!isset($manifest[$relative_path])) {
            $severity = is_php_file($relative_path) ? 'HIGH' : 'LOW';
            report_finding($severity, 'INTEGRITY_EXTRA', $base_dir . '/' . $relative_path, $label . ': file is not part of the official package');
            $totals['EXTRA']++;
        }
    }
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
    $root = rtrim($root, '/');
    $version_file = $root . '/wp-includes/version.php';
    if (!is_file($version_file)) {
        echo 'Error: ' . $root . " does not look like a WordPress root (wp-includes/version.php not found)\n";
        exit(1);
    }

    $totals = array('MODIFIED' => 0, 'MISSING' => 0, 'EXTRA' => 0, 'NO_REFERENCE' => 0);

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
            echo 'Checking core ' . $wp_version . ' (' . count($data['checksums']) . " files)\n";
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
            verify_against_manifest($root, $manifest, 'core ' . $wp_version, $present, $totals);
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

        echo 'Checking plugin ' . $slug . ' ' . $version . ' (' . count($data['files']) . " files)\n";
        $manifest = array();
        foreach ($data['files'] as $relative_path => $sums) {
            $manifest[$relative_path] = isset($sums['md5']) ? $sums['md5'] : null;
        }
        verify_against_manifest($plugin_dir, $manifest, 'plugin ' . $slug . ' ' . $version, list_files_recursive($plugin_dir, $plugin_dir), $totals);
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

    echo 'Integrity scan complete: ' . $totals['MODIFIED'] . ' modified, ' . $totals['MISSING'] . ' missing, '
        . $totals['EXTRA'] . ' extra, ' . $totals['NO_REFERENCE'] . " without reference checksums\n";
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
    global $CLEANUP_SIGNATURES, $CRONTAB_SIGS, $ACCESS_LOG_SIGS;

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
}

lint_signatures();

////////////
// Standalone scan modes: neither needs a scan directory, so they run and
// exit before the directory validation below.
///////////
if ( isset($_GET['scancron']) ) {
    scanCronTab();
    die();
}

if ( isset($_GET['scanlog']) ) {
    scanLogTarget($_GET['scanlog']);
    die();
}

if ( isset($_GET['scanintegrity']) ) {
    scanIntegrity($_GET['scandirectory']);
    die();
}

////////////
// using RecursiveDirectoryIterator and RecursiveIteratorIterator to crawl the directories
// using SKIP_DOTS because it's not important
///////////
if (!is_dir($_GET['scandirectory']) || !is_readable($_GET['scandirectory'])) {
    echo 'Error: cannot open scan directory ' . $_GET['scandirectory'] . "\n";
    exit(1);
}

$dir = new RecursiveDirectoryIterator($_GET['scandirectory'], RecursiveDirectoryIterator::SKIP_DOTS);
// CATCH_GET_CHILD: an unreadable subdirectory is skipped instead of aborting the whole walk.
$files = new RecursiveIteratorIterator($dir, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);

////////////
// Defining our variables
//    - $filesize_limit : Filesize limit to read is 2MB, but it can be better configured if we have an idea of how big are the php files we backup
//    - $extensions_to_check : list of extensions we'll check for malware
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

///////////
// iterating through the files collected
//////////
foreach( $files as $file ){
    $target_file = $file->getPathname();

//////////
//// Ignore current script
/////////
    if ( $file->getRealPath() === __FILE__ ) {
         continue;
    }
//////////
//// File will be scannable if extensions are on the list $extensions_to_check
/////////
    $scannable_file = isset($_GET['scan_all'])
        || in_array(strtolower($file->getExtension()), $extensions_to_check, true);
    if ( !$scannable_file ) {
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
    //echo "Scanning $target_file \n";
    $fh = @fopen($target_file, 'r');
    if (false === $fh) {
        echo 'Error reading ' . $target_file . "\n";
        continue;
    }
    $buffer = @fread($fh, $filesize_limit);
    @fclose($fh);
    if (false === $buffer) {
        echo 'Error reading ' . $target_file . "\n";
        continue;
    }

//////////
//  Performing the cleanup
//////////
    cleanup_util($buffer, $target_file);
}
