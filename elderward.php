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
// Adding a custom signature 
//////////////


$CLEANUP_RULES = array(
    "signatures" => array(
            ////// This means that signatures don't have a pre-filter.
            
            ////NESTING with array key
            "/if\((typeof)?\s*nds.===.?undefined.?\)/" => array( "NESTING_REGEX",
                array(
                    "name" => "javascript_ndsw",
                    "triggers" => array(
                            array("REGEX_ALL", "/if\((typeof)?\s*nds.===.?undefined.?\)/"),
                            array("REGEX_ALL","/\w\s*=\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*parseInt\(\w\(\w\.\w\)\)\s*\/\s*[\dx]+\s*[\+\s*\-]+\s*/"),
                    ),
                    "actions" => array(
                            array("REGEX_CLEANUP", "if\((typeof)?\s*nds.===.?undefined.?\)[^#]+return\s*A\s*\(\s*\)\s*;?\s*}\s*}\s*;?")
                    ),
                    "filenameRegex" => "",
                ),
            ),
            "/if\((typeof)?\s*wqpq\s*===.?undefined.?\)/" => array( "NESTING_REGEX",
                array(
                    "name" => "javascript_wqpq",
                    "triggers" => array(
                            array("REGEX_ALL", "/if\((typeof)?\s*wqpq\s*===.?undefined.?\)/"),
                            array("REGEX_ALL","/try{var\s*\w\s*=\s*\-?parseInt\(\w\(0x\d+,\s*.\w+/"),
                    ),
                    "actions" => array(
                            array("REGEX_CLEANUP", "if\((typeof)?\s*\w+.?===.?undefined.?\)[^\n]+;\s*\}\s*\}\s*\(\s*\)\s*\);\s*\};")
                    ),
                    "filenameRegex" => "",
                ),
            ),
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
                            echo("$line $name\n");
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
//////////////
$ACCESS_LOG_SIGS = array(
    array(
        'name'        => 'access.uploads.php',
        'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*wp-content/uploads/[^"\s]*\.ph(?:p[34578]?|tml|ps|t)\b@i',
        'threshold'   => 1,
        'description' => 'PHP file requested inside wp-content/uploads. Uploads should never contain executable PHP; this is usually a webshell dropped through an upload form.',
    ),
    array(
        'name'        => 'access.webshell.names',
        'pattern'     => '@"(?:GET|POST|HEAD) /[^"\s]*(?:wso\d*|filesman|alfa(?:-rex|_data)?|b374k|c99(?:shell)?|r57|indoxploit|mini_?shell|webshell|priv8)[^"\s]*\.ph@i',
        'threshold'   => 1,
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

        echo "LOG_IOC," . $name . "," . $hit_counts[$name] . " hit(s)\n";
        echo "    " . $signature['description'] . "\n";
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

function check_file($file_buffer, $file_path, $signature_array)
{
    foreach ( $signature_array as $signature )
    {
        if ( false === is_array($signature) )
        {
            continue;
        }
        // No triggers means nothing can confirm the pre-filter hit: fail closed.
        if ( empty($signature['triggers']) )
        {
            continue;
        }

        // ALL triggers must match to confirm. An unknown trigger type can never
        // match, so a typo'd tag fails the signature instead of being skipped.
        $all_triggers_matched = true;
        foreach ( $signature['triggers'] as $trigger )
        {
            if ( $trigger[0] === "STRING_ALL" )
            {
                $trigger_matched = (false !== strpos($file_buffer, $trigger[1]));
            }
            elseif ( $trigger[0] === "REGEX_ALL" )
            {
                // preg_match returns false on engine errors (e.g. backtrack limit);
                // only an explicit 1 counts as a match so errors never flag a file.
                $trigger_matched = (preg_match($trigger[1], $file_buffer) === 1);
            }
            else
            {
                $trigger_matched = false;
            }

            if ( !$trigger_matched )
            {
                $all_triggers_matched = false;
                break;
            }
        }

        if ( $all_triggers_matched )
        {
            return(true);
        }
    }
    return(false);
}

function clean_file($file_buffer, $file_path, $signature_array)
{

    foreach ( $signature_array as $signature ) 
    {
        if ( false === is_array($signature) )
        {
            continue;
        }

        foreach ( $signature['actions'] as $action )
        {
            if ( $action[0] === "REGEX_CLEANUP" )
            {
                // $file_buffer already holds the whole file: files larger than
                // the read cap are skipped before ever being scanned.
                $cleared_file = preg_replace('/' . $action[1]. '/s', '', $file_buffer);
                if ( $cleared_file === null || ( strlen($file_buffer) === strlen($cleared_file) ) )
                {
                   echo 'Error cleaning ' . $file_path .' with signature '. $signature['name'] . "," . $action[1]."\n";
                   return(false);
                }
                // Dry run: the cleanup regex was applied and verified to change
                // the file, but nothing is written.
                if ( isset($_GET['dryrun']) )
                {
                    return("WOULD_CLEAR," . $file_path . "," . $signature['name'] . "\n");
                }
                if ( !write_cleaned_file($file_path, $cleared_file) )
                {
                   echo 'Error writing cleaned content to ' . $file_path .' with signature '. $signature['name'] . "\n";
                   return(false);
                }
                return("CLEARED," . $file_path . "," . $signature['name'] . "\n");
            }
            if ( $action[0] === "DELETE_FILE" )
            {
                // Dry run: report the deletion without touching the file.
                if ( isset($_GET['dryrun']) )
                {
                    return("WOULD_CLEAR," . $file_path . "," . $signature['name'] . "\n");
                }
                if (unlink($file_path) === false) {
                    echo 'Error deleting ' . $file_path .' with signature '. $signature['name'] . "\n";
                    return (false);
                }
                return ("CLEARED," . $file_path . "," . $signature['name'] . "\n");
            }

        }
    } 
}

function cleanup_util($file_buffer, $file_path)
{
    global $CLEANUP_RULES;
    foreach ( $CLEANUP_RULES as $signature_array ) {
      ///////////////
      // Loop through the signature nesting and stop on the first confirmed match
      //////////////
      foreach ($signature_array as $key => $signature)
      {
            // The array key is the cheap pre-filter; only a hit is worth
            // the full trigger evaluation in check_file().
            if ( $signature[0] === "NESTING_STRING" )
            {
                $pre_filter_hit = (false !== strpos($file_buffer, $key));
            }
            elseif ( $signature[0] === "NESTING_REGEX" )
            {
                // Only an explicit 1 counts as a match; false (engine error) must not flag.
                $pre_filter_hit = (preg_match($key, $file_buffer) === 1);
            }
            else
            {
                continue;
            }

            if ( !$pre_filter_hit || false === check_file($file_buffer, $file_path, $signature) )
            {
                continue;
            }

            ////////////////
            // Confirmed match: attempt to clean the file, then stop.
            //////////////
            $cleanup_result = clean_file($file_buffer, $file_path, $signature);
            if ( false !== $cleanup_result )
            {
                echo $cleanup_result;
            }
            return;
      }
    }
}

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
