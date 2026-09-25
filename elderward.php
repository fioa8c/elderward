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

if ( isset($_GET['scancron']) ) {
    scanCronTab();
    die();
}

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
