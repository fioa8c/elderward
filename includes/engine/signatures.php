<?php
namespace Elderward\Engine;

////////////////
// Signature data. Every set is compile-checked by Signatures::lint() before
// a scan starts: a malformed regex stops the run naming the signature
// instead of silently never matching.
//////////////

final class Signatures
{
    // Files larger than this are skipped by the signature scanner (and the
    // buffer read per file is capped at it).
    const FILESIZE_LIMIT = 2097152;

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
    //////////////
    public static function cleanup()
    {
        return array(
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
    }

    // Crontab persistence patterns: name => pattern pairs.
    public static function crontab()
    {
        return array(
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
    }

    ///////////////
    // Access log IoC signatures.
    // Each signature matches one line of a common/combined format access log.
    // "threshold" hides findings until that many hits are seen: a single POST to
    // wp-login.php is normal traffic, five hundred of them is a brute force.
    // Findings report as MEDIUM (attack attempts) unless the signature sets
    // "severity" - traffic to a shell already on disk is HIGH.
    //////////////
    public static function access_log()
    {
        return array(
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
    }

    // Patterns matched against option values (first 256KB of each).
    public static function db_options()
    {
        return array(
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
    }

    // Patterns matched against post content (candidates come from a
    // server-side LIKE prefilter).
    public static function db_posts()
    {
        return array(
            array(
                'name'        => 'db.post.php-tag',
                'pattern'     => '@<\?php@i',
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
    }

    ///////////////
    // Extra files that are commonly legitimate, keyed by basename. They still
    // report (an attacker can hide behind a known name) but as INFO with the
    // reason, so HIGH/MEDIUM triage stays clean.
    //////////////
    public static function known_benign()
    {
        return array(
            'error_log'         => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
            'php_errorlog'      => 'PHP error log created by the hosting stack - not malware, but worth reading for attack traces',
            'wordfence-waf.php' => 'Wordfence extended protection bootstrap (auto_prepend_file) - verify it only loads wordfence/waf/bootstrap.php',
        );
    }

    // Extensions the signature scanner (and the correlate walk) look at
    // unless allfiles=1 widens the scan to everything.
    public static function extensions()
    {
        return array(
            'asa', 'asp', 'aspx', 'cfm', 'cgi', 'cin', 'conf', 'cron', 'css', 'ejl',
            'htm', 'html', 'inc', 'izo', 'js', 'local', 'mod', 'php', 'php3', 'php4',
            'php5', 'php7', 'php8', 'phps', 'pht', 'phtml', 'pl', 'py', 'sct', 'sh',
            'shtml', 'tmpl', 'tpl',
        );
    }

    ///////////////
    // A malformed signature would otherwise silently never match. Stop the
    // run and name the broken signature instead.
    //////////////
    public static function lint()
    {
        foreach (self::cleanup() as $name => $signature) {
            if (!isset($signature['prefilter'], $signature['triggers'], $signature['action'])) {
                throw new Fatal('invalid cleanup signature ' . $name . ': prefilter, triggers and action are required');
            }

            $conditions = array_merge(array($signature['prefilter'], $signature['action']), $signature['triggers']);
            foreach ($conditions as $condition) {
                $pattern = null;
                if (isset($condition['regex'])) {
                    $pattern = $condition['regex'];
                } elseif (isset($condition['remove_regex'])) {
                    $pattern = $condition['remove_regex'];
                }
                if (null !== $pattern && false === @preg_match($pattern, '')) {
                    throw new Fatal('invalid regex in cleanup signature ' . $name . ': ' . $pattern);
                }
            }
        }

        foreach (self::crontab() as $item) {
            foreach ($item as $name => $pattern) {
                if (false === @preg_match($pattern, '')) {
                    throw new Fatal('invalid regex in crontab signature ' . $name . ': ' . $pattern);
                }
            }
        }

        foreach (self::access_log() as $signature) {
            if (false === @preg_match($signature['pattern'], '')) {
                throw new Fatal('invalid regex in access log signature ' . $signature['name'] . ': ' . $signature['pattern']);
            }
        }

        foreach (array_merge(self::db_options(), self::db_posts()) as $signature) {
            if (false === @preg_match($signature['pattern'], '')) {
                throw new Fatal('invalid regex in database signature ' . $signature['name'] . ': ' . $signature['pattern']);
            }
        }
    }
}
