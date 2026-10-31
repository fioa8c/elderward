<?php
namespace Elderward\Engine;

////////////////
// Access log IoC scanning and log-to-file correlation.
//
// Logs are streamed line by line (never loaded whole) so rotated
// multi-hundred-MB logs stay within the memory limit. Hits accumulate
// across every file of a directory target, so a brute force split over
// rotations still crosses its signature's reporting threshold. A unit is
// one log file plus a byte offset, so a huge file can be resumed.
//////////////

class LogScanner extends Scanner
{
    const LINES_PER_TIME_CHECK = 1000;

    private $target;

    public function __construct(Context $ctx, $target)
    {
        parent::__construct($ctx);
        $this->target = $target;
    }

    public function name()
    {
        return ('scanlog');
    }

    public function init_state()
    {
        return array(
            'acc'     => self::new_accumulator(),
            'flagged' => array(),
            'logs'    => 0,
        );
    }

    public function plan(array &$state)
    {
        if (is_file($this->target)) {
            $state['logs'] = 1;
            return array(array('file' => $this->target, 'offset' => 0, 'announce' => 0));
        }

        if (!is_dir($this->target) || !is_readable($this->target)) {
            throw new Fatal('cannot open log target ' . $this->target);
        }

        ///////////////
        // A directory target scans everything in it that looks like an access
        // log (access*, *.log, rotated *.log.N and *.log.N.gz) into ONE shared
        // accumulator, so thresholds apply to the traffic as a whole rather
        // than per rotation. Error logs have a different format: skipped.
        //////////////
        $units = array();
        foreach (recursive_file_iterator($this->target) as $file) {
            $basename = $file->getFilename();
            if (preg_match('@error@i', $basename)) {
                continue;
            }
            if (preg_match('@(?:access[^/]*|\.log(?:\.\d+)?(?:\.gz)?)$@i', $basename) !== 1) {
                continue;
            }
            $units[] = array('file' => $file->getPathname(), 'offset' => 0, 'announce' => 1);
        }
        $state['logs'] = count($units);
        if (0 === count($units)) {
            $this->progress('No access log files found in ' . $this->target . "\n");
        }
        return ($units);
    }

    public function run(array $unit, array &$state)
    {
        if (!empty($unit['announce'])) {
            $this->progress('Scanning ' . $unit['file'] . "\n");
        }
        return ($this->scan_log($unit['file'], (int) $unit['offset'], $state['acc']));
    }

    public function finish(array &$state)
    {
        if (0 === $state['logs']) {
            return;
        }
        $state['flagged'] = $this->report_findings($state['acc'], $this->target);
    }

    public static function new_accumulator()
    {
        return array('counts' => array(), 'examples' => array(), 'ips' => array(), 'minutes' => array());
    }

    private function scan_log($log_path, $offset, array &$acc)
    {
        $is_gzipped = ('gz' === strtolower(pathinfo($log_path, PATHINFO_EXTENSION)));
        if ($is_gzipped && !function_exists('gzopen')) {
            $this->report('ERROR', 'LOG_UNREADABLE', $log_path, 'compressed log NOT scanned: PHP zlib extension not available (decompress it first, or scan from a host with zlib)');
            return (null);
        }

        $fh = $is_gzipped ? @gzopen($log_path, 'r') : @fopen($log_path, 'r');
        if (false === $fh) {
            $this->report('ERROR', 'LOG_UNREADABLE', $log_path, 'log NOT scanned: cannot open it (permissions?)');
            return (null);
        }
        if ($offset > 0) {
            $is_gzipped ? gzseek($fh, $offset) : fseek($fh, $offset);
        }

        $max_examples = 5;
        $max_example_length = 300;
        $hit_counts = &$acc['counts'];
        $hit_examples = &$acc['examples'];
        $hit_ips = &$acc['ips'];
        // Per-signature, per-minute buckets of matched lines, kept for the
        // correlate mode. Minute granularity bounds memory on flooded logs.
        $hit_minutes = &$acc['minutes'];
        $signatures = Signatures::access_log();

        $lines = 0;
        while (true) {
            if ($lines > 0 && 0 === ($lines % self::LINES_PER_TIME_CHECK) && $this->ctx->out_of_time()) {
                $position = $is_gzipped ? gztell($fh) : ftell($fh);
                $is_gzipped ? gzclose($fh) : fclose($fh);
                return array('file' => $log_path, 'offset' => $position, 'announce' => 0);
            }
            $line = self::read_line($fh, $is_gzipped);
            if (false === $line) {
                break;
            }
            $lines++;

            foreach ($signatures as $signature) {
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

                $timestamp = self::parse_timestamp($line);
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
        return (null);
    }

    public static function read_line($fh, $is_gzipped)
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

    public static function parse_timestamp($line)
    {
        // Common/combined log format: [20/Sep/2026:10:05:01 +0000]
        if (!preg_match('@\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]@', $line, $matches)) {
            return (null);
        }
        $parsed = \DateTime::createFromFormat('d/M/Y:H:i:s O', $matches[1]);
        return (false === $parsed) ? null : $parsed->getTimestamp();
    }

    private static function merge_flagged_minutes(&$into, $from)
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

    private function report_findings($acc, $target_label)
    {
        $hit_counts = $acc['counts'];
        $hit_examples = $acc['examples'];
        $hit_ips = $acc['ips'];
        $hit_minutes = $acc['minutes'];

        ///////////////
        // Report: every signature at or over its threshold, with example lines,
        // then the source IPs behind the reported hits.
        //////////////
        $this->progress("== Access log IoC report: " . $target_label . " ==\n");

        $reported = 0;
        $reported_ips = array();
        $flagged_minutes = array();
        foreach (Signatures::access_log() as $signature) {
            $name = $signature['name'];
            if (!isset($hit_counts[$name]) || $hit_counts[$name] < $signature['threshold']) {
                continue;
            }
            $reported++;
            if (isset($hit_minutes[$name])) {
                self::merge_flagged_minutes($flagged_minutes, $hit_minutes[$name]);
            }

            $severity = isset($signature['severity']) ? $signature['severity'] : 'MEDIUM';
            $context = array();
            foreach ($hit_examples[$name] as $example) {
                $context[] = 'e.g. ' . $example;
            }
            $this->report($severity, 'LOG_IOC', $target_label, $name . ': ' . $hit_counts[$name] . ' hit(s) - ' . $signature['description'], $context);

            foreach ($hit_ips[$name] as $ip => $count) {
                $reported_ips[$ip] = isset($reported_ips[$ip]) ? $reported_ips[$ip] + $count : $count;
            }
        }

        if (0 === $reported) {
            $this->summary('scanlog', array('flagged_signatures' => 0), "No known IoCs found.\n");
            return (array());
        }

        arsort($reported_ips);
        $top_ips = array_slice($reported_ips, 0, 10, true);
        $text = "Top source IPs on flagged requests:\n";
        foreach ($top_ips as $ip => $count) {
            $text .= "    " . $ip . " (" . $count . " hits)\n";
        }
        $this->summary('scanlog', array('flagged_signatures' => $reported, 'top_ips' => $top_ips), $text);

        return ($flagged_minutes);
    }
}

class CorrelateScanner extends Scanner
{
    private $root;
    private $flagged_minutes;
    private $window;

    public function __construct(Context $ctx, $root, array $flagged_minutes, $window)
    {
        parent::__construct($ctx);
        $this->root = $root;
        $this->flagged_minutes = $flagged_minutes;
        $this->window = $window;
    }

    public function name()
    {
        return ('correlate');
    }

    public function plan(array &$state)
    {
        return array(array('correlate' => 1));
    }

    public function run(array $unit, array &$state)
    {
        ///////////////
        // The IR smoking gun: a file whose mtime falls inside the window around
        // flagged attack traffic. Report-only - a hit is a strong lead, but a
        // miss clears nothing (later edits and faked mtimes erase the link).
        //////////////
        $flagged_minutes = $this->flagged_minutes;
        $window = $this->window;
        if (empty($flagged_minutes)) {
            $this->progress("Correlation: no flagged log traffic to correlate against.\n");
            return (null);
        }
        if (!is_dir($this->root) || !is_readable($this->root)) {
            throw new Fatal('cannot open correlation directory ' . $this->root);
        }

        $files = recursive_file_iterator($this->root);

        $correlated = 0;
        foreach ($files as $file) {
            if (!is_scannable_file($this->ctx, $file)) {
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
            $this->report($severity, 'LOG_FILE_CORRELATION', $path,
                'modified ' . date('Y-m-d H:i:s', $mtime) . ' within ' . $window . 's of flagged traffic: '
                . implode(' ', array_keys($in_window['names'])) . ' (' . $in_window['count'] . ' flagged requests in window)',
                array('e.g. ' . $in_window['example']));
            $correlated++;
        }

        $this->summary('correlate', array('correlated' => $correlated, 'window_seconds' => $window),
            'Correlation complete: ' . $correlated . ' file(s) modified within ' . $window
            . "s of flagged traffic. Later edits or faked mtimes erase this link - a miss clears nothing.\n");
        return (null);
    }
}
