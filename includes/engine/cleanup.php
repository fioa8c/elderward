<?php
namespace Elderward\Engine;

////////////////
// Signature-based malware detection and cleanup (the default scan mode).
//
// Files are collected first into a work file, then scanned in chunks so a
// web request can stop between chunks. The per-file logic is unchanged:
// a file is confirmed when its prefilter and every trigger match; the
// signature's action then removes the injection or deletes the file,
// unless dryrun is set, in which case nothing on disk changes.
//////////////

class SignatureScanner extends Scanner
{
    const CHUNK_FILES = 200;

    private $scan_dir;

    public function __construct(Context $ctx, $scan_dir)
    {
        parent::__construct($ctx);
        $this->scan_dir = $scan_dir;
    }

    public function name()
    {
        return ('signatures');
    }

    public function plan(array &$state)
    {
        if (!is_dir($this->scan_dir) || !is_readable($this->scan_dir)) {
            throw new Fatal('cannot open scan directory ' . $this->scan_dir);
        }
        return array(array('collect' => 1));
    }

    public function run(array $unit, array &$state)
    {
        if (isset($unit['collect'])) {
            return ($this->collect($state));
        }
        return ($this->scan_chunk($unit, $state));
    }

    private function collect(array &$state)
    {
        ///////////////
        // Walk the tree once and write every scannable path to a work file
        // (one base64-encoded path per line: filenames can contain newlines
        // and bytes that are not valid UTF-8).
        // Later chunks read from a byte offset, so no list sits in memory.
        //////////////
        $list_path = @tempnam($this->ctx->work_dir, 'elderward-files');
        if (false === $list_path) {
            throw new Fatal('cannot create a work file in ' . $this->ctx->work_dir);
        }
        $fh = @fopen($list_path, 'w');
        if (false === $fh) {
            @unlink($list_path);
            throw new Fatal('cannot write the work file ' . $list_path);
        }

        $files = recursive_file_iterator($this->scan_dir);
        foreach ($files as $file) {
            // Skip the tool itself and anything outside the risky-extension
            // list (allfiles=1 overrides) - shared with the correlate walk.
            if (!is_scannable_file($this->ctx, $file)) {
                continue;
            }
            fwrite($fh, base64_encode($file->getPathname()) . "\n"); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- one path per line, whatever bytes the filename holds.
        }
        fclose($fh);

        $state['list'] = $list_path;
        return array('from' => 0);
    }

    private function scan_chunk(array $unit, array &$state)
    {
        if (!isset($state['list']) || !is_file($state['list'])) {
            throw new Fatal('the scan work file disappeared mid-scan');
        }
        $fh = @fopen($state['list'], 'r');
        if (false === $fh) {
            throw new Fatal('cannot read the scan work file ' . $state['list']);
        }
        fseek($fh, (int) $unit['from']);

        $processed = 0;
        while (true) {
            if ($processed >= self::CHUNK_FILES || ($processed > 0 && $this->ctx->out_of_time())) {
                $next = array('from' => ftell($fh));
                fclose($fh);
                return ($next);
            }
            $line = fgets($fh);
            if (false === $line) {
                break;
            }
            $target_file = base64_decode(rtrim($line, "\n"), true); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- see collect().
            if (!is_string($target_file) || '' === $target_file) {
                continue;
            }
            $processed++;
            $this->scan_file($target_file);
        }
        fclose($fh);
        @unlink($state['list']);
        unset($state['list']);
        return (null);
    }

    private function scan_file($target_file)
    {
        // Files over the size cap are skipped; the read is capped too.
        $filesize = @filesize($target_file);
        if ($filesize > Signatures::FILESIZE_LIMIT) {
            return;
        }
        $fh = @fopen($target_file, 'r');
        if (false === $fh) {
            $this->progress('Error reading ' . $target_file . "\n");
            return;
        }
        $buffer = @fread($fh, Signatures::FILESIZE_LIMIT);
        @fclose($fh);
        if (false === $buffer) {
            $this->progress('Error reading ' . $target_file . "\n");
            return;
        }
        $this->cleanup($buffer, $target_file);
    }

    private function cleanup($file_buffer, $file_path)
    {
        // First confirmed signature wins: apply its action, then stop.
        foreach (Signatures::cleanup() as $signature_name => $signature) {
            if (self::signature_matches($file_buffer, $signature)) {
                $this->apply_action($file_buffer, $file_path, $signature_name, $signature['action']);
                return;
            }
        }
    }

    public static function pattern_matches($condition, $file_buffer)
    {
        // A condition is array('string' => needle) or array('regex' => pattern).
        if (isset($condition['string'])) {
            return (false !== strpos($file_buffer, $condition['string']));
        }
        if (isset($condition['regex'])) {
            // preg_match returns false on engine errors (e.g. backtrack limit);
            // only an explicit 1 counts as a match so errors never flag a file.
            return (preg_match($condition['regex'], $file_buffer) === 1);
        }
        // Unknown condition types never match, so a typo'd signature fails
        // closed instead of flagging files.
        return (false);
    }

    public static function signature_matches($file_buffer, $signature)
    {
        // The prefilter is the cheap first check and counts as confirmed
        // evidence; every additional trigger must ALSO match.
        if (!self::pattern_matches($signature['prefilter'], $file_buffer)) {
            return (false);
        }
        foreach ($signature['triggers'] as $trigger) {
            if (!self::pattern_matches($trigger, $file_buffer)) {
                return (false);
            }
        }
        return (true);
    }

    private function apply_action($file_buffer, $file_path, $signature_name, $action)
    {
        $dryrun = $this->ctx->has('dryrun');

        if (isset($action['remove_regex'])) {
            // $file_buffer already holds the whole file: files larger than
            // the read cap are skipped before ever being scanned.
            $cleared_file = preg_replace($action['remove_regex'], '', $file_buffer);
            if ($cleared_file === null || (strlen($file_buffer) === strlen($cleared_file))) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': cleanup regex removed nothing: ' . $action['remove_regex']);
                return;
            }
            // Dry run: the cleanup regex was applied and verified to change
            // the file, but nothing is written or deleted.
            if ($dryrun) {
                $this->report('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not modified)');
                return;
            }
            if (!write_cleaned_file($file_path, $cleared_file)) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not write cleaned file');
                return;
            }
            $this->report('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name);
            return;
        }

        if (isset($action['delete_file'])) {
            if ($dryrun) {
                $this->report('HIGH', 'MALWARE_FOUND', $file_path, $signature_name . ' (dry run: file not deleted)');
                return;
            }
            if (false === @unlink($file_path)) {
                $this->report('ERROR', 'CLEANUP_FAILED', $file_path, $signature_name . ': could not delete file');
                return;
            }
            $this->report('HIGH', 'MALWARE_CLEANED', $file_path, $signature_name . ' (file deleted)');
            return;
        }

        $this->report('ERROR', 'CLEANUP_FAILED', $file_path, 'unknown action for signature ' . $signature_name);
    }
}
