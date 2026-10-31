<?php
namespace Elderward\Engine;

////////////////
// Mode dispatch shared by every entry point (standalone CLI, WP-CLI, the
// admin page): maps a scan mode name to scanners and runs them.
//
// Modes: scanall, scancron, scanlog (+correlate), scanintegrity, scantimes,
// quickscan, scandb, and the default signature scan ("signatures").
//////////////

final class Runner
{
    const MODES = 'scanall,scancron,scanlog,scanintegrity,scantimes,quickscan,scandb';

    // Which standalone mode the options ask for ('signatures' when none).
    // Throws Fatal on invalid combinations.
    public static function mode_from_options(Context $ctx)
    {
        $requested = array();
        foreach (explode(',', self::MODES) as $mode) {
            if ($ctx->has($mode)) {
                $requested[] = $mode;
            }
        }
        // scanall consumes scanlog as its log input; every other combination
        // would silently run only one mode, so it is an error instead.
        if (count($requested) > 1 && $requested !== array('scanall', 'scanlog')) {
            throw new Fatal('scan modes are mutually exclusive, run them one at a time: ' . implode(', ', $requested));
        }
        // The old name for allfiles=1 was one underscore away from scanall=1
        // and meant something else entirely; refuse it rather than guess.
        if ($ctx->has('scan_all')) {
            throw new Fatal('scan_all=1 has been renamed: use allfiles=1 to scan every file extension, or scanall=1 to run every scanner');
        }
        if ($ctx->has('correlate') && !$ctx->has('scanlog')) {
            throw new Fatal('correlate=1 needs scanlog=/path to know which traffic to correlate against');
        }
        return (count($requested) > 0 ? $requested[0] : 'signatures');
    }

    public static function run_mode(Context $ctx, $mode)
    {
        Signatures::lint();

        switch ($mode) {
            case 'scanall':
                self::run_scanall($ctx);
                return;
            case 'scancron':
                Scanner::run_all(new CrontabScanner($ctx));
                return;
            case 'scanlog':
                $log_state = Scanner::run_all(new LogScanner($ctx, $ctx->get('scanlog')));
                if ($ctx->has('correlate')) {
                    Scanner::run_all(new CorrelateScanner($ctx, $ctx->get('scandirectory'), $log_state['flagged'], $ctx->correlation_window()));
                }
                return;
            case 'scanintegrity':
                Scanner::run_all(new IntegrityScanner($ctx));
                return;
            case 'scantimes':
                Scanner::run_all(new TimestampScanner($ctx));
                return;
            case 'quickscan':
                Scanner::run_all(new QuickScanner($ctx));
                return;
            case 'scandb':
                require_wordpress_root($ctx->root());
                Scanner::run_all(new DatabaseScanner($ctx, true));
                return;
            default:
                Scanner::run_all(new SignatureScanner($ctx, $ctx->get('scandirectory')));
                return;
        }
    }

    ///////////////
    // scanall: every scanner in sequence against the WordPress root,
    // report-only (the signature pass is forced into dry run and restore is
    // ignored). Returns the report-only Context so callers that run the
    // stages themselves (the admin page) share the exact same setup.
    //////////////
    public static function scanall_context(Context $ctx)
    {
        $root = require_wordpress_root($ctx->root());
        if ($ctx->has('restore')) {
            $ctx->reporter->progress("scanall is report-only: ignoring restore=1 (run scanintegrity=1 restore=1 separately)\n");
        }
        return ($ctx->with(array('scandirectory' => $root, 'dryrun' => 1), array('restore')));
    }

    // Ordered stage keys for scanall, given the options.
    public static function scanall_stages(Context $ctx)
    {
        $stages = array('quick', 'integrity', 'timestamps', 'crontab', 'database');
        if ($ctx->has('scanlog')) {
            $stages[] = 'logs';
            $stages[] = 'correlate';
        }
        $stages[] = 'signatures';
        return ($stages);
    }

    public static function stage_label($stage)
    {
        $labels = array(
            'quick'      => 'Quick checks',
            'integrity'  => 'Integrity',
            'timestamps' => 'Timestamps',
            'crontab'    => 'Crontab',
            'database'   => 'Database',
            'logs'       => 'Access logs',
            'correlate'  => 'Access logs',
            'signatures' => 'Malware signatures (dry run)',
        );
        return (isset($labels[$stage]) ? $labels[$stage] : $stage);
    }

    // Build the scanner for a scanall stage. $states holds the finished
    // states of earlier stages (correlate needs the log stage's result).
    public static function make_stage(Context $ctx, $stage, array $states)
    {
        switch ($stage) {
            case 'quick':
                return (new QuickScanner($ctx));
            case 'integrity':
                return (new IntegrityScanner($ctx));
            case 'timestamps':
                return (new TimestampScanner($ctx));
            case 'crontab':
                return (new CrontabScanner($ctx));
            case 'database':
                return (new DatabaseScanner($ctx, false));
            case 'logs':
                return (new LogScanner($ctx, $ctx->get('scanlog')));
            case 'correlate':
                $flagged = isset($states['logs']['flagged']) ? $states['logs']['flagged'] : array();
                return (new CorrelateScanner($ctx, $ctx->root(), $flagged, $ctx->correlation_window()));
            case 'signatures':
                return (new SignatureScanner($ctx, $ctx->root()));
        }
        throw new Fatal('unknown scan stage ' . $stage);
    }

    public static function run_scanall(Context $ctx)
    {
        $ctx = self::scanall_context($ctx);
        $reporter = $ctx->reporter;
        // In text mode findings buffer and print severity-sorted at the end;
        // JSON streams events as usual.
        if ($reporter instanceof TextReporter) {
            $reporter->buffer_findings(true);
        }

        $states = array();
        $previous = null;
        foreach (self::scanall_stages($ctx) as $stage) {
            $label = self::stage_label($stage);
            if ($label !== $previous) {
                $reporter->progress('== ' . $label . " ==\n");
            }
            $previous = $label;
            $states[$stage] = Scanner::run_all(self::make_stage($ctx, $stage, $states));
        }

        if ($reporter instanceof TextReporter) {
            $reporter->flush_buffered();
        }
    }
}
