<?php
/**
 * A resumable scanall job for the admin page.
 *
 * The job record (option elderward_job) holds the stage list, the queue of
 * work units for the current stage and the scanner state, so each
 * admin-ajax request can run units for a few seconds, save, and let the
 * next request continue. Findings go to the findings table through
 * Elderward_Store_Reporter; work files live under uploads/elderward/<id>.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Job
{
    const OPTION = 'elderward_job';
    const LOCK_OPTION = 'elderward_job_lock';
    const LOCK_SECONDS = 90;
    const MAX_BUDGET_SECONDS = 10;

    public static function current()
    {
        $job = get_option(self::OPTION);
        return is_array($job) ? $job : null;
    }

    private static function save(array $job)
    {
        $job['updated'] = time();
        update_option(self::OPTION, $job, false);
        return $job;
    }

    /**
     * Start a new report-only scanall. Only one job is kept: previous
     * findings are removed. Returns the job or a WP_Error.
     *
     * @param array $options Engine options (scanlog etc.).
     */
    public static function start(array $options)
    {
        global $wpdb;

        $existing = self::current();
        if (null !== $existing && 'running' === $existing['status']) {
            return new WP_Error('elderward_running', __('A scan is already running.', 'elderward'));
        }

        $id = wp_generate_password(16, false, false);
        $work_dir = self::work_dir($id);
        if (!self::prepare_work_dir($work_dir)) {
            return new WP_Error('elderward_workdir', __('Could not create the work directory under wp-content/uploads.', 'elderward'));
        }
        if (null !== $existing) {
            self::remove_work_dir(self::work_dir($existing['id']));
        }
        $wpdb->query('DELETE FROM `' . Elderward_Plugin::findings_table() . '`'); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table; one report is kept.

        $options['scanall'] = 1;
        $options['scandirectory'] = untrailingslashit(ABSPATH);
        $probe = Elderward_Plugin::make_context($options, new Elderward_Store_Reporter($id, array()), $work_dir);
        try {
            Elderward\Engine\Signatures::lint();
            $ctx = Elderward\Engine\Runner::scanall_context($probe);
        } catch (Elderward\Engine\Fatal $e) {
            self::remove_work_dir($work_dir);
            return new WP_Error('elderward_fatal', $e->getMessage());
        }

        $job = array(
            'id'          => $id,
            'status'      => 'running',
            'options'     => $ctx->options,
            'stages'      => Elderward\Engine\Runner::scanall_stages($ctx),
            'stage_index' => 0,
            'queue'       => null,
            'state'       => array(),
            'states'      => array(),
            'counts'      => array(),
            'summaries'   => array(),
            'units_done'  => 0,
            'started'     => time(),
            'finished'    => null,
            'message'     => '',
            'error'       => '',
        );
        return self::save($job);
    }

    /**
     * Run work units until the time budget is spent. Returns the job.
     */
    public static function step()
    {
        $job = self::current();
        if (null === $job || 'running' !== $job['status']) {
            return $job;
        }
        if (!self::acquire_lock()) {
            // Another request is stepping this job; report its state.
            return $job;
        }

        wp_raise_memory_limit('admin');
        $budget = self::budget_seconds();
        $deadline = microtime(true) + $budget;

        $reporter = new Elderward_Store_Reporter($job['id'], $job['counts']);
        $ctx = Elderward_Plugin::make_context($job['options'], $reporter, self::work_dir($job['id']));

        try {
            while (microtime(true) < $deadline) {
                if ($job['stage_index'] >= count($job['stages'])) {
                    $job = self::complete($job, 'done');
                    break;
                }
                $stage = $job['stages'][$job['stage_index']];
                $ctx->deadline = $deadline;
                $scanner = Elderward\Engine\Runner::make_stage($ctx, $stage, $job['states']);

                if (null === $job['queue']) {
                    $job['state'] = $scanner->init_state();
                    $job['queue'] = $scanner->plan($job['state']);
                    $job['message'] = $reporter->last_progress();
                }

                if (0 === count($job['queue'])) {
                    $ctx->deadline = null;
                    $scanner->finish($job['state']);
                    $job['states'][$stage] = $job['state'];
                    $job['summaries'] = array_merge($job['summaries'], $reporter->summaries());
                    $job['stage_index']++;
                    $job['queue'] = null;
                    $job['state'] = array();
                    $job['counts'] = $reporter->counts();
                    $job = self::save($job);
                    continue;
                }

                $unit = array_shift($job['queue']);
                $next = $scanner->run($unit, $job['state']);
                if (null !== $next) {
                    $job['queue'] = array_merge(Elderward\Engine\Scanner::as_unit_list($next), $job['queue']);
                }
                $job['units_done']++;
                $job['counts'] = $reporter->counts();
                if ('' !== $reporter->last_progress()) {
                    $job['message'] = $reporter->last_progress();
                }
                $job = self::save($job);
            }
        } catch (Elderward\Engine\Fatal $e) {
            $job['error'] = $e->getMessage();
            $job['counts'] = $reporter->counts();
            $job = self::complete($job, 'failed');
        } catch (Throwable $e) { // phpcs:ignore PHPCompatibility.Classes.NewClasses.throwableFound -- plugin side requires PHP 7.2.
            $job['error'] = get_class($e) . ': ' . $e->getMessage();
            $job['counts'] = $reporter->counts();
            $job = self::complete($job, 'failed');
        }

        self::release_lock();
        return $job;
    }

    public static function cancel()
    {
        $job = self::current();
        if (null === $job || 'running' !== $job['status']) {
            return $job;
        }
        return self::complete($job, 'cancelled');
    }

    private static function complete(array $job, $status)
    {
        $job['status'] = $status;
        $job['finished'] = time();
        $job['queue'] = null;
        $job['state'] = array();
        self::remove_work_dir(self::work_dir($job['id']));
        return self::save($job);
    }

    /**
     * Fraction of the job done, from the stage index and the queue length.
     */
    public static function percent(array $job)
    {
        $stages = max(1, count($job['stages']));
        if ('running' !== $job['status']) {
            return 'done' === $job['status'] ? 100 : 0;
        }
        $within = 0.0;
        if (is_array($job['queue']) && count($job['queue']) > 0) {
            // Continuation units keep the queue from shrinking to zero on big
            // stages; cap the within-stage estimate so the bar still moves.
            $within = min(0.9, 1.0 / (count($job['queue']) + 1));
        }
        return (int) floor((($job['stage_index'] + $within) / $stages) * 100);
    }

    public static function stage_label(array $job)
    {
        if ('running' !== $job['status'] || $job['stage_index'] >= count($job['stages'])) {
            return '';
        }
        return Elderward\Engine\Runner::stage_label($job['stages'][$job['stage_index']]);
    }

    private static function budget_seconds()
    {
        $max = (int) ini_get('max_execution_time');
        if ($max <= 0) {
            return self::MAX_BUDGET_SECONDS;
        }
        return max(2, min(self::MAX_BUDGET_SECONDS, (int) floor($max * 0.6)));
    }

    // add_option is atomic on the option_name unique key, which makes it a
    // usable lock between two concurrent admin-ajax requests.
    private static function acquire_lock()
    {
        $held = get_option(self::LOCK_OPTION);
        if (false !== $held && (int) $held < time() - self::LOCK_SECONDS) {
            delete_option(self::LOCK_OPTION);
        }
        return add_option(self::LOCK_OPTION, (string) time(), '', false);
    }

    private static function release_lock()
    {
        delete_option(self::LOCK_OPTION);
    }

    public static function work_dir($id)
    {
        $uploads = wp_upload_dir(null, false);
        return trailingslashit($uploads['basedir']) . 'elderward/' . preg_replace('/[^A-Za-z0-9]/', '', (string) $id);
    }

    private static function prepare_work_dir($dir)
    {
        if (!wp_mkdir_p($dir)) {
            return false;
        }
        $parent = dirname($dir);
        // Nothing in here is meant to be served: file lists and downloaded
        // package zips.
        $guards = array(
            $parent . '/.htaccess'  => "Require all denied\nDeny from all\n",
            $parent . '/web.config' => '<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><authorization><deny users="*" /></authorization></system.webServer></configuration>',
            $parent . '/index.php'  => "<?php\n// Silence is golden.\n",
        );
        foreach ($guards as $path => $content) {
            if (!file_exists($path)) {
                @file_put_contents($path, $content); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,WordPress.PHP.NoSilencedErrors.Discouraged -- tiny guard files in the plugin's own upload folder; a failure is caught by the writability check below.
            }
        }
        return is_dir($dir) && is_writable($dir); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- local directory check.
    }

    private static function remove_work_dir($dir)
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach ((array) @scandir($dir) as $entry) {
            if ('.' === $entry || '..' === $entry) {
                continue;
            }
            @unlink($dir . '/' . $entry); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- the plugin's own work files.
        }
        @rmdir($dir); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- the plugin's own work directory.
    }
}
