<?php
/**
 * Tools > Elderward: start a report-only scan, watch it progress, read
 * and export the findings.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Admin
{
    const PAGE = 'elderward';
    const NONCE_SCAN = 'elderward_scan';
    const NONCE_EXPORT = 'elderward_export';
    const PER_PAGE = 200;

    private static $hook_suffix = '';

    public static function init()
    {
        if (is_multisite()) {
            add_action('network_admin_menu', array(__CLASS__, 'register_network_menu'));
        } else {
            add_action('admin_menu', array(__CLASS__, 'register_menu'));
        }
        add_action('admin_enqueue_scripts', array(__CLASS__, 'enqueue'));
        add_action('wp_ajax_elderward_start', array(__CLASS__, 'ajax_start'));
        add_action('wp_ajax_elderward_step', array(__CLASS__, 'ajax_step'));
        add_action('wp_ajax_elderward_status', array(__CLASS__, 'ajax_status'));
        add_action('wp_ajax_elderward_cancel', array(__CLASS__, 'ajax_cancel'));
        add_action('admin_post_elderward_export', array(__CLASS__, 'export'));
    }

    public static function register_menu()
    {
        self::$hook_suffix = add_management_page(
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
            'manage_options',
            self::PAGE,
            array(__CLASS__, 'render_page')
        );
    }

    public static function register_network_menu()
    {
        self::$hook_suffix = add_submenu_page(
            'settings.php',
            __('Elderward', 'elderward'),
            __('Elderward', 'elderward'),
            'manage_network',
            self::PAGE,
            array(__CLASS__, 'render_page')
        );
    }

    public static function enqueue($hook_suffix)
    {
        if ($hook_suffix !== self::$hook_suffix) {
            return;
        }
        wp_enqueue_style('elderward-admin', ELDERWARD_URL . 'assets/admin.css', array(), ELDERWARD_VERSION);
        wp_enqueue_script('elderward-admin', ELDERWARD_URL . 'assets/admin.js', array(), ELDERWARD_VERSION, true);
        $job = Elderward_Job::current();
        wp_localize_script('elderward-admin', 'elderwardAdmin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce(self::NONCE_SCAN),
            'status'  => null === $job ? '' : $job['status'],
            'i18n'    => array(
                'starting'  => __('Starting scan…', 'elderward'),
                /* translators: %s: name of the scanner currently running */
                'running'   => __('Scanning: %s', 'elderward'),
                'done'      => __('Scan complete. Reloading…', 'elderward'),
                /* translators: %s: error message */
                'failed'    => __('Scan failed: %s', 'elderward'),
                'cancelled' => __('Scan cancelled.', 'elderward'),
                'network'   => __('Lost contact with the server; retrying…', 'elderward'),
                'confirm'   => __('Cancel the running scan?', 'elderward'),
            ),
        ));
    }

    private static function require_access()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_send_json_error(array('message' => __('You are not allowed to do that.', 'elderward')), 403);
        }
    }

    public static function ajax_start()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();

        $options = array();
        $log = isset($_POST['log']) ? sanitize_text_field(wp_unslash($_POST['log'])) : '';
        if ('' !== $log) {
            // The only free-text input: it must name an existing, readable
            // log file or directory. Nothing else is accepted.
            $real = realpath($log);
            if (false === $real || !is_readable($real) || !(is_file($real) || is_dir($real))) {
                wp_send_json_error(array('message' => __('The access log path does not exist or is not readable by PHP.', 'elderward')), 400);
            }
            $options['scanlog'] = $real;
        }

        $job = Elderward_Job::start($options);
        if (is_wp_error($job)) {
            wp_send_json_error(array('message' => $job->get_error_message()), 409);
        }
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_step()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        $job = Elderward_Job::step();
        wp_send_json_success(self::status_payload($job));
    }

    public static function ajax_status()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Elderward_Job::current()));
    }

    public static function ajax_cancel()
    {
        check_ajax_referer(self::NONCE_SCAN, 'nonce');
        self::require_access();
        wp_send_json_success(self::status_payload(Elderward_Job::cancel()));
    }

    private static function status_payload($job)
    {
        if (null === $job) {
            return array('status' => '', 'percent' => 0, 'stage' => '', 'message' => '', 'counts' => array(), 'error' => '');
        }
        return array(
            'status'  => $job['status'],
            'percent' => Elderward_Job::percent($job),
            'stage'   => Elderward_Job::stage_label($job),
            'message' => $job['message'],
            'counts'  => $job['counts'],
            'error'   => $job['error'],
            'units'   => $job['units_done'],
        );
    }

    /**
     * Download the findings as today's CLI formats: CSV-style text lines or
     * NDJSON finding events.
     */
    public static function export()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        $nonce = isset($_GET['_wpnonce']) ? sanitize_text_field(wp_unslash($_GET['_wpnonce'])) : '';
        if (!wp_verify_nonce($nonce, self::NONCE_EXPORT)) {
            wp_die(esc_html__('Expired link, go back and try again.', 'elderward'), '', array('response' => 403));
        }
        $format = (isset($_GET['format']) && 'json' === $_GET['format']) ? 'json' : 'txt';
        $job = Elderward_Job::current();
        $job_id = null === $job ? '' : $job['id'];

        nocache_headers();
        header('Content-Type: ' . ('json' === $format ? 'application/x-ndjson' : 'text/plain') . '; charset=utf-8');
        header('Content-Disposition: attachment; filename="elderward-findings-' . gmdate('Ymd-His') . '.' . $format . '"');

        foreach (self::iterate_findings($job_id) as $row) {
            $context = self::decode_context($row->context);
            if ('json' === $format) {
                $event = array('event' => 'finding', 'severity' => $row->severity, 'type' => $row->type, 'path' => $row->path, 'detail' => $row->detail);
                if (!empty($context)) {
                    $event['context'] = $context;
                }
                echo wp_json_encode($event) . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- machine-readable download, JSON-encoded.
            } else {
                $line = Elderward\Engine\BaseReporter::format_text_finding(array(
                    'severity' => $row->severity, 'type' => $row->type, 'path' => $row->path, 'detail' => $row->detail, 'context' => $context,
                ));
                echo $line; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text download; the formatter percent-encodes control characters.
            }
        }
        exit;
    }

    private static function iterate_findings($job_id)
    {
        global $wpdb;
        $table = Elderward_Plugin::findings_table();
        $last = 0;
        // phpcs:disable WordPress.DB -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        while (true) {
            $rows = $wpdb->get_results($wpdb->prepare(
                "SELECT id, severity, type, path, detail, context FROM `{$table}` WHERE job_id = %s AND id > %d ORDER BY FIELD(severity,'HIGH','ERROR','MEDIUM','LOW','INFO'), id LIMIT 500",
                $job_id, $last
            ));
            if (empty($rows)) {
                return;
            }
            foreach ($rows as $row) {
                $last = max($last, (int) $row->id);
                yield $row;
            }
        }
        // phpcs:enable WordPress.DB
    }

    private static function decode_context($json)
    {
        if (null === $json || '' === $json) {
            return array();
        }
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : array();
    }

    public static function render_page()
    {
        if (!Elderward_Plugin::can_manage()) {
            wp_die(esc_html__('You are not allowed to do that.', 'elderward'), '', array('response' => 403));
        }
        global $wpdb;
        $job = Elderward_Job::current();
        $table = Elderward_Plugin::findings_table();
        $severities = array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO');

        $filter = isset($_GET['severity']) ? sanitize_key(wp_unslash($_GET['severity'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter on a listing.
        $filter = in_array(strtoupper($filter), $severities, true) ? strtoupper($filter) : '';
        $paged = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only pagination.

        $counts = array_fill_keys($severities, 0);
        $total = 0;
        // phpcs:disable WordPress.DB -- the plugin's own table (name from the base prefix, never user input); values go through prepare(); results must not be cached.
        if (null !== $job) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT severity, COUNT(*) AS n FROM `{$table}` WHERE job_id = %s GROUP BY severity", $job['id']));
            foreach ((array) $rows as $row) {
                if (isset($counts[$row->severity])) {
                    $counts[$row->severity] = (int) $row->n;
                }
                $total += (int) $row->n;
            }
        }
        $shown = '' === $filter ? $total : $counts[$filter];
        $pages = max(1, (int) ceil($shown / self::PER_PAGE));
        $paged = min($paged, $pages);

        $findings = array();
        if (null !== $job && $shown > 0) {
            $where = "job_id = %s" . ('' === $filter ? '' : ' AND severity = %s');
            $params = '' === $filter ? array($job['id']) : array($job['id'], $filter);
            $params[] = self::PER_PAGE;
            $params[] = ($paged - 1) * self::PER_PAGE;
            $findings = $wpdb->get_results($wpdb->prepare(
                "SELECT severity, type, path, detail, context FROM `{$table}` WHERE {$where} ORDER BY FIELD(severity,'HIGH','ERROR','MEDIUM','LOW','INFO'), id LIMIT %d OFFSET %d",
                $params
            ));
        }
        // phpcs:enable WordPress.DB

        $page_url = is_multisite() ? network_admin_url('settings.php?page=' . self::PAGE) : admin_url('tools.php?page=' . self::PAGE);
        $export_base = wp_nonce_url(admin_url('admin-post.php?action=elderward_export'), self::NONCE_EXPORT);
        $root = untrailingslashit(ABSPATH);
        ?>
        <div class="wrap elderward-wrap">
            <h1><?php esc_html_e('Elderward', 'elderward'); ?></h1>
            <p class="description">
                <?php esc_html_e('A report-only look at this install: quick checks, core/plugin/theme integrity, timestamps, crontab, database and (optionally) access logs, then the malware signatures in dry-run mode. Nothing is modified.', 'elderward'); ?>
            </p>

            <div class="elderward-card">
                <form id="elderward-start-form" onsubmit="return false;">
                    <label for="elderward-log"><?php esc_html_e('Access log file or directory (optional)', 'elderward'); ?></label>
                    <input type="text" id="elderward-log" class="regular-text code" placeholder="/var/log/apache2" autocomplete="off" />
                    <p class="description"><?php esc_html_e('Must be readable by the PHP user. Rotated .log.N and .gz files in a directory are included.', 'elderward'); ?></p>
                    <p>
                        <button type="button" class="button button-primary" id="elderward-start" <?php disabled(null !== $job && 'running' === $job['status']); ?>><?php esc_html_e('Start scan', 'elderward'); ?></button>
                        <button type="button" class="button" id="elderward-cancel" <?php disabled(null === $job || 'running' !== $job['status']); ?>><?php esc_html_e('Cancel', 'elderward'); ?></button>
                    </p>
                </form>
                <div id="elderward-progress" class="elderward-progress" <?php echo (null !== $job && 'running' === $job['status']) ? '' : 'hidden'; ?>>
                    <div class="elderward-bar"><div class="elderward-bar-fill" style="width: <?php echo null === $job ? 0 : (int) Elderward_Job::percent($job); ?>%"></div></div>
                    <p id="elderward-status-text"><?php echo null === $job ? '' : esc_html($job['message']); ?></p>
                </div>
                <?php if (null !== $job) : ?>
                    <p class="elderward-last">
                        <?php
                        printf(
                            /* translators: 1: status word, 2: start date/time, 3: end date/time or dash */
                            esc_html__('Last scan: %1$s. Started %2$s, finished %3$s.', 'elderward'),
                            '<strong>' . esc_html(self::status_word($job['status'])) . '</strong>',
                            esc_html(wp_date(get_option('date_format') . ' ' . get_option('time_format'), $job['started'])),
                            esc_html(null === $job['finished'] ? '—' : wp_date(get_option('date_format') . ' ' . get_option('time_format'), $job['finished']))
                        );
                        if ('' !== $job['error']) {
                            echo ' <span class="elderward-error">' . esc_html($job['error']) . '</span>';
                        }
                        ?>
                    </p>
                <?php endif; ?>
            </div>

            <?php if (null !== $job) : ?>
            <h2><?php esc_html_e('Findings', 'elderward'); ?></h2>
            <ul class="subsubsub elderward-filters">
                <li><a href="<?php echo esc_url($page_url); ?>" class="<?php echo '' === $filter ? 'current' : ''; ?>"><?php esc_html_e('All', 'elderward'); ?> <span class="count">(<?php echo (int) $total; ?>)</span></a></li>
                <?php foreach ($severities as $severity) : ?>
                    <li>| <a href="<?php echo esc_url(add_query_arg('severity', strtolower($severity), $page_url)); ?>" class="<?php echo $filter === $severity ? 'current' : ''; ?>"><?php echo esc_html($severity); ?> <span class="count">(<?php echo (int) $counts[$severity]; ?>)</span></a></li>
                <?php endforeach; ?>
            </ul>
            <p class="elderward-export">
                <a class="button" href="<?php echo esc_url(add_query_arg('format', 'txt', $export_base)); ?>"><?php esc_html_e('Export text (CSV lines)', 'elderward'); ?></a>
                <a class="button" href="<?php echo esc_url(add_query_arg('format', 'json', $export_base)); ?>"><?php esc_html_e('Export JSON (NDJSON)', 'elderward'); ?></a>
            </p>

            <table class="widefat striped elderward-table">
                <thead>
                    <tr>
                        <th class="elderward-col-sev"><?php esc_html_e('Severity', 'elderward'); ?></th>
                        <th class="elderward-col-type"><?php esc_html_e('Type', 'elderward'); ?></th>
                        <th><?php esc_html_e('Path', 'elderward'); ?></th>
                        <th><?php esc_html_e('Detail', 'elderward'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($findings)) : ?>
                    <tr><td colspan="4"><?php echo 'running' === $job['status'] ? esc_html__('Scan in progress…', 'elderward') : esc_html__('No findings.', 'elderward'); ?></td></tr>
                <?php else : ?>
                    <?php foreach ($findings as $finding) : ?>
                        <?php
                        $path = (string) $finding->path;
                        $short = (0 === strpos($path, $root . '/')) ? substr($path, strlen($root) + 1) : $path;
                        $context = self::decode_context($finding->context);
                        ?>
                        <tr>
                            <td><span class="elderward-sev elderward-sev-<?php echo esc_attr(strtolower($finding->severity)); ?>"><?php echo esc_html($finding->severity); ?></span></td>
                            <td><code><?php echo esc_html($finding->type); ?></code></td>
                            <td><code title="<?php echo esc_attr($path); ?>"><?php echo esc_html($short); ?></code></td>
                            <td>
                                <?php echo esc_html($finding->detail); ?>
                                <?php if (!empty($context)) : ?>
                                    <details><summary><?php esc_html_e('Context', 'elderward'); ?></summary>
                                        <pre><?php echo esc_html(implode("\n", $context)); ?></pre>
                                    </details>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
            <?php if ($pages > 1) : ?>
                <div class="tablenav"><div class="tablenav-pages">
                    <?php
                    echo wp_kses_post(paginate_links(array(
                        'base'    => add_query_arg(array('paged' => '%#%', 'severity' => '' === $filter ? false : strtolower($filter)), $page_url),
                        'format'  => '',
                        'current' => $paged,
                        'total'   => $pages,
                    )));
                    ?>
                </div></div>
            <?php endif; ?>

            <h2><?php esc_html_e('Acting on the results', 'elderward'); ?></h2>
            <p><?php esc_html_e('This page never changes files. Cleanup and restore run from the command line, where you can take a backup first and preview with a dry run:', 'elderward'); ?></p>
            <pre class="elderward-cli">wp elderward scan --dryrun          <?php esc_html_e('# preview the signature cleanup', 'elderward'); ?>

wp elderward scan                   <?php esc_html_e('# remove known malware from infected files', 'elderward'); ?>

wp elderward integrity --restore --dryrun
wp elderward integrity --restore --quarantine-dir=/path/outside/webroot</pre>
            <p class="description"><?php esc_html_e('Without WP-CLI, the same scanners run from php bin/elderward.php inside the plugin folder; see the readme.', 'elderward'); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function status_word($status)
    {
        switch ($status) {
            case 'running':
                return __('running', 'elderward');
            case 'done':
                return __('complete', 'elderward');
            case 'failed':
                return __('failed', 'elderward');
            case 'cancelled':
                return __('cancelled', 'elderward');
        }
        return $status;
    }
}
