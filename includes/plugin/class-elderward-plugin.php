<?php
/**
 * Plugin bootstrap: activation, shared helpers, wiring of the admin page.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Elderward_Plugin
{
    const DB_VERSION = '1';
    const OPTION_DB_VERSION = 'elderward_db_version';

    public static function init()
    {
        if (get_option(self::OPTION_DB_VERSION) !== self::DB_VERSION) {
            // Covers installs activated before a schema change and
            // network-wide activations that skipped the hook.
            self::create_table();
        }
        if (is_admin()) {
            Elderward_Admin::init();
        }
    }

    public static function activate()
    {
        self::create_table();
    }

    /**
     * Only administrators may run scans or read results; on multisite the
     * scan covers the whole install, so only super admins qualify.
     */
    public static function can_manage()
    {
        if (!current_user_can('manage_options')) {
            return false;
        }
        if (is_multisite() && !is_super_admin()) {
            return false;
        }
        return true;
    }

    /**
     * One findings table per install (base prefix on multisite).
     */
    public static function findings_table()
    {
        global $wpdb;
        return $wpdb->base_prefix . 'elderward_findings';
    }

    public static function create_table()
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $table = self::findings_table();
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            job_id varchar(32) NOT NULL,
            severity varchar(8) NOT NULL,
            type varchar(40) NOT NULL,
            path text NOT NULL,
            detail text NOT NULL,
            context longtext NULL,
            created datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY job_severity (job_id, severity)
        ) {$charset_collate};";
        dbDelta($sql);
        update_option(self::OPTION_DB_VERSION, self::DB_VERSION, false);
    }

    /**
     * Build an engine Context wired to WordPress: HTTP through the
     * WordPress HTTP API, database through $wpdb, the plugin's own folder
     * excluded from file scans.
     *
     * @param array                      $options  Engine options (key => value).
     * @param Elderward\Engine\Reporter  $reporter Where findings go.
     * @param string|null                $work_dir Directory for work files.
     */
    public static function make_context(array $options, Elderward\Engine\Reporter $reporter, $work_dir = null)
    {
        if (!isset($options['scandirectory'])) {
            $options['scandirectory'] = untrailingslashit(ABSPATH);
        }
        return new Elderward\Engine\Context(
            $options,
            $reporter,
            new Elderward_WP_Http(),
            new Elderward_WP_Db(),
            ELDERWARD_DIR,
            null === $work_dir ? get_temp_dir() : $work_dir
        );
    }
}
