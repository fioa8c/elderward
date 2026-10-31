<?php
/**
 * Removes everything Elderward stored: the findings table, its options,
 * and the work directory under uploads.
 *
 * @package Elderward
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.DB.DirectDatabaseQuery -- uninstall removes the plugin's own table and its own work files.

global $wpdb;

$elderward_table = $wpdb->base_prefix . 'elderward_findings';
$wpdb->query('DROP TABLE IF EXISTS `' . $elderward_table . '`'); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table name from the base prefix, never user input.

delete_option('elderward_db_version');
delete_option('elderward_job');
if (is_multisite()) {
    delete_site_option('elderward_job');
}

$elderward_uploads = wp_upload_dir(null, false);
if (empty($elderward_uploads['error']) && !empty($elderward_uploads['basedir'])) {
    $elderward_work = trailingslashit($elderward_uploads['basedir']) . 'elderward';
    if (is_dir($elderward_work)) {
        $elderward_files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($elderward_work, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($elderward_files as $elderward_entry) {
            if ($elderward_entry->isDir()) {
                @rmdir($elderward_entry->getPathname());
            } else {
                @unlink($elderward_entry->getPathname());
            }
        }
        @rmdir($elderward_work);
    }
}
