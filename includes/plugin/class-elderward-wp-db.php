<?php
/**
 * Engine database adapter built on $wpdb.
 *
 * WordPress is already connected, so no credentials are parsed. Queries
 * stay SELECT-only and iterate in primary-key pages, which gives the same
 * row order as the streaming mysqli adapter used by the standalone CLI
 * and lets a web request pause between pages.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

class Elderward_WP_Db implements Elderward\Engine\Db
{
    const PAGE_SIZE = 500;

    public function connect(Elderward\Engine\Context $ctx)
    {
        global $wpdb;
        if (!($wpdb instanceof wpdb)) {
            return 'WordPress database connection not available';
        }
        return null;
    }

    public function name()
    {
        return defined('DB_NAME') ? DB_NAME : '';
    }

    public function prefix()
    {
        global $wpdb;
        return $wpdb->prefix;
    }

    public function table($short)
    {
        global $wpdb;
        switch ($short) {
            case 'users':
                return $wpdb->users;
            case 'usermeta':
                return $wpdb->usermeta;
            case 'options':
                return $wpdb->options;
            case 'posts':
                return $wpdb->posts;
        }
        return $wpdb->prefix . $short;
    }

    public function config_path()
    {
        return null;
    }

    public function each(array $query, $callback, $after = 0)
    {
        global $wpdb;

        $last = (int) $after;
        $base = 'SELECT ' . $query['columns'] . ' FROM ' . $query['from'];
        $where = (isset($query['where']) && '' !== $query['where']) ? '(' . $query['where'] . ') AND ' : '';

        $previous_suppress = $wpdb->suppress_errors(true);
        try {
            while (true) {
                // The fragments come from the engine's own fixed queries, never
                // from user input; the only variable parts are integers.
                $sql = $base . ' WHERE ' . $where . $query['pk'] . ' > ' . $last
                    . ' ORDER BY ' . $query['pk'] . ' LIMIT ' . (int) self::PAGE_SIZE;
                $rows = $wpdb->get_results($sql, ARRAY_N); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- fixed SELECT built by the engine; results must not be cached.
                if ('' !== $wpdb->last_error) {
                    return array('done' => false, 'last' => $last, 'error' => $wpdb->last_error, 'early' => $last > (int) $after);
                }
                if (empty($rows)) {
                    return array('done' => true, 'last' => $last, 'error' => null, 'early' => false);
                }
                foreach ($rows as $row) {
                    $last = (int) $row[0];
                    if (false === call_user_func($callback, $row)) {
                        return array('done' => false, 'last' => $last, 'error' => null, 'early' => false);
                    }
                }
                if (count($rows) < self::PAGE_SIZE) {
                    return array('done' => true, 'last' => $last, 'error' => null, 'early' => false);
                }
            }
        } finally {
            $wpdb->suppress_errors($previous_suppress);
        }
    }

    public function close()
    {
        // WordPress owns the connection.
    }
}
