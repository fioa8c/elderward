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
    // Rows per query: with values capped at 256KB each this bounds the memory
    // one page can take.
    const PAGE_SIZE = 200;
    // Primary keys per query. The range grows while pages come back sparse
    // and shrinks when a page fills up, so a table with sparse ids (option_id
    // after years of transient churn, post ids with revisions) is crossed in
    // few queries while a dense one never returns more than PAGE_SIZE rows.
    const RANGE_START = 1000;
    const RANGE_MAX = 262144;

    private $ctx = null;

    public function connect(Elderward\Engine\Context $ctx)
    {
        global $wpdb;
        $this->ctx = $ctx;
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

    /**
     * Iterate rows in primary-key order, a bounded slice of the table per
     * query.
     *
     * Paging by row count (`pk > last LIMIT n`) is unbounded in time: when
     * few rows match the WHERE clause (the posts prefilter on a large,
     * clean table) each page is a full scan and a web request dies before
     * anything is saved. Paging by key range (`pk > last AND pk <= last +
     * range`) keeps every query cheap and moves the cursor even when a
     * range matches nothing, and the Context deadline is checked between
     * ranges so a step can pause with a continuation that resumes exactly
     * where it stopped.
     */
    public function each(array $query, $callback, $after = 0)
    {
        global $wpdb;

        $last = (int) $after;
        $base = 'SELECT ' . $query['columns'] . ' FROM ' . $query['from'];
        $where = (isset($query['where']) && '' !== $query['where']) ? '(' . $query['where'] . ') AND ' : '';

        $previous_suppress = $wpdb->suppress_errors(true);
        try {
            // The fragments come from the engine's own fixed queries, never
            // from user input; the only variable parts are integers.
            // phpcs:disable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- fixed SELECTs built by the engine; results must not be cached.
            $max = $wpdb->get_var('SELECT MAX(' . $query['pk'] . ') FROM ' . $query['from']);
            if ('' !== $wpdb->last_error) {
                return array('done' => false, 'last' => $last, 'error' => $wpdb->last_error, 'early' => false);
            }
            $max = (int) $max;
            if ($max <= $last) {
                return array('done' => true, 'last' => $last, 'error' => null, 'early' => false);
            }

            $range = self::RANGE_START;
            while (true) {
                $upper = min($max, $last + $range);
                $sql = $base . ' WHERE ' . $where . $query['pk'] . ' > ' . $last . ' AND ' . $query['pk'] . ' <= ' . $upper
                    . ' ORDER BY ' . $query['pk'] . ' LIMIT ' . (int) self::PAGE_SIZE;
                $rows = $wpdb->get_results($sql, ARRAY_N);
                if ('' !== $wpdb->last_error) {
                    return array('done' => false, 'last' => $last, 'error' => $wpdb->last_error, 'early' => $last > (int) $after);
                }
                // $wpdb keeps its own copy of the page in last_result; drop it
                // before the callbacks run so a page costs one copy, not two.
                $wpdb->flush();
                $count = count($rows);
                foreach ($rows as $row) {
                    $last = (int) $row[0];
                    if (false === call_user_func($callback, $row)) {
                        return array('done' => false, 'last' => $last, 'error' => null, 'early' => false);
                    }
                }
                unset($rows);

                if ($count < self::PAGE_SIZE) {
                    // The whole range came back: everything up to $upper is seen.
                    $last = $upper;
                    if ($count * 4 < self::PAGE_SIZE) {
                        $range = min(self::RANGE_MAX, $range * 2);
                    }
                } else {
                    // The page was cut by LIMIT: continue after the last row
                    // seen, with a tighter range.
                    $range = max(self::RANGE_START, (int) ($range / 2));
                }
                if ($last >= $max) {
                    return array('done' => true, 'last' => $last, 'error' => null, 'early' => false);
                }
                if (null !== $this->ctx && $this->ctx->out_of_time()) {
                    return array('done' => false, 'last' => $last, 'error' => null, 'early' => false);
                }
            }
            // phpcs:enable WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        } finally {
            $wpdb->suppress_errors($previous_suppress);
        }
    }

    public function close()
    {
        // WordPress owns the connection.
    }
}
