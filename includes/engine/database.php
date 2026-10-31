<?php
namespace Elderward\Engine;

////////////////
// Database scanning (report-only, SELECT-only)
//
// A large share of WordPress compromises live partly or entirely in the
// database: rogue administrators, script injections in options and posts,
// hijacked siteurl/home. Everything read from the DB is hostile data -
// values are pattern-matched only, NEVER unserialize()d (PHP object
// injection) and never executed.
//
// Units: administrators, options, posts; each carries the primary key it
// resumes after, so a paused unit continues where it stopped.
//////////////

class DatabaseScanner extends Scanner
{
    // An administrator registered this recently on a compromised site is the
    // classic takeover artifact.
    const RECENT_ADMIN_DAYS = 30;
    // Only the first 256KB of a value is scanned, so a giant transient or post
    // cannot balloon memory.
    const VALUE_SCAN_CAP = 262144;
    // Capabilities that amount to site takeover. A role other than
    // administrator holding one of them is how an attacker keeps a
    // low-profile account powerful. unfiltered_html is left out: editors hold
    // it by default on single-site installs.
    const ADMIN_CAPS = 'manage_options|edit_users|create_users|promote_users|delete_users|edit_files|edit_plugins|edit_themes|install_plugins|install_themes|update_core|activate_plugins|switch_themes';
    const MAX_REPORTED_POSTS = 100;

    private $fatal_on_error;
    private $connected = false;

    public function __construct(Context $ctx, $fatal_on_error)
    {
        parent::__construct($ctx);
        $this->fatal_on_error = $fatal_on_error;
    }

    public function name()
    {
        return ('database');
    }

    public function init_state()
    {
        return array(
            'counts'      => array('ADMINS' => 0, 'OPTIONS' => 0, 'FLAGGED_OPTIONS' => 0, 'FLAGGED_POSTS' => 0),
            'suppressed'  => 0,
            'unavailable' => false,
        );
    }

    private function connect()
    {
        if ($this->connected) {
            return (null);
        }
        if (null === $this->ctx->db) {
            return ('no database adapter configured, cannot scan the database');
        }
        $error = $this->ctx->db->connect($this->ctx);
        if (null === $error) {
            $this->connected = true;
        }
        return ($error);
    }

    public function plan(array &$state)
    {
        $root = $this->ctx->root();
        $failure = $this->connect();
        if (null !== $failure) {
            if ($this->fatal_on_error) {
                throw new Fatal($failure);
            }
            ///////////////
            // Inside scanall a skipped database is an ERROR finding: it has to
            // show in the JSON stream and the exit code, or "nothing found"
            // silently means "never looked".
            //////////////
            $config_path = (null === $this->ctx->db) ? null : $this->ctx->db->config_path();
            $where = (null !== $config_path) ? $config_path : $root . '/wp-config.php';
            $this->report('ERROR', 'DB_UNAVAILABLE', $where, $failure . ' - the database was NOT scanned');
            $state['unavailable'] = true;
            return array();
        }

        $this->progress('Scanning database ' . $this->ctx->db->name() . ' (prefix ' . $this->ctx->db->prefix() . ") - read-only\n");
        return array(
            array('table' => 'admins', 'after' => 0),
            array('table' => 'options', 'after' => 0),
            array('table' => 'posts', 'after' => 0),
        );
    }

    public function run(array $unit, array &$state)
    {
        $failure = $this->connect();
        if (null !== $failure) {
            throw new Fatal($failure);
        }
        switch ($unit['table']) {
            case 'admins':
                return ($this->scan_admins((int) $unit['after'], $state));
            case 'options':
                return ($this->scan_options((int) $unit['after'], $state));
            case 'posts':
                return ($this->scan_posts((int) $unit['after'], $state));
        }
        return (null);
    }

    public function finish(array &$state)
    {
        if ($state['unavailable']) {
            return;
        }
        if ($this->connected) {
            $this->ctx->db->close();
            $this->connected = false;
        }
        $counts = $state['counts'];
        $this->summary('database', $counts,
            'Database scan complete: ' . $counts['ADMINS'] . ' administrator(s), ' . $counts['OPTIONS'] . ' options scanned, '
            . $counts['FLAGGED_OPTIONS'] . ' flagged options, ' . $counts['FLAGGED_POSTS'] . " flagged posts\n");
    }

    ///////////////
    // A query that fails or a result stream that dies mid-way means that
    // part of the database was NOT checked. That is an ERROR finding (exit
    // 2, visible in JSON) - never a progress line and a clean-looking
    // summary. Returns the continuation unit when the iteration paused.
    //////////////
    private function iterate($short_table, $what, array $query, $callback, $after)
    {
        $db = $this->ctx->db;
        $result = $db->each($query, $callback, $after);
        if (null !== $result['error']) {
            $label = $result['early'] ? $what . ' (result stream ended early)' : $what;
            $this->report('ERROR', 'DB_QUERY_FAILED', 'db:' . $db->table($short_table), $label . ' NOT verified: ' . $result['error']);
            return (null);
        }
        if (!$result['done']) {
            return array('table' => $short_table === 'users' ? 'admins' : $short_table, 'after' => $result['last']);
        }
        return (null);
    }

    private function scan_admins($after, array &$state)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        $prefix = $db->prefix();
        $users_table = $db->table('users');
        $recent_cutoff = time() - (self::RECENT_ADMIN_DAYS * 86400);

        // Serialized capabilities look like a:1:{s:13:"administrator";b:1;}.
        // Matching the b:1 excludes a revoked role (b:0) and look-alike custom
        // role names.
        $query = array(
            'columns' => 'u.ID, u.user_login, u.user_email, u.user_registered',
            'from'    => $users_table . ' u JOIN ' . $db->table('usermeta') . ' m ON m.user_id = u.ID',
            'where'   => "m.meta_key = '" . $prefix . "capabilities' AND m.meta_value LIKE '%\"administrator\";b:1;%'",
            'pk'      => 'u.ID',
        );
        $scanner = $this;
        return $this->iterate('users', 'administrators', $query, function ($row) use (&$counts, $ctx, $users_table, $recent_cutoff, $scanner) {
            $counts['ADMINS']++;
            $registered = strtotime($row[3]);
            $where = 'db:' . $users_table . ':ID=' . $row[0];
            $who = '"' . $row[1] . '" <' . $row[2] . '> registered ' . $row[3];

            if (false !== $registered && $registered >= $recent_cutoff) {
                $scanner->report_public('MEDIUM', 'DB_NEW_ADMIN', $where, 'administrator ' . $who . ' - created within the last ' . DatabaseScanner::RECENT_ADMIN_DAYS . ' days, the classic takeover artifact; verify who created it');
            } else {
                $scanner->report_public('INFO', 'DB_ADMIN_USER', $where, 'administrator ' . $who . ' - confirm this account is known');
            }
            return (!$ctx->out_of_time());
        }, $after);
    }

    private function scan_options($after, array &$state)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        $prefix = $db->prefix();
        $options_table = $db->table('options');
        $root = $this->ctx->root();
        $signatures = Signatures::db_options();
        $scanner = $this;

        // SUBSTRING caps each value read.
        $query = array(
            'columns' => 'option_id, option_name, SUBSTRING(option_value, 1, ' . self::VALUE_SCAN_CAP . ')',
            'from'    => $options_table,
            'where'   => '',
            'pk'      => 'option_id',
        );
        return $this->iterate('options', 'options', $query, function ($row) use (&$counts, $ctx, $prefix, $options_table, $root, $signatures, $scanner) {
            $counts['OPTIONS']++;
            $option_name = $row[1];
            $value = (string) $row[2];
            $where = 'db:' . $options_table . ':' . $option_name;

            ///////////////
            // siteurl/home hijacks redirect every visitor; report the values
            // as inventory even when they look sane.
            //////////////
            if ('siteurl' === $option_name || 'home' === $option_name) {
                if (preg_match('@^https?://[^\s<>\'"]+$@', $value) === 1) {
                    $scanner->report_public('INFO', 'DB_SITE_URL', $where, $option_name . ' = ' . $value . ' - confirm this is the real site address');
                } else {
                    $scanner->report_public('HIGH', 'DB_SITE_URL', $where, $option_name . ' does not look like a plain URL (hijack or injection): ' . substr($value, 0, 200));
                    $counts['FLAGGED_OPTIONS']++;
                }
                return (!$ctx->out_of_time());
            }

            ///////////////
            // active_plugins is serialized PHP; extract the .php entries with a
            // regex (NEVER unserialize hostile data) and sanity-check each.
            //////////////
            if ('active_plugins' === $option_name) {
                if (preg_match_all('@"((?:[^"\\\\]|\\\\.)*?\.php)"@', $value, $matches)) {
                    foreach ($matches[1] as $plugin_entry) {
                        if (false !== strpos($plugin_entry, '..')) {
                            $scanner->report_public('HIGH', 'DB_ACTIVE_PLUGIN', $where, 'active plugin path escapes the plugins directory: ' . $plugin_entry);
                            $counts['FLAGGED_OPTIONS']++;
                        } elseif (!is_file($root . '/wp-content/plugins/' . $plugin_entry)) {
                            $scanner->report_public('LOW', 'DB_ACTIVE_PLUGIN', $where, 'active plugin file missing on disk: ' . $plugin_entry);
                        }
                    }
                }
                return (!$ctx->out_of_time());
            }

            // Role definitions: a non-admin role quietly granted admin powers.
            if ($prefix . 'user_roles' === $option_name) {
                $scanner->check_user_roles($value, $where, $counts);
                return (!$ctx->out_of_time());
            }

            foreach ($signatures as $signature) {
                if (preg_match($signature['pattern'], $value, $hit, PREG_OFFSET_CAPTURE) !== 1) {
                    continue;
                }
                // Excerpt around the match itself, not the start of the value.
                $excerpt_start = max(0, $hit[0][1] - 40);
                $scanner->report_public($signature['severity'], 'DB_OPTION_IOC', $where,
                    $signature['name'] . ': ' . $signature['description'],
                    array('e.g. ' . substr($value, $excerpt_start, 200)));
                $counts['FLAGGED_OPTIONS']++;
                break;
            }
            return (!$ctx->out_of_time());
        }, $after);
    }

    private function scan_posts($after, array &$state)
    {
        $db = $this->ctx->db;
        $ctx = $this->ctx;
        $counts = &$state['counts'];
        $suppressed = &$state['suppressed'];
        $posts_table = $db->table('posts');
        $signatures = Signatures::db_posts();
        $scanner = $this;

        ///////////////
        // The posts table can be huge: a LIKE prefilter runs server-side and
        // only candidates come back (value capped) for the real pattern check.
        // Revisions and autosaves (post_type revision) would repeat every
        // injected post once per saved version: one finding per live post.
        //////////////
        $query = array(
            'columns' => 'ID, post_title, post_type, SUBSTRING(post_content, 1, ' . self::VALUE_SCAN_CAP . ')',
            'from'    => $posts_table,
            'where'   => "post_type <> 'revision'"
                . " AND (post_content LIKE '%<?php%' OR post_content LIKE '%eval(%'"
                . " OR post_content LIKE '%fromCharCode%' OR post_content LIKE '%atob(%'"
                . " OR post_content LIKE '%unescape(%' OR post_content LIKE '%<iframe%')",
            'pk'      => 'ID',
        );
        $next = $this->iterate('posts', 'posts', $query, function ($row) use (&$counts, &$suppressed, $ctx, $posts_table, $signatures, $scanner) {
            $content = (string) $row[3];
            foreach ($signatures as $signature) {
                if (preg_match($signature['pattern'], $content) !== 1) {
                    continue;
                }
                $counts['FLAGGED_POSTS']++;
                if ($counts['FLAGGED_POSTS'] > DatabaseScanner::MAX_REPORTED_POSTS) {
                    $suppressed++;
                } else {
                    $scanner->report_public($signature['severity'], 'DB_POST_IOC', 'db:' . $posts_table . ':ID=' . $row[0],
                        $signature['name'] . ' in ' . $row[2] . ' "' . $row[1] . '": ' . $signature['description']);
                }
                break;
            }
            return (!$ctx->out_of_time());
        }, $after);

        if (null === $next && $suppressed > 0) {
            $this->progress('...and ' . $suppressed . " more flagged posts not listed\n");
        }
        return ($next);
    }

    public function check_user_roles($value, $where, array &$counts)
    {
        ///////////////
        // {prefix}user_roles is serialized role => array(name, capabilities =>
        // array(cap => bool)). Parsed with a regex, never unserialize()d: each
        // capabilities array holds no nested arrays, so the lazy match stops at
        // the first "}}" (capabilities close + role close).
        //////////////
        if (!preg_match_all('/s:\d+:"([^"]*)";a:\d+:\{s:4:"name";s:\d+:"[^"]*";s:12:"capabilities";a:\d+:\{(.*?)\}\}/s', $value, $roles, PREG_SET_ORDER)) {
            return;
        }
        foreach ($roles as $role) {
            if ('administrator' === $role[1]) {
                continue;
            }
            if (preg_match_all('/"(' . self::ADMIN_CAPS . ')";b:1;/', $role[2], $caps)) {
                $this->report('MEDIUM', 'DB_ROLE_CAPS', $where,
                    'role "' . $role[1] . '" holds administrator-level capabilities: ' . implode(', ', array_unique($caps[1]))
                    . ' - role-editor plugins and shop-manager roles do this legitimately; verify it was intentional and check who holds the role');
                $counts['FLAGGED_OPTIONS']++;
            }
        }
    }

    // Closures in PHP 5.x cannot call a protected method of the enclosing
    // object; this is the same as report() for use from the row callbacks.
    public function report_public($severity, $type, $path, $detail, $context = array())
    {
        $this->report($severity, $type, $path, $detail, $context);
    }
}
