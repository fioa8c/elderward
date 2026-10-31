<?php
namespace Elderward\Engine;

////////////////
// Database access for the read-only database scan.
//
// Everything is SELECT-only. Values read from the database are hostile
// data: the scanners pattern-match them and never unserialize() them.
//
// Two implementations: MysqliDb (standalone CLI: credentials parsed out of
// wp-config.php with regexes, rows streamed with MYSQLI_USE_RESULT) and,
// inside WordPress, the plugin's $wpdb-backed adapter, which pages by
// primary key. Both iterate in primary-key order so the output is the same.
//////////////

interface Db
{
    // Prepare the connection. Returns null on success or an error message.
    public function connect(Context $ctx);
    // Database name and table prefix, for progress text and finding paths.
    public function name();
    public function prefix();
    // Full table name for 'users', 'usermeta', 'options', 'posts'.
    public function table($short);
    // Where the credentials came from (the wp-config.php path), or null.
    public function config_path();
    ///////////////
    // Iterate SELECT {columns} FROM {from} [WHERE {where}] ORDER BY {pk},
    // resuming after primary key $after. The pk must be the first selected
    // column. $callback($row) receives a numeric row and returns false to
    // pause. Returns array('done' => bool, 'last' => int, 'error' =>
    // string|null, 'early' => bool) where 'early' means the result stream
    // died part-way through.
    //////////////
    public function each(array $query, $callback, $after = 0);
    public function close();
}

class MysqliDb implements Db
{
    private $db = null;
    private $config = null;

    public function connect(Context $ctx)
    {
        if (!function_exists('mysqli_connect')) {
            return ('PHP mysqli extension not available, cannot scan the database');
        }
        $root = $ctx->root();
        $this->config = self::parse_wp_config($root);
        if (null === $this->config) {
            return ('could not read DB credentials from wp-config.php (looked in ' . $root . ' and its parent)');
        }
        $this->db = self::open($this->config);
        if (null === $this->db) {
            return ('could not connect to the database as ' . $this->config['DB_USER'] . '@' . $this->config['DB_HOST']);
        }
        return (null);
    }

    public function name()
    {
        return (null === $this->config) ? '' : $this->config['DB_NAME'];
    }

    public function prefix()
    {
        return (null === $this->config) ? 'wp_' : $this->config['prefix'];
    }

    public function table($short)
    {
        return ($this->prefix() . $short);
    }

    public function config_path()
    {
        return (null === $this->config) ? null : $this->config['path'];
    }

    public function each(array $query, $callback, $after = 0)
    {
        $sql = 'SELECT ' . $query['columns'] . ' FROM ' . $query['from'];
        $conditions = array();
        if (isset($query['where']) && '' !== $query['where']) {
            $conditions[] = '(' . $query['where'] . ')';
        }
        if ($after > 0) {
            $conditions[] = $query['pk'] . ' > ' . (int) $after;
        }
        if (count($conditions) > 0) {
            $sql .= ' WHERE ' . implode(' AND ', $conditions);
        }
        $sql .= ' ORDER BY ' . $query['pk'];

        // MYSQLI_USE_RESULT streams rows instead of buffering the table.
        $result = @mysqli_query($this->db, $sql, MYSQLI_USE_RESULT);
        if (false === $result) {
            return array('done' => false, 'last' => (int) $after, 'error' => mysqli_error($this->db), 'early' => false);
        }

        $last = (int) $after;
        $done = true;
        while ($row = mysqli_fetch_row($result)) {
            $last = (int) $row[0];
            if (false === call_user_func($callback, $row)) {
                $done = false;
                break;
            }
        }
        mysqli_free_result($result);

        // mysqli_fetch_* returns null both at the end of a result and when
        // the connection drops; only errno tells them apart.
        if ($done && 0 !== mysqli_errno($this->db)) {
            return array('done' => false, 'last' => $last, 'error' => mysqli_error($this->db), 'early' => true);
        }
        return array('done' => $done, 'last' => $last, 'error' => null, 'early' => false);
    }

    public function close()
    {
        if (null !== $this->db) {
            mysqli_close($this->db);
            $this->db = null;
        }
    }

    public static function parse_wp_config($root)
    {
        ///////////////
        // The config is parsed with regexes, never include()d - it sits on a
        // compromised host and must not get to run code inside the scanner.
        // wp-config.php commonly lives one directory above the WP root too.
        //////////////
        $config_path = null;
        foreach (array($root . '/wp-config.php', dirname($root) . '/wp-config.php') as $candidate) {
            if (is_file($candidate)) {
                $config_path = $candidate;
                break;
            }
        }
        if (null === $config_path) {
            return (null);
        }

        // Hostile host: never slurp an unbounded file. A real config is a few KB.
        $content = @file_get_contents($config_path, false, null, 0, 65536);
        if (false === $content) {
            return (null);
        }
        // Drop comment lines first: a commented-out define() left behind by a
        // migration must not shadow the live one below it.
        $content = preg_replace('@^[ \t]*(?://|#|/?\*).*$@m', '', $content);

        $config = array('path' => $config_path, 'prefix' => 'wp_');
        foreach (array('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST') as $constant) {
            // The value is a single- or double-quoted PHP string literal; escaped
            // quotes inside it must not end the match.
            if (preg_match('/define\s*\(\s*[\'"]' . $constant . '[\'"]\s*,\s*(?:\'((?:[^\'\\\\]|\\\\.)*)\'|"((?:[^"\\\\]|\\\\.)*)")\s*\)/', $content, $matches)) {
                if (isset($matches[2])) {
                    $config[$constant] = self::decode_php_string_literal('"', $matches[2]);
                } else {
                    $config[$constant] = self::decode_php_string_literal("'", $matches[1]);
                }
            }
        }
        if (preg_match('/\$table_prefix\s*=\s*[\'"]([A-Za-z0-9_]+)[\'"]/', $content, $matches)) {
            $config['prefix'] = $matches[1];
        }

        if (!isset($config['DB_NAME'], $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_HOST'])) {
            return (null);
        }
        // The prefix goes into query strings: anything but [A-Za-z0-9_] is
        // either broken or an injection attempt from a tampered config.
        if (preg_match('/^[A-Za-z0-9_]+$/', $config['prefix']) !== 1) {
            return (null);
        }
        return ($config);
    }

    public static function decode_php_string_literal($quote, $raw)
    {
        // Single-quoted PHP strings only escape \\ and \'; double-quoted ones
        // take the C-style set. Variable interpolation cannot be resolved
        // without executing the file, so that (rare) config fails to connect.
        if ("'" === $quote) {
            return preg_replace('/\\\\([\'\\\\])/', '$1', $raw);
        }
        return stripcslashes(str_replace('\\$', '$', $raw));
    }

    public static function open($config)
    {
        // PHP 8.1+ throws mysqli exceptions by default; this engine handles
        // errors fail-closed on return values instead.
        mysqli_report(MYSQLI_REPORT_OFF);

        ///////////////
        // DB_HOST can be "host", "host:port", "host:/path/to/socket", or an
        // IPv6 literal "[::1]" / "[::1]:3306" - the same forms wpdb accepts.
        //////////////
        $host = $config['DB_HOST'];
        $port = null;
        $socket = null;
        $socket_pos = strpos($host, ':/');
        if (false !== $socket_pos) {
            $socket = substr($host, $socket_pos + 1);
            $host = substr($host, 0, $socket_pos);
        }
        if (substr_count($host, ':') > 1) {
            if (preg_match('/^\[?([0-9a-fA-F:]+)\]?(?::(\d+))?$/', $host, $matches)) {
                $host = $matches[1];
                if (isset($matches[2])) {
                    $port = (int) $matches[2];
                }
            }
        } elseif (false !== strpos($host, ':')) {
            list($host, $port) = explode(':', $host, 2);
            $port = (int) $port;
        }
        if (0 === $port) {
            $port = null;
        }

        $db = @mysqli_connect($host, $config['DB_USER'], $config['DB_PASSWORD'], $config['DB_NAME'], $port, $socket);
        if (false === $db || null === $db) {
            return (null);
        }
        @mysqli_set_charset($db, 'utf8mb4');
        return ($db);
    }
}
