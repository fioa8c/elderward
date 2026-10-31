<?php
namespace Elderward\Engine;

////////////////
// Engine context: everything a scanner used to pull from $_GET and globals.
//
// A Context carries the scan options (the same key=value pairs the CLI
// accepts), the Reporter that receives findings/progress/summaries, the
// HTTP and database adapters, and an optional deadline that lets a
// scanner stop between work units when it runs inside a web request.
//
// The engine never reads $_GET, never echoes, and never exits: a usage or
// fatal error is thrown as Fatal and the entry layer (CLI, WP-CLI, admin
// page) decides how to present it.
//////////////

class Fatal extends \Exception
{
}

class Context
{
    public $options;
    public $reporter;
    public $http;
    public $db;
    // The plugin's own directory: never scanned, because the signature
    // strings inside the source would match themselves.
    public $plugin_dir;
    // Directory for work files (file lists, downloaded packages).
    public $work_dir;
    // microtime(true) after which scanners should yield between units;
    // null means run to completion (CLI).
    public $deadline = null;

    // $http and $db are untyped so a null default stays valid on PHP 5.6 and
    // PHP 8.4 alike (implicit nullable types are deprecated there).
    public function __construct(array $options, Reporter $reporter, $http = null, $db = null, $plugin_dir = null, $work_dir = null)
    {
        $this->options = $options;
        $this->reporter = $reporter;
        $this->http = $http;
        $this->db = $db;
        $this->plugin_dir = (null === $plugin_dir) ? null : rtrim(str_replace('\\', '/', (string) realpath($plugin_dir)), '/');
        $this->work_dir = (null === $work_dir) ? sys_get_temp_dir() : rtrim($work_dir, '/');
    }

    public function has($key)
    {
        return (isset($this->options[$key]));
    }

    public function get($key, $default = null)
    {
        return (isset($this->options[$key]) ? $this->options[$key] : $default);
    }

    // A copy with some options changed: scanall forces dryrun this way
    // instead of mutating shared state.
    public function with(array $overrides, array $remove = array())
    {
        $copy = clone $this;
        foreach ($overrides as $key => $value) {
            $copy->options[$key] = $value;
        }
        foreach ($remove as $key) {
            unset($copy->options[$key]);
        }
        return ($copy);
    }

    public function root()
    {
        return (rtrim((string) $this->get('scandirectory', '.'), '/'));
    }

    public function out_of_time()
    {
        return (null !== $this->deadline && microtime(true) >= $this->deadline);
    }

    public function correlation_window()
    {
        return ($this->has('window') ? max(60, (int) $this->get('window')) : 300);
    }
}
