<?php
namespace Elderward\Engine;

////////////////
// Quick checks: cheap, high-signal places attackers hide. PHP inside
// uploads, auto_prepend_file/auto_append_file directives, the mu-plugins
// inventory, and hidden dotfile PHP.
//
// Units: the files directly in the WordPress root, then each top-level
// directory (wp-content split into its own subdirectories, since uploads
// alone can be the bulk of a site).
//////////////

class QuickScanner extends Scanner
{
    public function name()
    {
        return ('quickscan');
    }

    public function init_state()
    {
        return array('counts' => array('UPLOADS_PHP' => 0, 'PHP_PREPEND' => 0, 'MU_PLUGIN' => 0, 'HIDDEN_PHP' => 0));
    }

    public function plan(array &$state)
    {
        $root = require_wordpress_root($this->ctx->root());
        $units = array(array('files' => $root));
        foreach (self::subdirs($root) as $dir) {
            if ('wp-content' === basename($dir)) {
                $units[] = array('files' => $dir);
                foreach (self::subdirs($dir) as $sub) {
                    $units[] = array('dir' => $sub);
                }
                continue;
            }
            $units[] = array('dir' => $dir);
        }
        return ($units);
    }

    private static function subdirs($dir)
    {
        $dirs = array();
        foreach ((array) @scandir($dir) as $entry) {
            if ('.' === $entry || '..' === $entry) {
                continue;
            }
            if (is_dir($dir . '/' . $entry) && !is_link($dir . '/' . $entry)) {
                $dirs[] = $dir . '/' . $entry;
            }
        }
        return ($dirs);
    }

    public function run(array $unit, array &$state)
    {
        $root = $this->ctx->root();
        $counts = &$state['counts'];
        if (isset($unit['files'])) {
            // Only the files directly inside this directory.
            foreach ((array) @scandir($unit['files']) as $entry) {
                $path = $unit['files'] . '/' . $entry;
                if ('.' === $entry || '..' === $entry || !is_file($path)) {
                    continue;
                }
                $this->check_file($root, $path, $entry, $counts);
            }
            return (null);
        }

        foreach (recursive_file_iterator($unit['dir']) as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $this->check_file($root, $file->getPathname(), $file->getFilename(), $counts);
        }
        return (null);
    }

    public function finish(array &$state)
    {
        $counts = $state['counts'];
        $this->summary('quickscan', $counts,
            'Quick scan complete: ' . $counts['UPLOADS_PHP'] . ' php-in-uploads, ' . $counts['PHP_PREPEND']
            . ' prepend/append directives, ' . $counts['MU_PLUGIN'] . ' mu-plugins, ' . $counts['HIDDEN_PHP'] . " hidden php files\n");
    }

    private function check_file($root, $path, $basename, array &$counts)
    {
        // Uploads hold media, never code: PHP there is the classic dropped
        // webshell (plugins do scatter "Silence is golden" index.php files).
        if (false !== strpos($path, '/wp-content/uploads/') && is_php_file($basename) && 'index.php' !== $basename) {
            $this->report('HIGH', 'UPLOADS_PHP', $path, 'executable PHP inside wp-content/uploads - usually a webshell dropped through an upload form');
            $counts['UPLOADS_PHP']++;
            return;
        }

        if (in_array($basename, array('.user.ini', 'php.ini', '.htaccess'), true)) {
            $this->check_prepend_directives($root, $path, $counts);
            return;
        }

        // mu-plugins load on every request with no activation step: a
        // favorite persistence spot. Inventory, not accusation.
        if (false !== strpos($path, '/wp-content/mu-plugins/') && is_php_file($basename)) {
            $this->report('INFO', 'MU_PLUGIN', $path, 'must-use plugin: loads on every request with no activation step - confirm it is intentional');
            $counts['MU_PLUGIN']++;
            return;
        }

        if ('.' === $basename[0] && is_php_file($basename)) {
            $this->report('MEDIUM', 'HIDDEN_PHP', $path, 'hidden PHP file (dotfile) - rarely legitimate');
            $counts['HIDDEN_PHP']++;
        }
    }

    private function check_prepend_directives($root, $config_path, array &$counts)
    {
        ///////////////
        // auto_prepend_file / auto_append_file make PHP execute a file on EVERY
        // request - the mechanism behind both Wordfence's WAF and a whole class
        // of persistent backdoors.
        //////////////
        $content = @file_get_contents($config_path, false, null, 0, 65536);
        if (false === $content) {
            return;
        }
        // Leading [^;#] skips ini/htaccess comment lines.
        if (!preg_match_all('/^[^;#\r\n]*auto_(?:prepend|append)_file[^\r\n]*/mi', $content, $matches)) {
            return;
        }

        foreach ($matches[0] as $directive_line) {
            $directive_line = trim($directive_line);
            $target = '';
            if (preg_match('/auto_(?:prepend|append)_file(?:\s*=|\s)\s*["\']?([^"\'\s]+)/i', $directive_line, $target_match)) {
                $target = $target_match[1];
            }
            if ('' === $target || 'none' === strtolower($target)) {
                continue;
            }

            if ('wordfence-waf.php' === basename($target) && is_dir($root . '/wp-content/plugins/wordfence')) {
                $this->report('INFO', 'PHP_PREPEND', $config_path, 'Wordfence WAF bootstrap prepend: ' . $directive_line . ' - verify the target only loads wordfence/waf/bootstrap.php');
            } else {
                $this->report('MEDIUM', 'PHP_PREPEND', $config_path, $target . ' is executed on EVERY php request via: ' . $directive_line . ' - verify this file');
            }
            $counts['PHP_PREPEND']++;
        }
    }
}
