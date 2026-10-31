<?php
namespace Elderward\Engine;

////////////////
// Integrity checking against wordpress.org reference packages.
//
// Core and plugins are verified against the official checksum APIs;
// themes have no checksum API, so their manifest is built by hashing the
// official theme zip. With checksumdir= everything is read from
// pre-downloaded files instead of the network. restore=1 rewrites
// MODIFIED/MISSING files from the official zip, byte-verified against the
// manifest before any write; EXTRA files are never touched.
//
// Units: core, one per plugin directory, one per theme directory, then the
// single-file plugins; totals accumulate in $state.
//////////////

class IntegrityScanner extends Scanner
{
    public function name()
    {
        return ('integrity');
    }

    public function init_state()
    {
        return array('totals' => array('MODIFIED' => 0, 'MISSING' => 0, 'EXTRA' => 0, 'NO_REFERENCE' => 0, 'UNREADABLE' => 0));
    }

    public function plan(array &$state)
    {
        $root = require_wordpress_root($this->ctx->root());

        if ($this->ctx->has('quarantinedir')) {
            $quarantine_real = @realpath($this->ctx->get('quarantinedir'));
            $root_real = @realpath($root);
            if (false !== $quarantine_real && false !== $root_real && 0 === strpos($quarantine_real . '/', $root_real . '/')) {
                $this->progress("Warning: quarantinedir is inside the scanned tree - move it outside the webroot so quarantined files cannot be served.\n");
            }
        }

        $units = array(array('core' => 1));
        foreach ((array) @glob($root . '/wp-content/plugins/*', GLOB_ONLYDIR) as $plugin_dir) {
            $units[] = array('plugin' => $plugin_dir);
        }
        $theme_dirs = (array) @glob($root . '/wp-content/themes/*', GLOB_ONLYDIR);
        if (count($theme_dirs) > 0 && !class_exists('ZipArchive')) {
            $units[] = array('themes_unavailable' => 1);
        } else {
            foreach ($theme_dirs as $theme_dir) {
                $units[] = array('theme' => $theme_dir);
            }
        }
        $units[] = array('loose' => 1);
        return ($units);
    }

    public function run(array $unit, array &$state)
    {
        $root = $this->ctx->root();
        $totals = &$state['totals'];
        if (isset($unit['core'])) {
            $this->check_core($root, $totals);
        } elseif (isset($unit['plugin'])) {
            $this->check_plugin($unit['plugin'], $totals);
        } elseif (isset($unit['themes_unavailable'])) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $root . '/wp-content/themes', 'themes: PHP zip extension not available, cannot verify themes');
            $totals['NO_REFERENCE']++;
        } elseif (isset($unit['theme'])) {
            $this->check_theme($unit['theme'], $totals);
        } elseif (isset($unit['loose'])) {
            // Single-file plugins (e.g. hello.php) sit directly in the plugins dir
            // and carry no per-directory manifest.
            foreach ((array) @glob($root . '/wp-content/plugins/*.php') as $loose_plugin) {
                if ('index.php' === basename($loose_plugin)) {
                    continue;
                }
                $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $loose_plugin, 'single-file plugin: no checksum manifest to verify against');
                $totals['NO_REFERENCE']++;
            }
        }
        return (null);
    }

    public function finish(array &$state)
    {
        $totals = $state['totals'];
        $this->summary('integrity', $totals,
            'Integrity scan complete: ' . $totals['MODIFIED'] . ' modified, ' . $totals['MISSING'] . ' missing, '
            . $totals['EXTRA'] . ' extra, ' . $totals['UNREADABLE'] . ' unreadable, '
            . $totals['NO_REFERENCE'] . " without reference checksums\n");
    }

    private function check_core($root, array &$totals)
    {
        ///////////////
        // Core: checksums come per version+locale. Bundled themes/plugins under
        // wp-content are legitimately deleted all the time, so core manifest
        // entries there are skipped (plugins are verified separately).
        // Extra-file detection covers wp-admin and wp-includes entirely, plus
        // root-level PHP files (a classic dropper spot) except wp-config.php.
        //////////////
        $version_file = $root . '/wp-includes/version.php';
        $wp_version = null;
        if (preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', (string) @file_get_contents($version_file), $matches)) {
            $wp_version = $matches[1];
        }
        if (null === $wp_version) {
            $this->report('ERROR', 'INTEGRITY_NO_REFERENCE', $version_file, 'could not read the core version');
            $totals['NO_REFERENCE']++;
            return;
        }

        $locale = $this->ctx->get('locale', 'en_US');
        list($status, $data) = $this->fetch_reference_checksums(
            'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($wp_version) . '&locale=' . rawurlencode($locale),
            'core-' . $wp_version . '.json'
        );
        if ('ok' !== $status || empty($data['checksums']) || !is_array($data['checksums'])) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $root, 'core ' . $wp_version . ' (' . $locale . '): no reference checksums available (' . $status . ')');
            $totals['NO_REFERENCE']++;
            return;
        }

        $this->progress('Checking core ' . $wp_version . ' (' . count($data['checksums']) . " files)\n");
        $manifest = array();
        foreach ($data['checksums'] as $relative_path => $expected) {
            if (0 === strpos($relative_path, 'wp-content/')) {
                continue;
            }
            $manifest[$relative_path] = $expected;
        }

        $present = array();
        foreach (array('wp-admin', 'wp-includes') as $core_dir) {
            if (is_dir($root . '/' . $core_dir)) {
                $present = array_merge($present, list_files_recursive($root . '/' . $core_dir, $root));
            }
        }
        foreach ((array) @glob($root . '/*.php') as $root_file) {
            if ('wp-config.php' !== basename($root_file)) {
                $present[] = basename($root_file);
            }
        }
        $restorable = $this->verify_against_manifest($root, $manifest, 'core ' . $wp_version, $present, $totals);
        if ($this->ctx->has('restore') && count($restorable) > 0) {
            if ('en_US' !== $locale) {
                $this->progress("Restore of non-en_US core packages is not supported yet; skipping core restore.\n");
            } else {
                $this->restore_package_files($root,
                    'https://wordpress.org/wordpress-' . rawurlencode($wp_version) . '.zip',
                    'core-' . $wp_version . '.zip',
                    'wordpress/', $restorable, 'core ' . $wp_version);
            }
        }
    }

    private function check_plugin($plugin_dir, array &$totals)
    {
        ///////////////
        // Plugins: one manifest per slug+version. A 404 means the plugin or the
        // version is not in the wordpress.org archive (custom/premium plugin):
        // reported as NO_REFERENCE so "clean" never silently means "unchecked".
        //////////////
        $slug = basename($plugin_dir);
        $version = self::read_plugin_version($plugin_dir);
        if (null === $version) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ': could not determine the installed version');
            $totals['NO_REFERENCE']++;
            return;
        }

        list($status, $data) = $this->fetch_reference_checksums(
            'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json',
            'plugin-' . $slug . '-' . $version . '.json'
        );
        if ('notfound' === $status) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ' ' . $version . ': not in the wordpress.org checksum archive (custom/premium plugin, or version not archived)');
            $totals['NO_REFERENCE']++;
            return;
        }
        if ('ok' !== $status || empty($data['files']) || !is_array($data['files'])) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $plugin_dir, 'plugin ' . $slug . ' ' . $version . ': could not fetch reference checksums');
            $totals['NO_REFERENCE']++;
            return;
        }

        $this->progress('Checking plugin ' . $slug . ' ' . $version . ' (' . count($data['files']) . " files)\n");
        $manifest = array();
        foreach ($data['files'] as $relative_path => $sums) {
            $manifest[$relative_path] = isset($sums['md5']) ? $sums['md5'] : null;
        }
        $restorable = $this->verify_against_manifest($plugin_dir, $manifest, 'plugin ' . $slug . ' ' . $version, list_files_recursive($plugin_dir, $plugin_dir), $totals);
        if ($this->ctx->has('restore') && count($restorable) > 0) {
            $this->restore_package_files($plugin_dir,
                'https://downloads.wordpress.org/plugin/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip',
                'plugin-' . $slug . '-' . $version . '.zip',
                $slug . '/', $restorable, 'plugin ' . $slug . ' ' . $version);
        }
    }

    private function check_theme($theme_dir, array &$totals)
    {
        ///////////////
        // Themes: wordpress.org publishes no theme checksums, so the reference
        // manifest is built by hashing the official package zip's contents.
        // Custom, premium, and child themes 404 there: NO_REFERENCE.
        //////////////
        $slug = basename($theme_dir);
        $version = self::read_theme_version($theme_dir);
        if (null === $version) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ': could not determine the installed version');
            $totals['NO_REFERENCE']++;
            return;
        }

        list($zip_path, $is_temp, $status) = $this->acquire_package_zip(
            'https://downloads.wordpress.org/theme/' . rawurlencode($slug) . '.' . rawurlencode($version) . '.zip',
            'theme-' . $slug . '-' . $version . '.zip'
        );
        if ('notfound' === $status) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': not in the wordpress.org theme directory (custom/premium/child theme, or version not archived)');
            $totals['NO_REFERENCE']++;
            return;
        }
        if ('ok' !== $status) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': could not fetch the official theme package');
            $totals['NO_REFERENCE']++;
            return;
        }

        $manifest = self::manifest_from_zip($zip_path, $slug . '/');
        if (null === $manifest || 0 === count($manifest)) {
            $this->report('INFO', 'INTEGRITY_NO_REFERENCE', $theme_dir, 'theme ' . $slug . ' ' . $version . ': could not read the official theme package');
            $totals['NO_REFERENCE']++;
        } else {
            $this->progress('Checking theme ' . $slug . ' ' . $version . ' (' . count($manifest) . " files)\n");
            $restorable = $this->verify_against_manifest($theme_dir, $manifest, 'theme ' . $slug . ' ' . $version, list_files_recursive($theme_dir, $theme_dir), $totals);
            if ($this->ctx->has('restore') && count($restorable) > 0) {
                $this->restore_items_from_zip($zip_path, $slug . '/', $theme_dir, $restorable, 'theme ' . $slug . ' ' . $version);
            }
        }
        if ($is_temp) {
            @unlink($zip_path);
        }
    }

    private function fetch_reference_checksums($url, $offline_name)
    {
        ///////////////
        // checksumdir=/path switches to pre-downloaded manifests for hosts with
        // no outbound network: {checksumdir}/{offline_name} holds the same JSON
        // the wordpress.org API would have returned.
        //////////////
        if ($this->ctx->has('checksumdir')) {
            $offline_path = rtrim($this->ctx->get('checksumdir'), '/') . '/' . $offline_name;
            if (!is_file($offline_path)) {
                return array('notfound', null);
            }
            $body = @file_get_contents($offline_path);
            if (false === $body) {
                return array('error', null);
            }
        } else {
            if (null === $this->ctx->http) {
                return array('error', null);
            }
            list($status, $body) = $this->ctx->http->get($url);
            if (404 === $status) {
                return array('notfound', null);
            }
            if (200 !== $status || '' === $body) {
                return array('error', null);
            }
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return array('error', null);
        }
        return array('ok', $decoded);
    }

    private function acquire_package_zip($zip_url, $offline_zip_name)
    {
        ///////////////
        // Returns array($zip_path_or_null, $is_temp, $status) with $status one
        // of 'ok', 'notfound', 'error'. With checksumdir= the zip is read from
        // there instead of the network, mirroring the manifest naming.
        //////////////
        if ($this->ctx->has('checksumdir')) {
            $zip_path = rtrim($this->ctx->get('checksumdir'), '/') . '/' . $offline_zip_name;
            if (is_file($zip_path)) {
                return array($zip_path, false, 'ok');
            }
            return array(null, false, 'notfound');
        }
        if (null === $this->ctx->http) {
            return array(null, false, 'error');
        }

        $zip_path = @tempnam($this->ctx->work_dir, 'elderward-zip');
        if (false === $zip_path) {
            return array(null, false, 'error');
        }
        $status = $this->ctx->http->download($zip_url, $zip_path);
        if (200 !== $status) {
            @unlink($zip_path);
            return array(null, false, (404 === $status) ? 'notfound' : 'error');
        }
        return array($zip_path, true, 'ok');
    }

    public static function manifest_from_zip($zip_path, $zip_prefix)
    {
        if (!class_exists('ZipArchive')) {
            return (null);
        }
        $zip = new \ZipArchive();
        if (true !== $zip->open($zip_path)) {
            return (null);
        }

        $manifest = array();
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $entry_name = $zip->getNameIndex($i);
            if (0 !== strpos($entry_name, $zip_prefix) || '/' === substr($entry_name, -1)) {
                continue;
            }
            $content = $zip->getFromIndex($i);
            if (false === $content) {
                continue;
            }
            $manifest[substr($entry_name, strlen($zip_prefix))] = md5($content);
        }
        $zip->close();
        return ($manifest);
    }

    public static function md5_in_list($actual_md5, $expected)
    {
        // The plugin checksum API returns a string, or an array of valid
        // checksums when a release was ever repackaged.
        foreach ((array) $expected as $candidate) {
            if (null !== $candidate && hash_equals(strtolower((string) $candidate), $actual_md5)) {
                return (true);
            }
        }
        return (false);
    }

    private function verify_against_manifest($base_dir, $manifest, $label, $present_files, array &$totals)
    {
        ///////////////
        // $manifest maps package-relative paths to expected md5(s). Report
        // mismatches (MODIFIED), files gone from disk (MISSING), and files on
        // disk that the official package does not contain (EXTRA). Extra or
        // modified PHP is the classic dropped/backdoored webshell: HIGH.
        //////////////
        $known_benign_list = Signatures::known_benign();
        $restorable = array();
        foreach ($manifest as $relative_path => $expected) {
            $full_path = $base_dir . '/' . $relative_path;
            if (!is_file($full_path)) {
                $this->report('LOW', 'INTEGRITY_MISSING', $full_path, $label . ': file from the official package is missing');
                $totals['MISSING']++;
                $restorable[] = array('rel' => $relative_path, 'expected' => $expected);
                continue;
            }

            // A file we cannot read is UNVERIFIED, not modified: saying
            // "checksum does not match" would be false, and restoring would
            // overwrite content the tool never saw.
            $actual_md5 = @md5_file($full_path);
            if (false === $actual_md5) {
                $this->report('ERROR', 'INTEGRITY_UNREADABLE', $full_path, $label . ': cannot read the file to verify its checksum');
                $totals['UNREADABLE']++;
                continue;
            }

            if (null === $expected || !self::md5_in_list($actual_md5, $expected)) {
                $severity = is_php_file($relative_path) ? 'HIGH' : 'MEDIUM';
                $this->report($severity, 'INTEGRITY_MODIFIED', $full_path, $label . ': checksum does not match the official package');
                $totals['MODIFIED']++;
                $restorable[] = array('rel' => $relative_path, 'expected' => $expected);
            }
        }

        foreach ($present_files as $relative_path) {
            if (!isset($manifest[$relative_path])) {
                $basename = basename($relative_path);
                $known_benign = isset($known_benign_list[$basename]);
                // wordfence-waf.php is only expected where Wordfence is installed;
                // anywhere else the name is camouflage.
                if ($known_benign && 'wordfence-waf.php' === $basename && !is_dir($base_dir . '/wp-content/plugins/wordfence')) {
                    $known_benign = false;
                }

                if ($known_benign) {
                    $this->report('INFO', 'INTEGRITY_EXTRA', $base_dir . '/' . $relative_path, $label . ': ' . $known_benign_list[$basename]);
                } else {
                    $detail = $label . ': file is not part of the official package';
                    // Hex-named PHP at the docroot is used both by dropped
                    // webshells and by migration/backup tooling: say so.
                    if (preg_match('/^[0-9a-f]{32,64}\.php$/i', $basename)) {
                        $detail .= ' (hex-named PHP is dropped by webshells AND by migration/backup tools such as BlogVault/MalCare or Duplicator - inspect the contents)';
                    }
                    $severity = is_php_file($relative_path) ? 'HIGH' : 'LOW';
                    $this->report($severity, 'INTEGRITY_EXTRA', $base_dir . '/' . $relative_path, $detail);
                }
                $totals['EXTRA']++;
            }
        }

        // MODIFIED and MISSING files can be restored from the official package
        // zip; EXTRA files are never touched - deleting unknown files is the
        // operator's call, not this tool's.
        return ($restorable);
    }

    private function quarantine_original($target, $relative_path, $label)
    {
        ///////////////
        // Overwriting a backdoored file destroys the evidence an IR needs.
        // With quarantinedir= set, the original is copied there first, with a
        // .quarantine suffix so nothing serves or executes it.
        //////////////
        $quarantine_root = rtrim($this->ctx->get('quarantinedir'), '/') . '/' . str_replace(' ', '-', $label);
        $dest = $quarantine_root . '/' . $relative_path . '.quarantine';
        $dest_dir = dirname($dest);
        if (!is_dir($dest_dir) && !@mkdir($dest_dir, 0700, true)) {
            return (false);
        }
        return (@copy($target, $dest));
    }

    private function restore_package_files($base_dir, $zip_url, $offline_zip_name, $zip_prefix, $items, $label)
    {
        if (!class_exists('ZipArchive')) {
            $this->report('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': PHP zip extension not available, cannot restore');
            return;
        }

        list($zip_path, $is_temp, $status) = $this->acquire_package_zip($zip_url, $offline_zip_name);
        if ('ok' !== $status) {
            $this->report('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': could not obtain the official package (' . $status . ')');
            return;
        }

        $this->restore_items_from_zip($zip_path, $zip_prefix, $base_dir, $items, $label);

        if ($is_temp) {
            @unlink($zip_path);
        }
    }

    private function restore_items_from_zip($zip_path, $zip_prefix, $base_dir, $items, $label)
    {
        $zip = new \ZipArchive();
        if (true !== $zip->open($zip_path)) {
            $this->report('ERROR', 'RESTORE_FAILED', $base_dir, $label . ': could not open the package zip');
            return;
        }

        foreach ($items as $item) {
            $target = $base_dir . '/' . $item['rel'];

            $content = $zip->getFromName($zip_prefix . $item['rel']);
            if (false === $content) {
                $this->report('ERROR', 'RESTORE_FAILED', $target, $label . ': file not found inside the package zip');
                continue;
            }

            ///////////////
            // Only byte-verified content is ever written: the packaged file must
            // match the reference manifest, so a tampered zip (or a manifest/zip
            // version mix-up) can never plant content.
            //////////////
            if (!self::md5_in_list(md5($content), $item['expected'])) {
                $this->report('ERROR', 'RESTORE_FAILED', $target, $label . ': packaged file does not match the reference checksum, refusing to restore');
                continue;
            }

            if ($this->ctx->has('dryrun')) {
                $this->report('INFO', 'INTEGRITY_RESTORABLE', $target, $label . ' (dry run: not restored)');
                continue;
            }

            if ($this->ctx->has('quarantinedir') && is_file($target) && !$this->quarantine_original($target, $item['rel'], $label)) {
                $this->report('ERROR', 'RESTORE_FAILED', $target, $label . ': could not quarantine the original, refusing to overwrite it');
                continue;
            }

            $target_dir = dirname($target);
            if (!is_dir($target_dir) && !@mkdir($target_dir, 0755, true)) {
                $this->report('ERROR', 'RESTORE_FAILED', $target, $label . ': could not create the target directory');
                continue;
            }
            if (!write_cleaned_file($target, $content)) {
                $this->report('ERROR', 'RESTORE_FAILED', $target, $label . ': could not write the restored file');
                continue;
            }
            $this->report('INFO', 'INTEGRITY_RESTORED', $target, $label . ': pristine copy restored from the official package');
        }

        $zip->close();
    }

    public static function read_theme_version($theme_dir)
    {
        $header = @file_get_contents($theme_dir . '/style.css', false, null, 0, 8192);
        if (false === $header || false === stripos($header, 'Theme Name:')) {
            return (null);
        }
        if (preg_match('/^[ \t\/*#@]*Version:\s*(\S+)/mi', $header, $matches)) {
            return trim($matches[1]);
        }
        return (null);
    }

    public static function read_plugin_version($plugin_dir)
    {
        // The main plugin file is whichever top-level PHP file carries the
        // "Plugin Name:" header; its "Version:" header is the installed version.
        foreach ((array) @glob($plugin_dir . '/*.php') as $candidate) {
            $header = @file_get_contents($candidate, false, null, 0, 8192);
            if (false === $header || false === stripos($header, 'Plugin Name:')) {
                continue;
            }
            if (preg_match('/^[ \t\/*#@]*Version:\s*(\S+)/mi', $header, $matches)) {
                return trim($matches[1]);
            }
        }
        return (null);
    }
}
