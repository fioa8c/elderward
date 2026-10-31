<?php
namespace Elderward\Engine;

////////////////
// Timestamp anomaly heuristics (report-only)
//
// Timestamps are leads, not proof: attackers fake mtimes (touch -t) and
// legitimate migrations rewrite them wholesale. Nothing here ever feeds a
// cleanup action, and every check looks for outliers WITHIN one package
// (core, a plugin, a theme) - never comparisons against a site-wide date,
// which drown in false positives after any migration or update.
//////////////

class TimestampScanner extends Scanner
{
    // mtimes closer together than this belong to one install/update event.
    const CLUSTER_TOLERANCE = 7200;
    // Groups smaller than this carry no statistics and are skipped.
    const MIN_GROUP_FILES = 10;
    // mtime this far before ctime suggests a faked mtime: touch can back-date
    // the content time, but the inode change time cannot be set without root.
    const TIMESTOMP_MIN_GAP = 2592000;

    public function name()
    {
        return ('timestamps');
    }

    public function init_state()
    {
        return array('totals' => array('OUTLIER' => 0, 'TIMESTOMP' => 0));
    }

    public function plan(array &$state)
    {
        $root = require_wordpress_root($this->ctx->root());
        $units = array(array('core' => 1));
        foreach (array('plugins', 'themes') as $package_type) {
            foreach ((array) @glob($root . '/wp-content/' . $package_type . '/*', GLOB_ONLYDIR) as $package_dir) {
                $units[] = array('package' => $package_dir, 'label' => rtrim($package_type, 's') . ' ' . basename($package_dir));
            }
        }
        return ($units);
    }

    public function run(array $unit, array &$state)
    {
        $root = $this->ctx->root();
        if (isset($unit['core'])) {
            ///////////////
            // Core is one group: wp-admin, wp-includes, and root-level PHP files.
            // wp-config.php is excluded - editing it legitimately is routine and it
            // would flag on almost every site.
            //////////////
            $core_files = array();
            foreach (array('wp-admin', 'wp-includes') as $core_dir) {
                if (is_dir($root . '/' . $core_dir)) {
                    $core_files = array_merge($core_files, list_files_absolute($root . '/' . $core_dir));
                }
            }
            foreach ((array) @glob($root . '/*.php') as $root_file) {
                if ('wp-config.php' !== basename($root_file)) {
                    $core_files[] = $root_file;
                }
            }
            $this->analyze_group('core', $core_files, $state['totals']);
        } else {
            $this->analyze_group($unit['label'], list_files_absolute($unit['package']), $state['totals']);
        }
        return (null);
    }

    public function finish(array &$state)
    {
        $totals = $state['totals'];
        $this->summary('timestamps', $totals,
            'Timestamp scan complete: ' . $totals['OUTLIER'] . ' outliers, ' . $totals['TIMESTOMP']
            . " possible timestomps. Timestamps are leads, not proof - a clean result does not clear a file.\n");
    }

    public static function outlier_limit($group_size)
    {
        // An install or update touches most of a package at once. A handful of
        // files changing on their own is the anomaly worth reporting.
        return (int) max(2, ceil($group_size * 0.05));
    }

    private function analyze_group($group_label, $file_paths, array &$totals)
    {
        $entries = array();
        foreach ($file_paths as $path) {
            $stat = @stat($path);
            if (false === $stat) {
                continue;
            }
            $entries[] = array('path' => $path, 'mtime' => $stat['mtime'], 'ctime' => $stat['ctime']);
        }
        if (count($entries) < self::MIN_GROUP_FILES) {
            return;
        }

        ///////////////
        // Cluster the group's mtimes: sorted times closer than the tolerance
        // merge into one cluster. The dominant (largest) cluster is the last
        // legitimate install/update event for most of the package.
        //////////////
        usort($entries, function ($a, $b) {
            return $a['mtime'] - $b['mtime'];
        });

        $clusters = array();
        $current = array($entries[0]);
        $entry_count = count($entries);
        for ($i = 1; $i < $entry_count; $i++) {
            if (($entries[$i]['mtime'] - $entries[$i - 1]['mtime']) <= self::CLUSTER_TOLERANCE) {
                $current[] = $entries[$i];
            } else {
                $clusters[] = $current;
                $current = array($entries[$i]);
            }
        }
        $clusters[] = $current;

        $dominant_index = 0;
        foreach ($clusters as $i => $cluster) {
            if (count($cluster) > count($clusters[$dominant_index])) {
                $dominant_index = $i;
            }
        }
        $dominant = $clusters[$dominant_index];
        $dominant_time = $dominant[count($dominant) - 1]['mtime'];
        $outlier_limit = self::outlier_limit($entry_count);

        ///////////////
        // Files modified AFTER the dominant cluster, in numbers too small to be
        // an update, are the classic post-install edit (backdoored functions.php,
        // dropped loader). Older stragglers are not flagged here: preserved
        // mtimes from uploads/migrations are routine, and faked-old mtimes are
        // the timestomp check's job.
        //////////////
        foreach ($clusters as $i => $cluster) {
            if ($i <= $dominant_index || count($cluster) > $outlier_limit) {
                continue;
            }
            foreach ($cluster as $entry) {
                $severity = is_php_file($entry['path']) ? 'MEDIUM' : 'LOW';
                $this->report($severity, 'TIMESTAMP_OUTLIER', $entry['path'],
                    $group_label . ': modified ' . date('Y-m-d H:i', $entry['mtime'])
                    . ' but ' . count($dominant) . ' of ' . $entry_count . ' files cluster around ' . date('Y-m-d H:i', $dominant_time));
                $totals['OUTLIER']++;
            }
        }

        ///////////////
        // Timestomp: mtime far behind ctime. Migrations and rsync/cp -p make
        // that true for a whole tree at once, so it only means something when
        // few files in the group show it. PHP files only - a back-dated image
        // is not a lead worth the noise.
        //////////////
        $diverged = array();
        foreach ($entries as $entry) {
            if (($entry['ctime'] - $entry['mtime']) > self::TIMESTOMP_MIN_GAP) {
                $diverged[] = $entry;
            }
        }
        if (count($diverged) > 0 && count($diverged) <= $outlier_limit) {
            foreach ($diverged as $entry) {
                if (!is_php_file($entry['path'])) {
                    continue;
                }
                $this->report('MEDIUM', 'TIMESTAMP_TIMESTOMP', $entry['path'],
                    $group_label . ': content claims to be from ' . date('Y-m-d H:i', $entry['mtime'])
                    . ' but the inode changed ' . date('Y-m-d H:i', $entry['ctime']) . ' - the mtime may have been faked (touch -t)');
                $totals['TIMESTOMP']++;
            }
        }
    }
}
