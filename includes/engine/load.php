<?php
////////////////
// Loads the Elderward scanning engine (namespace Elderward\Engine). The
// engine has no WordPress dependency and only declares classes and
// functions: nothing runs until an entry point builds a Context.
//////////////

// Loaded by the plugin (ABSPATH defined) or the standalone CLI; never
// served directly over the web.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') {
    exit;
}

if (!defined('ELDERWARD_ENGINE_LOADED')) {
    define('ELDERWARD_ENGINE_LOADED', true);

    require_once __DIR__ . '/context.php';
    require_once __DIR__ . '/reporter.php';
    require_once __DIR__ . '/http.php';
    require_once __DIR__ . '/db.php';
    require_once __DIR__ . '/signatures.php';
    require_once __DIR__ . '/files.php';
    require_once __DIR__ . '/scanner.php';
    require_once __DIR__ . '/cleanup.php';
    require_once __DIR__ . '/crontab.php';
    require_once __DIR__ . '/logs.php';
    require_once __DIR__ . '/integrity.php';
    require_once __DIR__ . '/timestamps.php';
    require_once __DIR__ . '/quick.php';
    require_once __DIR__ . '/database.php';
    require_once __DIR__ . '/runner.php';
}
