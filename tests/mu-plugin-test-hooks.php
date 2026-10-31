<?php
/**
 * Test-only hooks for the Elderward admin job (TESTPLAN F6). Copy into
 * wp-content/mu-plugins/ on a test site, never on a real one.
 *
 *   wp option update elderward_test_budget 0.05   # force many pauses/resumes
 *   wp option update elderward_test_die 1         # next finding INSERT dies with a PHP fatal (one-shot)
 *   wp option update elderward_test_exit 1        # every finding INSERT exits silently, like a cut-off request
 *
 * @package Elderward
 */
add_filter('elderward_step_budget_seconds', function ($budget) {
    $forced = get_option('elderward_test_budget');
    return (false === $forced) ? $budget : (float) $forced;
});
// Simulate a step dying with a PHP fatal while it writes a finding. The
// option lookup inside a 'query' filter runs a query itself, hence the guard.
add_filter('query', function ($sql) {
    static $inside = false;
    if ($inside || 0 !== stripos(ltrim($sql), 'INSERT') || false === strpos($sql, 'elderward_findings')) {
        return $sql;
    }
    $inside = true;
    $die = get_option('elderward_test_die');
    if ($die) {
        delete_option('elderward_test_die');
    }
    $vanish = get_option('elderward_test_exit');
    $inside = false;
    if ($die) {
        trigger_error('elderward test fatal', E_USER_ERROR);
    }
    if ($vanish) {
        exit(0); // like a request the web server cut off: no error recorded
    }
    return $sql;
});
