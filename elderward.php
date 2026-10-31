<?php
/**
 * Elderward
 *
 * @package           Elderward
 * @author            Fio Cavallari
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       Elderward
 * Plugin URI:        https://github.com/fioa8c/elderward
 * Description:       Malware scanner and incident-response toolkit: file signatures, core/plugin/theme integrity, database, crontab and access-log checks.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.2
 * Author:            Fio Cavallari
 * Author URI:        https://github.com/fioa8c
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

define('ELDERWARD_VERSION', '1.0.0');
define('ELDERWARD_FILE', __FILE__);
define('ELDERWARD_DIR', plugin_dir_path(__FILE__));
define('ELDERWARD_URL', plugin_dir_url(__FILE__));

require_once ELDERWARD_DIR . 'includes/engine/load.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-plugin.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-wp-http.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-wp-db.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-job.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-store-reporter.php';
require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-admin.php';

register_activation_hook(__FILE__, array('Elderward_Plugin', 'activate'));
add_action('plugins_loaded', array('Elderward_Plugin', 'init'));

if (defined('WP_CLI') && WP_CLI) {
    require_once ELDERWARD_DIR . 'includes/plugin/class-elderward-cli.php';
    WP_CLI::add_command('elderward', 'Elderward_CLI');
}
