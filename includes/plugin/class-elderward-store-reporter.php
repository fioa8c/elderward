<?php
/**
 * Engine Reporter that stores findings in the plugin's table and keeps
 * progress/summary text on the job, for scans run from the admin page.
 *
 * @package Elderward
 */

if (!defined('ABSPATH')) {
    exit;
}

class Elderward_Store_Reporter extends Elderward\Engine\BaseReporter
{
    private $job_id;
    private $counts;
    private $summaries = array();
    private $last_progress = '';

    public function __construct($job_id, array $counts)
    {
        $this->job_id = $job_id;
        $this->counts = $counts;
    }

    public function finding($severity, $type, $path, $detail, $context = array())
    {
        global $wpdb;
        $this->track($severity);
        if (!isset($this->counts[$severity])) {
            $this->counts[$severity] = 0;
        }
        $this->counts[$severity]++;

        // Findings are hostile data from the scanned host: stored raw here
        // (prepared statement) and escaped wherever they are rendered.
        $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- the plugin's own findings table.
            Elderward_Plugin::findings_table(),
            array(
                'job_id'   => $this->job_id,
                'severity' => substr((string) $severity, 0, 8),
                'type'     => substr((string) $type, 0, 40),
                'path'     => (string) $path,
                'detail'   => (string) $detail,
                'context'  => empty($context) ? null : wp_json_encode(array_values((array) $context)),
                'created'  => gmdate('Y-m-d H:i:s'),
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );
    }

    public function summary($scan, $data, $text)
    {
        $this->summaries[$scan] = $data;
    }

    public function progress($text)
    {
        $text = trim((string) $text);
        if ('' !== $text) {
            $this->last_progress = $text;
        }
    }

    public function fatal($message)
    {
        $this->last_progress = 'Error: ' . $message;
    }

    public function counts()
    {
        return $this->counts;
    }

    public function summaries()
    {
        return $this->summaries;
    }

    public function last_progress()
    {
        return $this->last_progress;
    }
}
