<?php
namespace Elderward\Engine;

////////////////
// Unified finding format, shared by every scanner. Text mode (default):
//
//   SEVERITY,TYPE,path,detail
//
// The first three fields never contain commas; everything after the third
// comma is free-form detail. Severities: HIGH, MEDIUM, LOW, INFO, ERROR.
// Indented lines under a finding are supporting context (log examples etc).
//
// Paths and details come from a compromised host, so the attacker chooses
// them: '%', control characters, and (in the path field) commas are
// percent-encoded so a crafted filename cannot shift fields or inject
// fake finding lines into the report.
//
// JSON mode prints NDJSON, one event object per line:
//   {"event":"finding","severity":...,"type":...,"path":...,"detail":...}
//   {"event":"summary","scan":...,...counts...}
//   {"event":"error","detail":...}
// Fields carry raw values (json_encode escapes them safely) and progress
// text moves to STDERR, so stdout is pure machine-readable events.
//
// The exit code reflects the worst finding: 0 clean (or INFO only),
// 1 usage/fatal error, 2 LOW/MEDIUM/ERROR findings, 3 HIGH findings.
//////////////

interface Reporter
{
    public function finding($severity, $type, $path, $detail, $context = array());
    public function summary($scan, $data, $text);
    public function progress($text);
    public function fatal($message);
    public function exit_code();
}

abstract class BaseReporter implements Reporter
{
    protected $exit_code = 0;

    protected function track($severity)
    {
        if ('HIGH' === $severity) {
            $this->exit_code = max($this->exit_code, 3);
        } elseif ('INFO' !== $severity) {
            $this->exit_code = max($this->exit_code, 2);
        }
    }

    public function exit_code()
    {
        return ($this->exit_code);
    }

    public static function sanitize_field($text, $encode_commas)
    {
        $text = str_replace('%', '%25', (string) $text);
        if ($encode_commas) {
            $text = str_replace(',', '%2C', $text);
        }
        return preg_replace_callback('/[\x00-\x1F\x7F]/', function ($match) {
            return sprintf('%%%02X', ord($match[0]));
        }, $text);
    }

    public static function format_text_finding($finding)
    {
        $text = $finding['severity'] . ',' . $finding['type'] . ','
            . self::sanitize_field($finding['path'], true) . ','
            . self::sanitize_field($finding['detail'], false) . "\n";
        foreach ($finding['context'] as $context_line) {
            $text .= '    ' . self::sanitize_field($context_line, false) . "\n";
        }
        return ($text);
    }
}

class TextReporter extends BaseReporter
{
    // When scanall runs in text mode, findings buffer here and print
    // severity-sorted at the end; null means report immediately.
    private $buffer = null;

    public function buffer_findings($enable)
    {
        $this->buffer = $enable ? array() : null;
    }

    public function finding($severity, $type, $path, $detail, $context = array())
    {
        $this->track($severity);
        $finding = array('severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail, 'context' => $context);
        if (is_array($this->buffer)) {
            $this->buffer[] = $finding;
            return;
        }
        echo self::format_text_finding($finding);
    }

    public function summary($scan, $data, $text)
    {
        echo $text;
    }

    public function progress($text)
    {
        echo $text;
    }

    public function fatal($message)
    {
        echo 'Error: ' . $message . "\n";
    }

    public function flush_buffered()
    {
        ///////////////
        // Flush the buffered findings worst-first. ERROR sits right after
        // HIGH: something that blocked verification needs eyes too.
        //////////////
        if (!is_array($this->buffer)) {
            return;
        }
        $buffered = $this->buffer;
        $this->buffer = null;

        echo "\n== Findings by severity (" . count($buffered) . ") ==\n";
        foreach (array('HIGH', 'ERROR', 'MEDIUM', 'LOW', 'INFO') as $severity_group) {
            foreach ($buffered as $finding) {
                if ($finding['severity'] === $severity_group) {
                    echo self::format_text_finding($finding);
                }
            }
        }
    }
}

class JsonReporter extends BaseReporter
{
    public function finding($severity, $type, $path, $detail, $context = array())
    {
        $this->track($severity);
        $event = array('event' => 'finding', 'severity' => $severity, 'type' => $type, 'path' => $path, 'detail' => $detail);
        if (!empty($context)) {
            $event['context'] = $context;
        }
        echo json_encode($event) . "\n";
    }

    public function summary($scan, $data, $text)
    {
        echo json_encode(array_merge(array('event' => 'summary', 'scan' => $scan), $data)) . "\n";
    }

    public function progress($text)
    {
        // Informational text must stay off stdout in JSON mode: STDERR on
        // the CLI, nowhere when there is no STDERR.
        if (defined('STDERR')) {
            fwrite(STDERR, $text);
        }
    }

    public function fatal($message)
    {
        echo json_encode(array('event' => 'error', 'detail' => $message)) . "\n";
        if (defined('STDERR')) {
            fwrite(STDERR, 'Error: ' . $message . "\n");
        }
    }
}
