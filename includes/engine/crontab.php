<?php
namespace Elderward\Engine;

////////////////
// Crontab persistence check: runs the fixed, read-only command
// "crontab -l" for the user PHP executes as and matches each entry
// against the crontab signatures.
//////////////

class CrontabScanner extends Scanner
{
    public function name()
    {
        return ('crontab');
    }

    public function plan(array &$state)
    {
        return array(array('crontab' => 1));
    }

    public function run(array $unit, array &$state)
    {
        ///////////////
        // A crontab that could not be read is an ERROR finding, never a silent
        // pass: shell_exec is disabled on much shared hosting (function_exists
        // still says yes for a disable_functions entry), and "no crontab" has
        // to be told apart from "crontab failed".
        //////////////
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
        if (!function_exists('shell_exec') || in_array('shell_exec', $disabled, true)) {
            $this->report('ERROR', 'CRONTAB_UNAVAILABLE', 'crontab', 'crontab NOT checked: shell_exec is not available in this PHP (run "crontab -l" by hand, or from the host\'s shell)');
            return (null);
        }

        // Fixed command, no user input: lists the current user's own crontab.
        $output = @shell_exec('crontab -l 2>&1; echo "__ELDERWARD_RC=$?"'); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_shell_exec -- read-only, fixed command; see readme.
        if (!is_string($output) || !preg_match('/__ELDERWARD_RC=(\d+)\s*$/', $output, $matches)) {
            $this->report('ERROR', 'CRONTAB_UNAVAILABLE', 'crontab', 'crontab NOT checked: shell_exec produced no output (disabled by the host?)');
            return (null);
        }
        $rc = (int) $matches[1];
        $output = (string) preg_replace('/__ELDERWARD_RC=\d+\s*$/', '', $output);

        if (0 !== $rc) {
            if (preg_match('/no crontab for/i', $output)) {
                $this->progress("No crontab for the current user.\n");
                return (null);
            }
            $this->report('ERROR', 'CRONTAB_UNAVAILABLE', 'crontab', 'crontab NOT checked: "crontab -l" failed (exit ' . $rc . '): ' . trim($output));
            return (null);
        }

        foreach (explode("\n", $output) as $line) {
            if ((trim($line) === "") || ((strlen($line) > 0) && ('#' == $line[0]))) {
                continue;
            }

            foreach (Signatures::crontab() as $item) {
                foreach ($item as $name => $pattern) {
                    if (preg_match($pattern, $line)) {
                        $this->report('HIGH', 'CRONTAB_IOC', 'crontab', $name . ': ' . $line);
                        break 2;
                    }
                }
            }
        }
        return (null);
    }
}
