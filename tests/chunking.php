<?php
// Resumability check: run scanall one unit per "request" with an expired
// deadline and serialised state, and compare the findings with one
// uninterrupted run. Usage: php tests/chunking.php /path/to/wp-root [logdir]
require_once dirname(__DIR__) . '/includes/engine/load.php';
use Elderward\Engine\Context; use Elderward\Engine\BaseReporter; use Elderward\Engine\Runner;
use Elderward\Engine\Scanner; use Elderward\Engine\CurlHttp; use Elderward\Engine\MysqliDb;

class CollectReporter extends BaseReporter {
    public $lines = array(); public $units = 0;
    public function finding($s, $t, $p, $d, $c = array()) { $this->track($s); $this->lines[] = "$s,$t,$p,$d"; }
    public function summary($scan, $data, $text) { $this->lines[] = 'summary:' . $scan . ':' . json_encode($data); }
    public function progress($text) {}
    public function fatal($m) { $this->lines[] = 'fatal:' . $m; }
}
$opts = array('scandirectory' => $argv[1], 'scanall' => 1, 'checksumdir' => sys_get_temp_dir());
if (isset($argv[2])) { $opts['scanlog'] = $argv[2]; }

function run_full($opts) {
    $r = new CollectReporter();
    Runner::run_mode(new Context($opts, $r, new CurlHttp(), new MysqliDb(), dirname(__DIR__)), 'scanall');
    return $r;
}
function run_chunked($opts) {
    $r = new CollectReporter();
    $ctx = Runner::scanall_context(new Context($opts, $r, new CurlHttp(), new MysqliDb(), dirname(__DIR__)));
    $states = array(); $requests = 0;
    foreach (Runner::scanall_stages($ctx) as $stage) {
        $scanner = Runner::make_stage($ctx, $stage, $states);
        $state = $scanner->init_state();
        $queue = $scanner->plan($state);
        $blob = serialize(array($queue, $state));
        while (true) {
            list($queue, $state) = unserialize($blob);          // fresh "request"
            if (0 === count($queue)) { break; }
            $requests++;
            $scanner = Runner::make_stage($ctx, $stage, $states);   // new instance each request
            $ctx->deadline = microtime(true) - 1;               // already out of time
            $unit = array_shift($queue);
            $next = $scanner->run($unit, $state);
            if (null !== $next) { $queue = array_merge(Scanner::as_unit_list($next), $queue); }
            $blob = serialize(array($queue, $state));
        }
        $ctx->deadline = null;
        $scanner->finish($state);
        $states[$stage] = $state;
    }
    $r->units = $requests;
    return $r;
}
$full = run_full($opts); $chunk = run_chunked($opts);
$a = $full->lines; $b = $chunk->lines; sort($a); sort($b);
echo "full: " . count($a) . " lines, exit " . $full->exit_code() . "\n";
echo "chunked: " . count($b) . " lines, exit " . $chunk->exit_code() . ", " . $chunk->units . " requests\n";
if ($a === $b && $full->exit_code() === $chunk->exit_code()) { echo "IDENTICAL\n"; exit(0); }
echo "DIFFERENT\n"; print_r(array_diff($a, $b)); print_r(array_diff($b, $a)); exit(1);
