<?php
namespace Elderward\Engine;

////////////////
// Every scanner is a list of work units.
//
//   $state = $scanner->init_state();
//   $queue = $scanner->plan($state);        // serialisable units
//   ...   = $scanner->run($unit, $state);   // null, a unit, or a list of
//                                           // units to run next (prepended)
//   $scanner->finish($state);               // per-scanner summary
//
// The CLI runs the whole queue in one go (Scanner::run_all). Inside a web
// request the plugin runs units until the Context deadline passes, stores
// the queue and $state, and continues on the next request. Units and
// state therefore hold only plain arrays and scalars.
//////////////

abstract class Scanner
{
    protected $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    abstract public function name();

    public function init_state()
    {
        return array();
    }

    abstract public function plan(array &$state);

    abstract public function run(array $unit, array &$state);

    public function finish(array &$state)
    {
    }

    protected function report($severity, $type, $path, $detail, $context = array())
    {
        $this->ctx->reporter->finding($severity, $type, $path, $detail, $context);
    }

    protected function progress($text)
    {
        $this->ctx->reporter->progress($text);
    }

    protected function summary($scan, $data, $text)
    {
        $this->ctx->reporter->summary($scan, $data, $text);
    }

    // Run every unit to completion (no deadline). Returns the final state.
    public static function run_all(Scanner $scanner)
    {
        $state = $scanner->init_state();
        $queue = $scanner->plan($state);
        while (count($queue) > 0) {
            $unit = array_shift($queue);
            $next = $scanner->run($unit, $state);
            if (null !== $next) {
                $queue = array_merge(self::as_unit_list($next), $queue);
            }
        }
        $scanner->finish($state);
        return ($state);
    }

    // A unit is an associative array; a list of units is a numeric array.
    public static function as_unit_list($next)
    {
        if (is_array($next) && (0 === count($next) || isset($next[0]))) {
            return ($next);
        }
        return (array($next));
    }
}
