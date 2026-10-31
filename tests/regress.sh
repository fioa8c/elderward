#!/usr/bin/env bash
# Old-vs-new regression harness for the engine refactor.
#
# Runs the pre-refactor single-file script (taken from git) and the new
# bin/elderward.php with identical arguments over synthetic fixtures, and
# diffs stdout (sorted: unit ordering inside a scanner is not a contract)
# and exit codes. Any difference fails the run.
#
#   tests/regress.sh [git-ref-of-old-script]   (default: add-db-scanner)
#
# The database cases need the MariaDB fixture from TESTPLAN E (database
# wp_test reachable through /run/mysqld/mysqld.sock); they are skipped
# with a note when the server is not running.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OLD_REF="${1:-add-db-scanner}"
WORK="$(mktemp -d)"
OLD="$WORK/old-elderward.php"
NEW="$REPO/bin/elderward.php"
PASS=0
FAIL=0
SKIP=0

git -C "$REPO" show "$OLD_REF:elderward.php" > "$OLD" || { echo "cannot extract $OLD_REF:elderward.php"; exit 1; }

###############
# Fixtures
##############
SITE="$WORK/site"
mkdir -p "$SITE/sub"
cat > "$SITE/ndsw.js" <<'EOF'
var legit=1;
if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};
console.log(legit);
EOF
printf 'if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};\n' > "$SITE/sub/payload.txt"
printf 'clean file\n' > "$SITE/sub/clean.php"

LOGS="$WORK/logs"
mkdir -p "$LOGS"
cat > "$LOGS/access.log" <<'EOF'
203.0.113.5 - - [20/Sep/2026:10:05:01 +0000] "POST /wp-content/uploads/2026/09/wp-cache.php HTTP/1.1" 200 312 "-" "python-requests/2.31"
192.0.2.44 - - [20/Sep/2026:10:08:30 +0000] "GET /.env HTTP/1.1" 404 210 "-" "Mozilla/5.0"
192.0.2.44 - - [20/Sep/2026:10:09:00 +0000] "GET /?q=eval(base64_decode($_POST[1])) HTTP/1.1" 200 100 "-" "Mozilla/5.0"
EOF
ln -sf /nonexistent/access.log.1.gz "$LOGS/access.log.1.gz"
printf 'noise\n' > "$LOGS/error.log"

# A fake WordPress root with the quick-check artifacts and packages for the
# integrity/timestamp passes (checksumdir points at an empty dir, so the
# integrity pass never touches the network).
WP="$WORK/wp"
mkdir -p "$WP/wp-includes" "$WP/wp-admin" "$WP/wp-content/plugins/hello-dolly" "$WP/wp-content/themes/twentyx" \
         "$WP/wp-content/uploads/2026" "$WP/wp-content/mu-plugins"
printf '<?php\n$wp_version = '"'"'6.5.2'"'"';\n' > "$WP/wp-includes/version.php"
for i in $(seq 1 12); do printf '<?php // core %s\n' "$i" > "$WP/wp-includes/file$i.php"; done
printf '<?php // login\n' > "$WP/wp-login.php"
printf '<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/\n' > "$WP/wp-content/plugins/hello-dolly/hello.php"
printf '<?php // loose plugin\n' > "$WP/wp-content/plugins/loose.php"
printf '/*\nTheme Name: Twenty X\nVersion: 1.0\n*/\n' > "$WP/wp-content/themes/twentyx/style.css"
printf '<?php echo 1;\n' > "$WP/wp-content/uploads/2026/shell.php"
printf '<?php // silence\n' > "$WP/wp-content/uploads/index.php"
printf '<?php // mu\n' > "$WP/wp-content/mu-plugins/loader.php"
printf '<?php // hidden\n' > "$WP/wp-content/.hidden.php"
printf 'auto_prepend_file = /tmp/evil.php\n' > "$WP/.user.ini"
printf 'if(ndsw===undefined){(function(){var a = parseInt(f(q.a)) / 0x1 + parseInt(f(q.b)) / 0x2 + 0;function A(){return 1;}return A();}};\n' > "$WP/wp-content/themes/twentyx/bad.js"
# A timestamp outlier: 12 core files from 2024, one edited "later".
find "$WP/wp-includes" -type f -exec touch -t 202401010000 {} +
touch -t 202406010000 "$WP/wp-includes/file7.php"
touch -t 202401010000 "$WP/wp-login.php"
EMPTY="$WORK/empty"
mkdir -p "$EMPTY"

SP_DBROOT="${ELDERWARD_DBROOT:-/tmp/claude-0/-home-user-repo/17782ee5-9ca9-5ef3-84d1-5311e5ee9ae3/scratchpad/dbroot}"
DB_UP=0
if command -v mysqladmin >/dev/null 2>&1 && mysqladmin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1 && [ -f "$SP_DBROOT/wp-config.php" ]; then
    DB_UP=1
fi

###############
# Runner
##############
# compare NAME [args...]  - run old and new in text and json, compare.
compare() {
    local name="$1"; shift
    local mode
    for mode in text json; do
        local extra=()
        [ "$mode" = json ] && extra=(format=json)
        local o_out n_out o_rc n_rc
        (cd "$WORK" && php "$OLD" "$@" "${extra[@]}" > "$WORK/o.out" 2>/dev/null); o_rc=$?
        (cd "$WORK" && php "$NEW" "$@" "${extra[@]}" > "$WORK/n.out" 2>/dev/null); n_rc=$?
        o_out="$(sort "$WORK/o.out")"
        n_out="$(sort "$WORK/n.out")"
        if [ "$o_out" == "$n_out" ] && [ "$o_rc" == "$n_rc" ]; then
            PASS=$((PASS+1))
            printf 'PASS  %-34s %-4s exit=%s lines=%s\n' "$name" "$mode" "$n_rc" "$(printf '%s' "$n_out" | grep -c .)"
        else
            FAIL=$((FAIL+1))
            printf 'FAIL  %-34s %-4s old exit=%s new exit=%s\n' "$name" "$mode" "$o_rc" "$n_rc"
            diff <(printf '%s\n' "$o_out") <(printf '%s\n' "$n_out") | head -20
        fi
    done
}

compare "signature dryrun"            dryrun=1 "scandirectory=$SITE"
compare "signature allfiles dryrun"   dryrun=1 allfiles=1 "scandirectory=$SITE"
compare "signature bad dir"           "scandirectory=$WORK/nonexistent"
compare "scan_all rejected"           scan_all=1 "scandirectory=$SITE"
compare "mode exclusivity"            scancron=1 scantimes=1
compare "correlate without scanlog"   correlate=1
compare "plus decodes to space"       "scandirectory=$WORK/a+b"
compare "log single file"             "scanlog=$LOGS/access.log"
compare "log directory"               "scanlog=$LOGS"
compare "log + correlate"             "scanlog=$LOGS" correlate=1 "scandirectory=$SITE"
compare "log missing target"          "scanlog=$WORK/nope"
compare "crontab"                     scancron=1
compare "quickscan"                   quickscan=1 "scandirectory=$WP"
compare "quickscan non-wp root"       quickscan=1 "scandirectory=$SITE"
compare "scantimes"                   scantimes=1 "scandirectory=$WP"
compare "scanintegrity offline"       scanintegrity=1 "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall offline (no db)"     scanall=1 "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall + scanlog"           scanall=1 "scanlog=$LOGS" "checksumdir=$EMPTY" "scandirectory=$WP"
compare "scanall restore ignored"     scanall=1 restore=1 "checksumdir=$EMPTY" "scandirectory=$WP"

if [ "$DB_UP" = 1 ]; then
    compare "scandb infected"         scandb=1 "scandirectory=$SP_DBROOT"
    compare "scanall with db"         scanall=1 "checksumdir=$EMPTY" "scandirectory=$SP_DBROOT"
    for variant in root_badprefix root_badpass root_tcp; do
        if [ -d "$(dirname "$SP_DBROOT")/$variant" ]; then
            compare "scandb $variant"       scandb=1 "scandirectory=$(dirname "$SP_DBROOT")/$variant"
            compare "scanall $variant"      scanall=1 "checksumdir=$EMPTY" "scandirectory=$(dirname "$SP_DBROOT")/$variant"
        fi
    done
else
    SKIP=$((SKIP+1))
    echo "SKIP  database cases (MariaDB not reachable or $SP_DBROOT missing)"
fi

###############
# Real cleanup: both must leave the same bytes on disk.
##############
cp -r "$SITE" "$WORK/clean-old"; cp -r "$SITE" "$WORK/clean-new"
php "$OLD" "scandirectory=$WORK/clean-old" >/dev/null 2>&1; o_rc=$?
php "$NEW" "scandirectory=$WORK/clean-new" >/dev/null 2>&1; n_rc=$?
if diff -r "$WORK/clean-old" "$WORK/clean-new" >/dev/null && [ "$o_rc" == "$n_rc" ] && ! grep -q ndsw "$WORK/clean-new/ndsw.js"; then
    PASS=$((PASS+1)); echo "PASS  real cleanup: identical trees, payload removed, exit=$n_rc"
else
    FAIL=$((FAIL+1)); echo "FAIL  real cleanup differs (old exit=$o_rc new exit=$n_rc)"; diff -r "$WORK/clean-old" "$WORK/clean-new" | head
fi

echo
echo "passed=$PASS failed=$FAIL skipped=$SKIP  (work dir: $WORK)"
[ "$FAIL" = 0 ]
