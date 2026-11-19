# Run the test programs built by build.sh (POSIX sh, also on Android).
# usage: [NO_THREADS=1] sh run.sh <dir> <suffix> [runner...]
# Prints "ALL OK" at the end if every program exited with 0.
D=$1; S=$2; shift 2
fail=0
run() {
  echo "== $*"
  "$@" > run-last.log 2>&1
  rc=$?
  tail -n 3 run-last.log
  echo "   exit=$rc"
  [ $rc = 0 ] || fail=1
}
run "$@" "$D/osrngcheck$S"
run "$@" "$D/cryptotest$S"
run "$@" "$D/tempfiletest$S" 20000
run "$@" "$D/tempfiletest$S" 20000 1 faults
run "$@" "$D/tempfiletest$S" 20000 1 db4096
run "$@" "$D/oomtest$S"
run "$@" "$D/rekeytest$S"
run "$@" "$D/crashtest$S"
run "$@" "$D/vfsstacktest$S"
[ -n "$NO_THREADS" ] || run "$@" "$D/threadtest$S"
if [ $fail = 0 ]; then echo "ALL OK"; else echo "SOME FAILED"; fi
exit $fail
