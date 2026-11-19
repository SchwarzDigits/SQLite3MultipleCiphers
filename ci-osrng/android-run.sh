#!/bin/bash
# Push the Android build of one ABI to the running emulator and run the tests there.
# usage: android-run.sh <outdir>
set -e
OUT=$1
D=/data/local/tmp/osrng
adb shell "rm -rf $D && mkdir -p $D"
adb push "$OUT/." "$D/" > /dev/null
adb push ci-osrng/run.sh "$D/" > /dev/null
adb shell getprop ro.build.version.sdk
adb shell uname -r
adb shell "cd $D && chmod 755 ./* && TMPDIR=$D sh ./run.sh . ''" | tee android.log
grep -q "^ALL OK" android.log
