#!/usr/bin/env bash
# Run ONLY inside the disposable GitHub-hosted Android emulator step.
# Never run on, install to, or connect to any owner device or ADB endpoint.
set -euo pipefail
apk="apps/android/build/outputs/apk/debug/OpenDropAndroid-debug.apk"
testapk="apps/android/build/outputs/apk/androidTest/debug/OpenDropAndroid-debug-androidTest.apk"
test -s "$apk"
test -s "$testapk"

# This job operates a freshly created emulator, not the owner's USB device.
devices="$(adb devices | sed -n '2,$p' | sed '/^$/d')"
if [[ "$devices" != $'emulator-5554\tdevice' ]]; then
  echo "Refusing to install: expected exactly one disposable emulator-5554" >&2
  exit 1
fi
adb -s emulator-5554 install -r "$apk"
adb -s emulator-5554 install -r "$testapk"
# Discard unrelated emulator boot logs. Only synthetic test process
# failures may appear in public CI diagnostic output.
adb -s emulator-5554 logcat -c

dump_crash_evidence() {
  echo 'S1E_HOSTED_EMULATOR_CRASH_EVIDENCE_BEGIN'
  # A process can die before Instrumentation.finish() produces a test-stage
  # result. Restrict output to actual Android crash-buffer stack lines, on
  # this disposable emulator only. No keys, personal files or full logcat.
  adb -s emulator-5554 logcat -d -b crash -t 180 2>/dev/null |
    grep -E '(FATAL EXCEPTION|Process:|Caused by:|Exception|Error:|^.*[[:space:]]at (org\.opendrop|android\.|java\.|kotlin\.|com\.android)|^.*[[:space:]]at )' |
    tail -65 || true
  echo 'S1E_HOSTED_EMULATOR_CRASH_EVIDENCE_END'
}

for phase in prepare restart; do
  if [[ "$phase" == restart ]]; then
    # Kill only the disposable emulator's test app after prepare commits its
    # encrypted record, then exercise a genuinely distinct Android process.
    adb -s emulator-5554 shell am force-stop org.opendrop.app
    sleep 2
  fi
  if ! result="$(
    timeout --signal=TERM --kill-after=5s 180s \
      adb -s emulator-5554 shell am instrument -w \
        -e phase "$phase" \
        org.opendrop.app.test/org.opendrop.app.GuestRuntimeInstrumentation
  )"; then
    printf '%s\n' "$result"
    dump_crash_evidence
    echo "Actual Android instrumentation process failed in phase $phase" >&2
    exit 1
  fi
  printf '%s\n' "$result"
  grep -Fq "S1E_ANDROID_ART_PASS:$phase" <<< "$result" || {
    dump_crash_evidence
    echo "Actual ART instrumentation $phase did not assert PASS" >&2
    exit 1
  }
  grep -Fq 'INSTRUMENTATION_CODE: -1' <<< "$result" || {
    dump_crash_evidence
    echo "Actual ART instrumentation $phase did not return RESULT_OK" >&2
    exit 1
  }
done
echo 'HOSTED ART/P256/URI/AES-GCM: two real test phases passed; no personal device or attestation claim.'
