#!/usr/bin/env bash
# Exactly one freshly created GitHub-hosted API35 emulator, never a real phone.
set -euo pipefail
apk="apps/android/build/outputs/apk/offlineSmoke/debug/OpenDropAndroid-offlineSmoke-debug.apk"
testapk="apps/android/build/outputs/apk/androidTest/offlineSmoke/debug/OpenDropAndroid-offlineSmoke-debug-androidTest.apk"
test -s "$apk" && test -s "$testapk"
devices="$(adb devices | sed -n '2,$p' | sed '/^$/d')"
if [[ "$devices" != $'emulator-5554\tdevice' ]]; then
  echo "Refusing to install anything outside one disposable emulator" >&2
  exit 1
fi
adb -s emulator-5554 install -r "$apk"
adb -s emulator-5554 install -r "$testapk"
for phase in prepare restart; do
  if [[ "$phase" == restart ]]; then
    adb -s emulator-5554 shell am force-stop org.opendrop.app.s1fsmoke
    sleep 2
  fi
  if ! result="$(
    timeout --signal=TERM --kill-after=5s 180s \
      adb -s emulator-5554 shell am instrument -w \
      -e phase "$phase" \
      org.opendrop.app.s1fsmoke.test/org.opendrop.app.OfflineSmokeInstrumentation
  )"; then
    echo "S1F hosted ART instrumentation process exited incorrectly" >&2
    exit 1
  fi
  printf '%s\n' "$result"
  grep -Fq "S1F_OFFLINE_ART_PASS:$phase" <<< "$result"
  if grep -Eq 'S1F_OFFLINE_ART_FAIL:|INSTRUMENTATION_RESULT: shortMsg=|INSTRUMENTATION_CODE: (0|[1-9][0-9]*)' <<< "$result"; then
    echo "S1F native app/test generated an error" >&2
    exit 1
  fi
done
echo "S1F_OFFLINE_HOSTED_ART_SUCCESS: actual Keystore/JNI + real ContentResolver bytes + process restart"
