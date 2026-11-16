#!/usr/bin/env bash
# Exactly one freshly created GitHub-hosted API35 emulator, never a real phone.
set -euo pipefail
apk="apps/android/build/outputs/apk/offlineSmoke/debug/OpenDropAndroid-offlineSmoke-debug.apk"
testapk="apps/android/build/outputs/apk/androidTest/offlineSmoke/debug/OpenDropAndroid-offlineSmoke-debug-androidTest.apk"
normalapk="apps/android/build/outputs/apk/normal/debug/OpenDropAndroid-normal-debug.apk"
normaltest="apps/android/build/outputs/apk/androidTest/normal/debug/OpenDropAndroid-normal-debug-androidTest.apk"
test -s "$apk" && test -s "$testapk" && test -s "$normalapk" && test -s "$normaltest"
devices="$(adb devices | sed -n '2,$p' | sed '/^$/d')"
if [[ "$devices" != $'emulator-5554\tdevice' ]]; then
  echo "Refusing to install anything outside one disposable emulator" >&2
  exit 1
fi

# First run the actual NORMAL production Keystore/recovery instrumentation
# with the new multi-record selection, expiry, corruption, capacity and
# process-restart assertions. Its APK lives only on this disposable emulator,
# not in the downloadable owner artifact.
adb -s emulator-5554 install -r "$normalapk"
adb -s emulator-5554 install -r "$normaltest"
for phase in prepare restart; do
  if [[ "$phase" == restart ]]; then
    adb -s emulator-5554 shell am force-stop org.opendrop.app
    sleep 2
  fi
  result="$(timeout --signal=TERM --kill-after=5s 180s \
    adb -s emulator-5554 shell am instrument -w -e phase "$phase" \
    org.opendrop.app.test/org.opendrop.app.GuestRuntimeInstrumentation)"
  printf '%s\n' "$result"
  grep -Fq "S1E_ANDROID_ART_PASS:$phase" <<< "$result"
  if grep -Eq 'S1E_ANDROID_ART_FAIL:|INSTRUMENTATION_RESULT: shortMsg=|INSTRUMENTATION_CODE: (0|[1-9][0-9]*)' <<< "$result"; then
    echo "Normal production Android recovery tests failed" >&2
    exit 1
  fi
done
adb -s emulator-5554 uninstall org.opendrop.app.test
adb -s emulator-5554 uninstall org.opendrop.app

# Now install ONLY the distinct offline app (and disposable androidTest APK).
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
