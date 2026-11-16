#!/usr/bin/env bash
# Disposable GitHub-hosted Android 35 ART; never the owner's phone.
set -euo pipefail
apk="apps/android/build/outputs/apk/normal/debug/OpenDropAndroid-normal-debug.apk"
testapk="apps/android/build/outputs/apk/androidTest/normal/debug/OpenDropAndroid-normal-debug-androidTest.apk"
test -s "$apk" && test -s "$testapk"
devices="$(adb devices | sed -n '2,$p' | sed '/^$/d')"
if [[ "$devices" != $'emulator-5554\tdevice' ]]; then
  echo 'Refusing to operate any device except ONE disposable emulator-5554' >&2
  exit 1
fi
adb -s emulator-5554 install -r "$apk"
adb -s emulator-5554 install -r "$testapk"
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
    echo 'Android Keystore/JNI or missing-hotspot fail-closed assertion failed' >&2
    exit 1
  fi
done
echo 'S1G_ANDROID_NATIVE_ART_PASS: Keystore signing, recovery persistence, AP-absent fail-closed'
