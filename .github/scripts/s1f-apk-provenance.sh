#!/usr/bin/env bash
# Record only public, synthetic-offline APK provenance on GitHub-hosted CI.
set -euo pipefail
test "$GITHUB_REF" = refs/heads/verification/s1f-offline-smoke-20261116
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
src="apps/android/build/outputs/apk/offlineSmoke/debug/OpenDropAndroid-offlineSmoke-debug.apk"
test -s "$src"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
toolsdir="$(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)"
test -x "$toolsdir/aapt"
test -x "$toolsdir/apksigner"
apk="$src"
badge="$("$toolsdir/aapt" dump badging "$apk")"
package="$(printf '%s\n' "$badge" | grep '^package:')"
echo "$package" | grep -F "name='org.opendrop.app.s1fsmoke'"
echo "$package" | grep -F "versionCode='1'"
echo "$badge" | grep -F "sdkVersion:'26'"
echo "$badge" | grep -F "targetSdkVersion:'35'"
permissions="$("$toolsdir/aapt" dump permissions "$apk")"
if grep -E 'android.permission.(INTERNET|ACCESS_NETWORK_STATE|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE)' <<< "$permissions"; then
  echo "Network or broad storage permission FOUND in built owner APK" >&2
  exit 1
fi
"$toolsdir/apksigner" verify --verbose --print-certs "$apk" > "$RUNNER_TEMP/s1f-signer-report.txt"
grep -F 'Verified using v2 scheme (APK Signature Scheme v2): true' "$RUNNER_TEMP/s1f-signer-report.txt"
# Android Build Tools releases differ in capitalization and whether the
# certificate digest is colon-delimited. Print ONLY the PUBLIC certificate
# digest report for inspection, normalize hex and refuse non-256bit values.
grep -iE '(certificate.*SHA-256|SHA-256.*certificate)' "$RUNNER_TEMP/s1f-signer-report.txt" || {
  echo "Signing certificate fingerprint not reported by apksigner" >&2
  exit 1
}
raw="$(grep -im1 -E '(certificate.*SHA-256|SHA-256.*certificate)' "$RUNNER_TEMP/s1f-signer-report.txt")"
cert="$(printf '%s\n' "$raw" | sed -E 's/.*[Dd]igest: *//' | tr -cd '0-9a-fA-F' | tr 'A-F' 'a-f')"
test "${#cert}" -eq 64
unzip -l "$apk" | grep -F 'lib/arm64-v8a/libopendrop_android_guest.so'
if unzip -l "$apk" | grep -E '(lib/.*\.so)' | grep -v -F 'libopendrop_android_guest.so'; then
  echo "Unexpected extra JNI libraries in offline owner APK" >&2
  exit 1
fi
tree="$("$toolsdir/aapt" dump xmltree "$apk" AndroidManifest.xml)"
echo "$tree" | grep -F 'org.opendrop.app.OfflineSmokeActivity'
echo "$tree" | grep -F 'android.intent.action.SEND'
echo "$tree" | grep -F 'android.intent.action.SEND_MULTIPLE'
if grep -E 'ShareIngressActivity|GuestFixtureProvider|GuestGrantIssuerProvider|android.permission.INTERNET|android.permission.ACCESS_NETWORK_STATE' <<< "$tree"; then
  echo "Prohibited production transfer UI, test provider or network permission" >&2
  exit 1
fi
if unzip -p "$apk" classes.dex | strings | grep -E 'Lorg/opendrop/app/(ShareIngressActivity|GuestFixtureProvider|GuestGrantIssuerProvider);'; then
  echo "Unexpected normal-sender Activity or test fixture code in offline owner DEX" >&2
  exit 1
fi
out="$RUNNER_TEMP/s1f-owner-artifact"
mkdir -p "$out"
cp "$src" "$out/OpenDrop-S1F-OfflineSmoke-ARM64.apk"
apkhash="$(sha256sum "$out/OpenDrop-S1F-OfflineSmoke-ARM64.apk" | cut -d' ' -f1)"
libhash="$(sha256sum apps/android/build/generated/opendrop-jni/arm64-v8a/libopendrop_android_guest.so | cut -d' ' -f1)"
cat > "$out/S1F_APK_PROVENANCE.txt" <<EOF
OpenDrop S1-F owner-operated OFFLINE smoke, NOT production signed.
source_repository=Suraj-H675/OpenDrop
source_branch=verification/s1f-offline-smoke-20261116
source_commit=$GITHUB_SHA
github_actions_run=$GITHUB_RUN_ID
github_actions_attempt=$GITHUB_RUN_ATTEMPT
artifact_file=OpenDrop-S1F-OfflineSmoke-ARM64.apk
artifact_sha256=$apkhash
android_signer_certificate_sha256=$cert
android_package=org.opendrop.app.s1fsmoke
versionCode=1
minSdk=26
targetSdk=35
arm64_jni_sha256=$libhash
android_uses_permissions=NONE (aapt dump permissions verified)
internet_permission=ABSENT (aapt manifest verified)
normal_sender_activity=ABSENT (aapt manifest/DEX verified)
send_and_recover_jni_symbols=ABSENT (native readelf verified)
androidTest_fixture_providers=ABSENT (aapt manifest/DEX verified)
hosted_ART=PASS both prepare/restart
sig_type=runner-generated DEBUG signature only; NEVER release.
EOF
cat "$out/S1F_APK_PROVENANCE.txt"
echo "S1F_VERIFIED_APK_SHA256=$apkhash" >> "$GITHUB_ENV"
echo "S1F_OWNER_ARTIFACT_DIR=$out" >> "$GITHUB_ENV"
