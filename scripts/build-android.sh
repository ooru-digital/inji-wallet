#!/usr/bin/env bash
# Builds the CredIssuer Wallet Android release. This is the Android build step of
# .github/workflows/credissuer-build.yml, and it runs the same way on a developer machine.
#
#   scripts/build-android.sh        AAB for the Play Store. Runs exactly
#                                   ./gradlew :app:bundleResidentappRelease
#   scripts/build-android.sh apk    APK that installs directly on a phone
#                                   (./gradlew :app:assembleResidentappRelease)
#
# Before building it checks everything the release build silently depends on, and stops with
# one message per problem instead of failing twenty minutes into Gradle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUTPUT_TYPE="${1:-aab}"
case "$OUTPUT_TYPE" in
  aab)
    GRADLE_TASK=":app:bundleResidentappRelease"
    OUTPUT="android/app/build/outputs/bundle/residentappRelease/app-residentapp-release.aab"
    ;;
  apk)
    GRADLE_TASK=":app:assembleResidentappRelease"
    OUTPUT="android/app/build/outputs/apk/residentapp/release/CredIssuerWallet_universal.apk"
    ;;
  *)
    echo "Usage: scripts/build-android.sh [aab|apk]" >&2
    exit 2
    ;;
esac

problems=()

[ -d node_modules ] ||
  problems+=("node_modules is missing. Run: npm ci")

# android/app/build.gradle falls back to a dummy keystore when this one is missing, and the
# build then fails at signing with an unrelated-looking error.
[ -f android/app/release.keystore ] ||
  problems+=("android/app/release.keystore is missing. Copy the release keystore there (it is git-ignored).")

# build.gradle reads both from the environment; unset, they become the literal string "null".
[ -n "${RELEASE_KEYSTORE_ALIAS:-}" ] ||
  problems+=("RELEASE_KEYSTORE_ALIAS is not set. Run: export RELEASE_KEYSTORE_ALIAS=<keystore alias>")
[ -n "${RELEASE_KEYSTORE_PASSWORD:-}" ] ||
  problems+=("RELEASE_KEYSTORE_PASSWORD is not set. Run: export RELEASE_KEYSTORE_PASSWORD=<keystore password>")

# Without the token the app still builds and runs, but silently shows the wallet-generated QR
# instead of the CredIssuer one, so a release must not be built without it.
if ! grep -Eq '^CREDISSUER_API_TOKEN=.+' .env.local 2>/dev/null; then
  problems+=("CREDISSUER_API_TOKEN is missing from .env.local. Add the line: CREDISSUER_API_TOKEN=<token>")
fi

if [ "${#problems[@]}" -gt 0 ]; then
  echo "❌ Cannot build Android yet:" >&2
  for problem in "${problems[@]}"; do
    echo "   - $problem" >&2
  done
  exit 1
fi

# Not a hard stop: once Gradle has cached the BioChq AARs it never contacts the Nexus again.
if [ ! -f android/artifactory.local.properties ] && [ -z "${ARTIFACTORY_USERNAME:-}" ]; then
  echo "⚠️  No Nexus credentials found (android/artifactory.local.properties or ARTIFACTORY_USERNAME)."
  echo "   If the build fails with '401 Unauthorized' from nexus-biochq, see README section 5."
fi

VERSION_NAME="$(sed -nE 's/^[[:space:]]*versionName[[:space:]]+"([^"]+)".*/\1/p' android/app/build.gradle | head -1)"
VERSION_CODE="$(sed -nE 's/^[[:space:]]*versionCode[[:space:]]+([0-9]+).*/\1/p' android/app/build.gradle | head -1)"
echo "▶ Building CredIssuer Wallet $VERSION_NAME ($VERSION_CODE) for Android: ./gradlew $GRADLE_TASK"

# A leftover file from an earlier build must not be reported as this build's result.
rm -f "$OUTPUT"

(cd android && ./gradlew "$GRADLE_TASK")

if [ ! -f "$OUTPUT" ]; then
  echo "❌ Gradle finished but $OUTPUT was not created." >&2
  exit 1
fi

SIZE="$(du -h "$OUTPUT" | cut -f1)"
echo "✅ Built $VERSION_NAME ($VERSION_CODE), $SIZE: $ROOT/$OUTPUT"
