# CredIssuer Wallet — Setup & Build Guide

> **Do not follow the upstream guide at `docs.inji.io/inji-wallet/inji-mobile/build-and-deployment`.**
> It still documents the React Native 0.74 / Expo 51 era. This repo is on RN 0.79 / Expo 53, and
> almost every version number there (Kotlin, Gradle, NDK, SDK levels) is wrong for this codebase.
> Following it will fail the build. The tables below are taken from the actual build files.

---

## 1. Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Node.js** | 20 LTS or newer | `react-native@0.79` requires `>=18`. The `engines` field in `package.json` still says `>=16` — that is stale, ignore it. Verified working on 24.19.0. |
| **npm** | 10 or newer | Verified on 11.17.0. |
| **JDK** | **17** | Required by AGP 8.9. Verified on Amazon Corretto 17.0.13. JDK 21 is not validated here. |
| **Gradle** | *don't install* | The wrapper pins **8.13** and downloads it for you. Always use `./gradlew`. |
| **Xcode** | 15+ | iOS only. Deployment target 14.0. |
| **CocoaPods** | > 1.12 | iOS only. |

Kotlin **2.0.21** and Android Gradle Plugin **8.9.2** are resolved by Gradle automatically — you do
not install them. Kotlin 2.x is **not optional**: Expo 53's `expo-modules-core` applies
`org.jetbrains.kotlin.plugin.compose`, which does not exist before Kotlin 2.0.

### Installing JDK 17 (macOS, via SDKMAN)

```bash
curl -s "https://get.sdkman.io" | bash
sdk install java 17.0.13-amzn
sdk use java 17.0.13-amzn
java -version   # must print 17.x
```

---

## 2. Android SDK

Install these exact components through Android Studio's SDK Manager (or `sdkmanager`):

| Component | Version |
|---|---|
| Compile SDK | **36** |
| Target SDK | **36** |
| Min SDK | **26** |
| Build-Tools | **36.0.0** |
| NDK | **29.0.14206865** |

The NDK version must match exactly — the upstream guide's `21.4.7075529` is eight majors behind and
will not work.

```bash
sdkmanager "platforms;android-36" "build-tools;36.0.0" "ndk;29.0.14206865"
```

### Shell environment

Add to `~/.zshrc` (or `~/.bashrc`):

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_PLATFORM_TOOLS="$ANDROID_HOME/platform-tools"
export ANDROID_CMDLINE_TOOLS="$ANDROID_HOME/cmdline-tools/latest/bin"
export PATH="$PATH:$ANDROID_PLATFORM_TOOLS:$ANDROID_CMDLINE_TOOLS"

export DEBUG_KEYSTORE_ALIAS=androiddebugkey
export DEBUG_KEYSTORE_PASSWORD=android
```

---

## 3. Install dependencies

```bash
git clone <this-repo>
cd inji-wallet
npm ci
```

> ### Use `npm ci`, never `npm install`
>
> The lockfile pins 13 `@digitalbazaar/*` packages to exact git commit SHAs. `npm install`
> re-resolves them and fails with a `git checkout initial` error, because a `#initial` branch some of
> them referenced no longer exists upstream. `npm ci` installs the lockfile verbatim and sidesteps
> this entirely.
>
> This also applies when a build breaks mysteriously: `rm -rf node_modules && npm ci`.

`postinstall` automatically runs `patch-package`, `jetify`, and the Talisman pre-commit hook setup.

---

## 4. Configure `.env`

A `.env` file at the repo root drives the runtime configuration. Keys currently in use:

```bash
MIMOTO_HOST=            # CredIssuer / Mimoto backend base URL
ESIGNET_HOST=           # eSignet base URL
OBSRV_HOST=             # telemetry endpoint

APPLICATION_THEME=      # gradient | purple
APPLICATION_LANGUAGE=   # en, fil, ar, hi, kn, ta
CREDENTIAL_REGISTRY_EDIT=
DEBUG_MODE=

LIVENESS_DETECTION=     # generic liveness toggle
SNAPKYC_LIVENESS=       # SnapKYC native liveness after mDOC proximity consent (Android only)
SNAPKYC_RELAYING_PARTY_NAME=
SNAPKYC_DEBUG_SKIP_FACE_IMAGE=   # debug only: skip credential portrait

GOOGLE_ANDROID_CLIENT_ID=
```

Get the real values from a team member — `.env` is not committed.

> **After editing `.env`, restart the bundler with `--reset-cache`.** The values are inlined at
> bundle time, so a running Metro instance will keep serving the old ones.

---

## 5. Configure Artifactory credentials (required — Android will not build without this)

This fork depends on the private **SnapKYC face-liveness AARs** (`io.ooru.biometrics`), hosted on an
internal Nexus. This step does not exist in the upstream guide.

Create `android/artifactory.local.properties` (gitignored):

```properties
artifactoryUsername=<ask a team member>
artifactoryPassword=<ask a team member>
artifactorySnapshotUrl=https://nexus-biochq.credissuer.com/repository/maven-snapshots/
artifactoryReleaseUrl=https://nexus-biochq.credissuer.com/repository/maven-releases/
```

CI can supply `ARTIFACTORY_USERNAME` / `ARTIFACTORY_PASSWORD` as environment variables instead.

Both AARs are pinned to fixed release versions (`1.0.1`), so **the Nexus is contacted only on the
first build**. Afterwards Gradle serves them from its local cache and builds work offline. Do not add
`changing = true` or a `-SNAPSHOT` version to these dependencies: that makes Gradle re-check the
server on *every* build and fail outright whenever it is unreachable.

---

## 6. Run the app

Start Metro in one terminal:

```bash
npm start
```

Build and install the debug app in another:

```bash
npm run android:mosip
```

After any `.env` change, restart Metro with a cache reset

```bash
npm run android:mosip --reset-cache
```

### Build flavors

`android:mosip` builds the **`residentapp`** flavor, which is the CredIssuer Wallet build
(`applicationId io.ooru.credissuerwallet`, app name "CredIssuer Wallet"). Other flavors defined in
[`android/app/build.gradle`](android/app/build.gradle) — `inji`, `collab`, `synergy`, `mec` — are
upstream MOSIP variants and are not used here.

> **Note on package naming:** only the `applicationId` was renamed to `io.ooru.credissuerwallet`. The
> internal Java/Kotlin `namespace` is deliberately left as `io.mosip.residentapp`, as is the OAuth
> redirect scheme. Renaming those would mean rewriting the package declaration in 31 source files and
> would conflict heavily on every upstream merge.

### Release build

```bash
npm run build:android:mosip
```

Output: `android/app/build/outputs/apk/residentapp/release/`.

---

## 7. iOS

```bash
cd ios && pod install && cd ..
npm run ios                 # simulator
npm run ios -- --device     # physical device
```

Android is the primary target for this fork; the SnapKYC liveness integration is Android-only.

---

## 8. Tests

```bash
npm test                # jest
npm run test-coverage
npm run lint
```

---

## 9. Troubleshooting

**`expo/scripts/autolinking.gradle` not found (from `android/settings.gradle`)**
`node_modules` has drifted from `package.json` — usually the result of an `npm install`. Check the
*installed* version before assuming corruption:
```bash
node -p "require('./node_modules/expo/package.json').version"   # must be 53.x
```
Fix with `rm -rf node_modules && npm ci`.

**`Read timed out` fetching from `www.jitpack.io`**
Already handled. [`android/build.gradle`](android/build.gradle) rewrites every `https://www.jitpack.io`
repository to `https://jitpack.io`, because the `www.` host completes the TLS handshake but never
responds. Remove that workaround only once React Native ships a fixed URL upstream.

**`Connect timed out` on `io.ooru.biometrics`**
VPN is down. See section 5.

**Gradle keeps contacting the Nexus on every build**
Something reintroduced a `-SNAPSHOT` version or `changing = true`. Gradle treats any version ending
in `-SNAPSHOT` as mutable and re-checks it every build, regardless of naming intent. Pin a fixed
release version instead.

**Clearing caches**
```bash
cd android && ./gradlew clean && cd ..     # build outputs only — does NOT clear downloaded deps
npm start -- --reset-cache                 # Metro cache
```
`./gradlew clean` does **not** evict the cached SnapKYC AARs; those live in `~/.gradle/caches`.

---

## 10. Known gaps on the current branch

- **Firebase is not wired natively yet.** `@react-native-firebase/app` and `messaging` are in
  `package.json`, but the `com.google.gms.google-services` plugin is not applied in
  `android/app/build.gradle` and no `android/app/google-services.json` is present. The build
  succeeds; push notifications will not initialise at runtime until both are added.
- **`patches/@react-native+gradle-plugin+0.74.87.patch`** is named for RN 0.74 while the repo is on
  0.79. It is stale and worth reviewing.

---

## Source of truth

When this document and the build files disagree, **the build files win**:

| Fact | File |
|---|---|
| SDK levels, NDK, Kotlin, AGP | [`android/build.gradle`](android/build.gradle) |
| Gradle version | `android/gradle/wrapper/gradle-wrapper.properties` |
| applicationId, flavors, dependencies | [`android/app/build.gradle`](android/app/build.gradle) |
| JS dependencies | `package.json` / `package-lock.json` |
