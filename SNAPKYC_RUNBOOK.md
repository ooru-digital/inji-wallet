# SnapKYC liveness — build & test runbook

Everything is already wired. These are the steps to run once you're on the ooru VPN.
Delete this file when you're done (it's scratch, not meant to be committed).

---

## 0. Confirm the VPN actually fixes reachability

```bash
curl -sv --max-time 15 -u 'ayush:Ayush@Nexus657' \
  "http://biometrics.credissuer.com:8081/repository/maven-snapshots/io/ooru/biometrics/faceliveness-sdk/1.0.1-SNAPSHOT/maven-metadata.xml" 2>&1 | tail -20
```

**Expect:** `HTTP/1.1 200` and an XML body listing snapshot versions.

- `Connect timed out` → VPN isn't routing `172.31.42.196`. Nothing below will work.
- `HTTP/1.1 401` → reachable but credentials rejected. Fix `android/artifactory.local.properties`.
- `HTTP/1.1 404` → reachable and authed, but the artifact/version moved. Browse
  `http://biometrics.credissuer.com:8081/repository/maven-snapshots/io/ooru/biometrics/`
  and update the version in `android/app/build.gradle` (two `1.0.1-SNAPSHOT` lines).

---

## 1. Resolve the SnapKYC dependencies

```bash
cd android
./gradlew :app:dependencies --configuration residentappDebugRuntimeClasspath | grep -E "io\.ooru"
cd ..
```

**Expect:** two lines, neither ending in `FAILED`:

```
+--- io.ooru.biometrics:faceliveness-sdk:1.0.1-SNAPSHOT -> 1.0.1-20xx...
+--- io.ooru.biometrics:faceliveness-frontend:1.0.1-SNAPSHOT -> 1.0.1-20xx...
```

CameraX already resolves to 1.4.1 across the board — that was verified off-VPN, no need to recheck.

---

## 2. Build

```bash
cd android && ./gradlew :app:assembleResidentappDebug && cd ..
```

First build after adding the SDK will be slow (new AARs + dexing).

### If it fails

| Error                                                | Fix                                                                                                                                                                                                                                        |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Duplicate class ...commons.logging...`              | Already excluded; if a _different_ dup appears, add `all*.exclude group: '<group>', module: '<module>'` in the `configurations.all` block of `android/app/build.gradle`                                                                    |
| `Manifest merger failed ... networkSecurityConfig`   | Add `networkSecurityConfig` to the existing `tools:replace` list in `android/app/src/main/AndroidManifest.xml` (currently `tools:replace="usesCleartextTraffic"`)                                                                          |
| `Manifest merger failed ... FileProvider`            | Another lib already declares `${applicationId}.fileprovider`. Change the authority in **both** the manifest `<provider>` and `RNSnapKycLivenessModule.java` (the `authority` variable, ~line 96) to `${applicationId}.snapkycfileprovider` |
| `cannot find symbol: BioChqFaceLivenessMainActivity` | The AAR resolved but the class path differs in this build. Unzip the AAR and check the real activity name, then update the `import` in `RNSnapKycLivenessModule.java`                                                                      |
| `minSdk` / `compileSdk` complaint from the AAR       | Bump `compileSdkVersion` in `android/build.gradle` — do **not** lower anything else                                                                                                                                                        |

---

## 3. Install and run

```bash
adb devices                     # confirm your device is listed
npx react-native start --reset-cache      # leave running in terminal A
```

`--reset-cache` is **required** — Metro caches `.env` values and the three new `SNAPKYC_*`
flags won't be picked up otherwise.

In terminal B:

```bash
npm run android:mosip
```

---

## 4. Watch the logs

Terminal C, keep this open for the whole test:

```bash
adb logcat -c && adb logcat -s SnapKycLiveness:V ReactNativeJS:V InjiIso18013:V
```

---

## 5. The actual test

1. Open an **mso_mdoc** credential that has a `portrait`, show its QR.
2. Scan it from the verifier (Tap2iD). The **Share Information** consent sheet appears.
3. Tap **Share**.
   - The consent sheet should disappear and the **SnapKYC camera opens**.
   - The app must **not** restart to the home screen.
4. Complete the smile + blink prompts.
5. On success the response goes to the verifier and it receives the data.

### What the logs should show

```
SnapKycLiveness  Launching liveness relayingParty=SnapKYC skipFaceImage=false faceImageBytes=<n>
SnapKycLiveness  Liveness result verdict=Genuine timedOut=false hasProbeImage=true
ReactNativeJS    [DEBUG] Outgoing purposes response to verifier: ...
```

`faceImageBytes=0` means the credential portrait wasn't found — liveness will still run and
(by design) pass on the verdict alone, but the 1:1 face match is being skipped. Check that the
mdoc really has a `portrait` element.

---

## 6. Failure paths (test these too)

- **Cover the camera / press back mid-session** → retry dialog appears.
- **Retry** → SDK relaunches. This is safe: native is still parked on `consentDeferred.await()`,
  the BLE session never dropped.
- **Cancel** → `denyIso18013PresentmentConsent()` fires, verifier sees a rejection.

---

## 7. Regression check

```bash
# set SNAPKYC_LIVENESS=false in .env, then restart Metro with --reset-cache
```

Share should approve immediately, exactly as before this change. The share-with-selfie,
OpenID4VP and QR-login flows were deliberately left untouched — confirm one of them still works.

---

## Known issues to expect

- **App restarts on START.** The PR hit this; the fix already applied is launching from the
  Activity context with no `FLAG_ACTIVITY_CLEAR_TOP`. If it still happens, check that `AppTheme`
  isn't conflicting — the PR needed a Material theme (`com.google.android.material:material:1.9.0`
  is already added as a dependency).
- **SnapKYC UI is blue, not wallet-branded.** Deliberate — I skipped the PR's `colors.xml` /
  `styles.xml` overrides because they paint the app z-identity green. If you want the SDK
  restyled, port those two files from the PR and adjust the hex values.
- **`relayingPartyName` is `SnapKYC`.** Still unconfirmed with their team — that's an open item
  carried over from the original PR. A wrong tenant id may fail server-side in non-offline mode.

---

## Things I could not verify off-VPN

Only two: that the `io.ooru.biometrics` artifacts download, and everything downstream of that
(compile, install, on-device run). TypeScript, the jest suite (1345 passing), Gradle
configuration, and CameraX 1.4.1 resolution were all verified.

## Pre-existing, not mine

`components/QrCodeOverlay.test.tsx` fails 4 tests with `Element type is invalid` inside
`MdocProximityConsentOverlay` — that predates this work and lives in your uncommitted changes.
I left it alone.
