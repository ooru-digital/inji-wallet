# Inji

Inji Mobile Wallet is a mobile application specifically created to streamline all types of identification and credentials into one digital wallet.
It offers a secure, trustworthy, and dependable mobile Verifiable Credentials wallet designed to fulfil the following functions

- Download and store Verifiable Credentials
- Share Verifiable Credentials
- Enable users to log in to relying parties with their credential
- Generate a QR code for the credential to be shared offline with relying parties.

for more details refer [here](https://docs.inji.io/inji-wallet/overview)

## Setup PreRequisites

Be sure to have the following build tools installed before proceeding:

- [React Native 0.74.5](https://reactnative.dev/docs/0.74/getting-started)
  - Hermes Engine enabled
- [Expo 51.0.0](https://docs.expo.dev/get-started/installation/)
- [node v18.17.1](https://nodejs.org/en/blog/release/v18.17.1)
- [npm 8.19.3](https://www.npmjs.com/package/npm/v/8.19.3)

### Android

- [Java 17](https://openjdk.org/projects/jdk/17/)
- [Gradle 8.2](https://gradle.org/install/)
- [Android SDK](https://developer.android.com/)
- minSdkVersion = 23
- compileSdkVersion = 33
- targetSdkVersion = 34
- ndkVersion = 21.4.7075529
- kotlinVersion = 1.9.0

### iOS

- [XCode](https://developer.apple.com/xcode/) = >15
- Minimum Deployment Target = 14.0
- cocoapods > 1.12
- Ruby >= 2.6.10

## Configuring the Environment

If you ever want to use something in your local environment based on your customization and in need of using environment files other than default (.env), you can add some variables to your .env.local file.
Create a `.env.local` file using `.env` as your template in your root directory :

```
# Mimoto Server
MIMOTO_HOST =  https://api.collab.mosip.net/

# ESignet Server
ESIGNET_HOST =  https://esignet.collab.mosip.net/

# Telemetry Server
OBSRV_HOST = https://dataset-api.obsrv.mosip.net
Telemetry Dashboard = https://druid.obsrv.mosip.net/unified-console.html#workbench

#Application Theme can be ( gradient | purple ), defaults to gradient theme
APPLICATION_THEME=grdaient

#environment can be changed if it is toggled
CREDENTIAL_REGISTRY_EDIT=true

#Inji Wallet CLIENT ID for Data backup & Restore
GOOGLE_ANDROID_CLIENT_ID='<client_id>'
```

for more information on the backend services
refer [here](https://docs.inji.io/inji-wallet/technical-overview/backend-services).

## Building & Running for Android

For local build, update targetSdkVersion to 33. There is some known issues in the debug build with targetSdk version = 34.

**Step 1:** Generate debug keystore for building debug build. [One time activity]

```
keytool \
 -genkey -v \
 -storetype PKCS12 \
 -keyalg RSA \
 -keysize 2048 \
 -validity 10000 \
 -storepass 'android' \
 -keypass 'android' \
 -alias androiddebugkey \
 -keystore android/app/debug.keystore \
 -dname "CN=io.mosip.residentapp,OU=,O=,L=,S=,C=US"
```

Export keystore. Run the below command in your terminal.

```
export DEBUG_KEYSTORE_ALIAS=androiddebugkey
export DEBUG_KEYSTORE_PASSWORD=android
```

**Step 2:** Clone the inji repository and create an `android/local.properties` file with the following data:

```
sdk.dir = <location-of-the-android-sdk>
```

Alternatively, you can open the Android folder in the android studio. It will create local.properties file with sdk.dir = <location-of-the-android-sdk>.

**Step 3:** Update the mimoto url and esignet host in the .env file.

- mimoto url: https://api.collab.mosip.net
- esignet host: https://esignet.collab.mosip.net

**Step 4:** Go to the root folder of the project in the terminal. Install all the dependencies using `npm install`.

**Step 5:** Build and run the application on the device:

- Run `npm run android:mosip` to build and install the application on the device.
- Run `npm run android:mosip --reset-cache` to build and install the application if any change is made in the .env file.

Note: Alternative to building and running app via react native CLI, it can be built via Android Studio. The app is available in this repository's `./android` directory. Open this directory in Android Studio (version  
4.1 and above) and the app can be built and run from there.

Refer to the documentation of Inji Wallet's [build and deployment android section](https://docs.inji.io/inji-wallet/build-and-deployment#android-build-and-run) for the steps to build the android application.

More info here:

- [Build your app using Android Studio](https://developer.android.com/studio/run)

## Building & Running for iOS

**Step 1:** Install all the dependencies

```
npm install
npx pod-install
```

**Step 2:** Run Metro bundler in the background

```
npm start
```

**Step 3:** Run Inji directly to a connected device Command to run on simulator

```
npm run ios
```

**Step 4:** Command to run real device

```
npm run ios -- --device
```

Refer to the documentation of Inji Wallet's [build and deployment iOS section](https://docs.inji.io/inji-wallet/build-and-deployment#ios-build-and-run) for detailed steps to build the iOS application.

More info here:

- [React Native - Publishing to the App Store](https://reactnative.dev/docs/publishing-to-app-store)
- [Apple Developer - Distributing Your App for Beta Testing and Releases](https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases)

### Note 

When application is built via IDE, metro need to be started manually (For instance, if building app via XCode open metro manually, as metro hook has been removed from building via XCode - [reference](https://github.com/facebook/react-native/issues/42173#issuecomment-1921091973)). 
However, if app is built via npm commands, metro starts automatically (For instance, `npm run android:mosip` or `npm run ios`)

## Known Issues

- **Terminal Configuration Error**
   
  When attempting to build the application using certain terminals via npm commands, you may encounter the following error:

    ```
    Cannot start server in new windows because no terminal app was specified, use --terminal to specify, or start a dev server manually by running npm start or yarn start in other terminal window.
    ```
  **Cause:** 
    - This issue occurs due to missing or incorrect terminal configuration or environment settings.
  
  **Workaround:**
  - Start the development server manually by running `npm start` in a separate terminal window. 

## Contributions

Please refer [here](https://docs.inji.io/inji-mobile-wallet/contribution) for contributing to Inji

## Credits

Credits listed [here](/Credits.md)

## Troubleshooting

If you can't get this to work, see the [Troubleshooting](https://reactnative.dev/docs/troubleshooting) page.

## Learn More

To learn more about React Native, take a look at the following resources:

- [React Native Website](https://reactnative.dev) - learn more about React Native.
- [Getting Started](https://reactnative.dev/docs/environment-setup) - an **overview** of React Native and how to setup your environment.
- [Learn the Basics](https://reactnative.dev/docs/getting-started) - a **guided tour** of the React Native **basics**.
- [Blog](https://reactnative.dev/blog) - read the latest official React Native **Blog** posts.
- [`@facebook/react-native`](https://github.com/facebook/react-native) - the Open Source; GitHub **repository** for  
  React Native.
