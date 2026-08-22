module.exports = {
  dependencies: {
    'react-native-vector-icons': {
      platforms: {
        ios: null,
      },
    },
    // Legacy pre-Expo-modules native packages pulled in transitively by
    // isomorphic-webcrypto (via @digitalcredentials/jsonld-signatures). Their
    // android/build.gradle uses the removed Gradle `maven` plugin and isn't
    // actually needed - isomorphic-webcrypto only uses this backend as one of
    // several JS-side fallbacks. Disable autolinking so Gradle doesn't try to
    // build them.
    '@unimodules/core': {
      platforms: {
        android: null,
      },
    },
    '@unimodules/react-native-adapter': {
      platforms: {
        android: null,
      },
    },
  },
  assets: ['./assets/images'],
};
