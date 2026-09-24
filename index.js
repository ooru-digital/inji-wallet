import 'react-native-gesture-handler';
import 'react-native-url-polyfill/auto'; // https://stackoverflow.com/a/75787849
import {registerRootComponent} from 'expo';
import messaging from '@react-native-firebase/messaging';
import './globals.js';

import App from './App';

// Must be registered outside of React lifecycle for Android background delivery
try {
  messaging().setBackgroundMessageHandler(async () => {});
} catch (error) {
  // Firebase may be unavailable in some environments
}

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
