import 'react-native-gesture-handler';
import 'react-native-url-polyfill/auto'; // https://stackoverflow.com/a/75787849
import {registerRootComponent} from 'expo';
import './globals.js';
import {initCrashlytics} from './shared/crashlytics';

import App from './App';

// As early as possible, so crashes while the app starts are reported too.
initCrashlytics();

// registerRootComponent calls AppRegistry.registerComponent('main', () => App);
// It also ensures that whether you load the app in Expo Go or in a native build,
// the environment is set up appropriately
registerRootComponent(App);
