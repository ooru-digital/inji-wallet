import React, {useEffect, useRef, useState, useCallback} from 'react';
import psl from 'psl';
import {
  View,
  ActivityIndicator,
  Alert,
  TouchableOpacity,
  Text,
  BackHandler,
} from 'react-native';
import {WebView} from 'react-native-webview';
import * as WebBrowser from 'expo-web-browser';
import {Ionicons} from '@expo/vector-icons';
import VciClient from '../shared/vciClient/VciClient';
import {Theme} from '../components/ui/styleUtils';
import {useTranslation} from 'react-i18next';
import {isAndroid, isIOS} from '../shared/constants';

const AuthWebViewScreen: React.FC<any> = ({route, navigation}) => {
  const {authorizationURL, clientId, redirectUri, controller} = route.params;
  const webViewRef = useRef<WebView>(null);
  const [showWebView, setShowWebView] = useState(false);
  const [shouldRenderWebView, setShouldRenderWebView] = useState(false);
  const {t} = useTranslation('authWebView');
  const WEBVIEW_INIT_DELAY_MS = 300;

  const hostName = new URL(authorizationURL).hostname; // example.mosip.net
  const parsed = psl.parse(hostName);
  const rootDomain = parsed.domain || hostName;
  const ALERT_TITLE = t('title', {
    wallet: 'CredIssuer Wallet',
    domain: rootDomain || 'mosip.net',
  });
  const ALERT_MESSAGE = t('message');

  const handleBackPress = useCallback(() => {
    return true;
  }, []);

  useEffect(() => {
    if (!authorizationURL || !clientId || !redirectUri) {
      console.error('Missing required parameters for authentication');
      navigation.goBack();
      return;
    }

    navigation.setOptions({gestureEnabled: false});

    const backHandler = BackHandler.addEventListener(
      'hardwareBackPress',
      handleBackPress,
    );

    Alert.alert(ALERT_TITLE, ALERT_MESSAGE, [
      {
        text: t('cancel'),
        style: 'cancel',
        onPress: () => {
          controller.CANCEL();
          navigation.goBack();
        },
      },
      {
        text: t('continue'),
        style: 'default',
        onPress: () =>
          isIOS() ? startAuthSessionOnIOS() : setShowWebView(true),
      },
    ]);

    return () => backHandler.remove();
  }, [
    authorizationURL,
    clientId,
    redirectUri,
    navigation,
    controller,
    handleBackPress,
  ]);

  useEffect(() => {
    let timeoutId: NodeJS.Timeout | null = null;

    if (isAndroid()) {
      setShouldRenderWebView(true);

      timeoutId = setTimeout(() => {
        setShouldRenderWebView(false);
      }, WEBVIEW_INIT_DELAY_MS);
    }

    return () => {
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, []);

  // Shared by both platforms: pull the authorization code out of the issuer's redirect and hand
  // it to the native layer. Android reaches here from inside the WebView, iOS from the system
  // auth session's result URL — the parsing and failure handling are identical either way.
  const completeWithRedirectUrl = (url: string) => {
    try {
      const code = new URL(url).searchParams.get('code');

      if (!code) {
        controller.CANCEL();
        navigation.goBack();
        return;
      }

      VciClient.getInstance().sendAuthCode(code);
      navigation.goBack();
    } catch (err: any) {
      console.error('Error parsing redirect URL:', err);
      controller.CANCEL();
      navigation.goBack();
    }
  };

  const handleNavigationRequest = (request: any) => {
    const {url} = request;
    if (url.startsWith(redirectUri)) {
      completeWithRedirectUrl(url);
      return false;
    }

    return true;
  };

  /**
   * iOS only. react-native-webview 16 ships no old-architecture view manager on iOS — it exports
   * `RNCWebView` solely as a Fabric component — so on Paper (newArchEnabled: false) RCTUIManager
   * has nothing registered under that name and rendering <WebView> throws
   * "No component found for view with name RNCWebView". Android is unaffected: v16 still ships
   * RNCWebViewManager.kt there, which is why the same code works on one platform and not the other.
   *
   * ASWebAuthenticationSession needs no RN view at all, and it captures the redirect by matching
   * the custom scheme (every issuer returns io.mosip.residentapp.inji://oauthredirect, registered
   * in Info.plist's CFBundleURLTypes), so the flow completes without the broken component.
   */
  const startAuthSessionOnIOS = async () => {
    try {
      const result = await WebBrowser.openAuthSessionAsync(
        authorizationURL,
        redirectUri,
      );

      if (result.type === 'success' && result.url) {
        completeWithRedirectUrl(result.url);
        return;
      }

      // 'cancel' or 'dismiss' — the user closed the sheet before authorizing.
      controller.CANCEL();
      navigation.goBack();
    } catch (err: any) {
      console.error('Error opening auth session:', err);
      controller.CANCEL();
      navigation.goBack();
    }
  };

  const renderHeader = () => (
    <View style={Theme.AuthWebViewScreenStyle.header}>
      <TouchableOpacity
        onPress={() => {
          controller.CANCEL();
          navigation.goBack();
        }}>
        <Ionicons name="arrow-back" size={24} color="black" />
      </TouchableOpacity>
      <Text style={Theme.AuthWebViewScreenStyle.headerText}>Authenticate</Text>
      <View style={{width: 24}} />
    </View>
  );

  return (
    <View style={{flex: 1}}>
      {renderHeader()}
      {shouldRenderWebView && !showWebView && (
        <WebView style={{width: 0, height: 0}} source={{uri: 'about:blank'}} />
      )}
      {showWebView && (
        <WebView
          ref={webViewRef}
          originWhitelist={['*']}
          source={{uri: authorizationURL}}
          onShouldStartLoadWithRequest={handleNavigationRequest}
          startInLoadingState
          renderLoading={() => (
            <View style={Theme.AuthWebViewScreenStyle.loader}>
              <ActivityIndicator size="large" />
            </View>
          )}
          javaScriptEnabled
          incognito
          sharedCookiesEnabled={false}
          thirdPartyCookiesEnabled={false}
        />
      )}
    </View>
  );
};

export default AuthWebViewScreen;
