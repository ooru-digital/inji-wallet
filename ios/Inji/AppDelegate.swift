import Expo
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@objc(AppDelegate)
class AppDelegate: ExpoAppDelegate {
  var window: UIWindow?

  private var reactNativeDelegate: ReactNativeDelegate?
  private var reactNativeFactory: RCTReactNativeFactory?

  private enum LinkedURLScheme {
    case inji
    case openID4VP
    case unknown
  }

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    let factory = ExpoReactNativeFactory(delegate: delegate)
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory
    bindReactNativeFactory(factory)

    // No window here. Under the UIScene lifecycle (required from iOS 27) the window belongs to a
    // scene, which doesn't exist yet at this point. SceneDelegate creates it and calls
    // startReactNative(in:launchOptions:) below.
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  /// Mounts React Native into the scene's window. Called once by SceneDelegate when the scene connects.
  func startReactNative(
    in window: UIWindow,
    launchOptions: [UIApplication.LaunchOptionsKey: Any]
  ) {
    reactNativeFactory?.startReactNative(
      withModuleName: "main",
      in: window,
      initialProperties: [:],
      launchOptions: launchOptions
    )
  }

  /// Routes a scene-delivered URL through the existing open-URL handler below, so scene and
  /// pre-scene delivery share one path.
  func route(_ urlContext: UIOpenURLContext) {
    var options: [UIApplication.OpenURLOptionsKey: Any] = [
      .openInPlace: urlContext.options.openInPlace,
    ]
    if let sourceApplication = urlContext.options.sourceApplication {
      options[.sourceApplication] = sourceApplication
    }
    if let annotation = urlContext.options.annotation {
      options[.annotation] = annotation
    }
    _ = application(UIApplication.shared, open: urlContext.url, options: options)
  }

  /// Routes a scene-delivered universal link through the existing user-activity handler below.
  func route(_ userActivity: NSUserActivity) {
    _ = application(UIApplication.shared, continue: userActivity, restorationHandler: { _ in })
  }

  // Linking API. Under the UIScene lifecycle UIKit no longer calls this directly;
  // SceneDelegate reaches it through route(_: UIOpenURLContext).
  override func application(
    _ app: UIApplication,
    open url: URL,
    options: [UIApplication.OpenURLOptionsKey: Any] = [:]
  ) -> Bool {
    handleIntent(url)
    return super.application(app, open: url, options: options)
      || RCTLinkingManager.application(app, open: url, options: options)
  }

  private func handleIntent(_ url: URL) {
    switch linkedScheme(for: url) {
    case .inji:
      IntentData.shared.setQrData(url.absoluteString)
    case .openID4VP:
      IntentData.shared.setOvpQrData(url.absoluteString)
    case .unknown:
      break
    }
  }

  private func linkedScheme(for url: URL) -> LinkedURLScheme {
    switch url.scheme {
    case "io.mosip.residentapp.inji":
      return .inji
    case "openid4vp":
      return .openID4VP
    default:
      return .unknown
    }
  }

  // Universal Links. Reached through route(_: NSUserActivity) from SceneDelegate, as above.
  override func application(
    _ application: UIApplication,
    continue userActivity: NSUserActivity,
    restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void
  ) -> Bool {
    let result = RCTLinkingManager.application(
      application,
      continue: userActivity,
      restorationHandler: restorationHandler
    )
    return super.application(application, continue: userActivity, restorationHandler: restorationHandler) || result
  }
}

class ReactNativeDelegate: ExpoReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? {
    bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    return RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: ".expo/.virtual-metro-entry")
#else
    return Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
