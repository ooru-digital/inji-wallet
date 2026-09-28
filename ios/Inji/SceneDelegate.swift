import UIKit

/**
 Owns the app's window under the UIScene lifecycle.

 iOS 27 refuses to launch apps built with the current SDK that still use the pre-scene model,
 where the AppDelegate creates and owns the window: UIKit traps at launch in
 `_UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption` (EXC_BREAKPOINT). Declaring
 `UIApplicationSceneManifest` in Info.plist and creating the window here is what opts the app in.
 Info.plist can't carry this explanation itself: the Podfile's post_install hook round-trips it
 through JSON, which strips comments.

 Adopting scenes also changes how URLs arrive. UIKit stops calling the AppDelegate's
 `application(_:open:options:)` and `application(_:continue:restorationHandler:)` and delivers
 them to this class instead, including on a cold launch, where they come in `connectionOptions`.
 Expo SDK 53's ExpoAppDelegate doesn't forward scene events to its subscribers (its source has a
 TODO where scene support would go). So every URL is routed back through the AppDelegate's
 existing handlers. That keeps a single code path for the deep-link intent store the JS side reads,
 expo-linking, Google Sign-In, and RCTLinkingManager.
 */
@objc(SceneDelegate)
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
  var window: UIWindow?

  private var appDelegate: AppDelegate? {
    UIApplication.shared.delegate as? AppDelegate
  }

  func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    guard let windowScene = scene as? UIWindowScene, let appDelegate = appDelegate else {
      return
    }

    // A cold launch from a link delivers the URL here, not in didFinishLaunching's launchOptions.
    // It's routed before React Native starts, so the intent is already stored when the JS app
    // machine reads it on first becoming active. It's also put into launchOptions because that is
    // where RCTLinkingManager's getInitialURL looks.
    var launchOptions: [UIApplication.LaunchOptionsKey: Any] = [:]
    if let urlContext = connectionOptions.urlContexts.first {
      launchOptions[.url] = urlContext.url
      if let sourceApplication = urlContext.options.sourceApplication {
        launchOptions[.sourceApplication] = sourceApplication
      }
      appDelegate.route(urlContext)
    }
    if let activity = connectionOptions.userActivities.first(where: {
      $0.activityType == NSUserActivityTypeBrowsingWeb
    }) {
      // Same shape RCTLinkingManager reads a universal-link initial URL from.
      launchOptions[.userActivityDictionary] = [
        "UIApplicationLaunchOptionsUserActivityKey": activity,
        "UIApplicationLaunchOptionsUserActivityTypeKey": activity.activityType,
      ]
      appDelegate.route(activity)
    }

    let window = UIWindow(windowScene: windowScene)
    self.window = window
    // Anything still reaching for the window through the app delegate keeps working.
    appDelegate.window = window
    appDelegate.startReactNative(in: window, launchOptions: launchOptions)
  }

  // A link opened while the app is already running.
  func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    for context in URLContexts {
      appDelegate?.route(context)
    }
  }

  // A universal link opened while the app is already running.
  func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
    appDelegate?.route(userActivity)
  }

  // MARK: - Lifecycle forwarding
  //
  // Under scenes UIKit stops calling the AppDelegate's activation and background methods, so
  // ExpoAppDelegate never passes them on to its subscribers. Nothing depends on that today: the
  // three registered subscribers (Google Sign-In, expo-linking, expo-file-system) use only the
  // URL and background-URL-session callbacks, and expo-modules-core and RN's AppState get
  // lifecycle from UIApplication notifications, which UIKit still posts. These forwards are
  // insurance for a future Expo module that subscribes to these callbacks.
  //
  // The app runs a single scene (UIApplicationSupportsMultipleScenes is false), so each
  // transition reaches Expo once. If an Expo upgrade adds its own scene forwarding, remove these
  // or subscribers will receive every transition twice.

  func sceneDidBecomeActive(_ scene: UIScene) {
    appDelegate?.applicationDidBecomeActive(UIApplication.shared)
  }

  func sceneWillResignActive(_ scene: UIScene) {
    appDelegate?.applicationWillResignActive(UIApplication.shared)
  }

  func sceneWillEnterForeground(_ scene: UIScene) {
    appDelegate?.applicationWillEnterForeground(UIApplication.shared)
  }

  func sceneDidEnterBackground(_ scene: UIScene) {
    appDelegate?.applicationDidEnterBackground(UIApplication.shared)
  }
}
