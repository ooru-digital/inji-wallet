package io.mosip.residentapp;
import expo.modules.ApplicationLifecycleDispatcher;
import expo.modules.ExpoReactHostFactory;
import expo.modules.ReactNativeHostWrapper;

import android.app.Application;
import android.content.res.Configuration;

import com.facebook.react.PackageList;
import com.facebook.react.ReactApplication;
import com.facebook.react.ReactHost;
import com.facebook.react.ReactNativeHost;
import com.facebook.react.ReactPackage;
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint;
import com.facebook.react.defaults.DefaultReactNativeHost;
import com.facebook.react.soloader.OpenSourceMergedSoMapping;
import com.facebook.soloader.SoLoader;
import timber.log.Timber;
import java.util.List;

import io.mosip.residentapp.jsonld.BundledJsonLdDocumentLoader;

public class MainApplication extends Application implements ReactApplication {
  private final ReactNativeHost mReactNativeHost =
    new ReactNativeHostWrapper(this, new DefaultReactNativeHost(this) {
    @Override
    public boolean getUseDeveloperSupport() {
      return BuildConfig.DEBUG;
    }

    @Override
    protected List<ReactPackage> getPackages() {
      @SuppressWarnings("UnnecessaryLocalVariable")
      List<ReactPackage> packages = new PackageList(this).getPackages();
      // Packages that cannot be autolinked yet can be added manually here, for example:
      packages.add(new InjiPackage());
      return packages;
    }

    @Override
    protected String getJSMainModuleName() {
      return "index";
    }
   @Override
    protected boolean isNewArchEnabled() {
      return BuildConfig.IS_NEW_ARCHITECTURE_ENABLED;
    }
    @Override
    protected Boolean isHermesEnabled() {
      return BuildConfig.IS_HERMES_ENABLED;
    }    
  });

  @Override
  public ReactNativeHost getReactNativeHost() {
    return mReactNativeHost;
  }

  // ReactApplication.getReactHost() has no default in this RN 0.79.6 / Expo 53 combination — RN's
  // own template builds one via DefaultReactHost.getDefaultReactHost(context, ReactNativeHost),
  // but that call requires a plain ReactNativeHost, and mReactNativeHost is wrapped in Expo's
  // ReactNativeHostWrapper. Left unoverridden, Expo's ReactActivityDelegateWrapper reads this as
  // null and MainActivity crashes with "createSurface on a null object reference" the instant new
  // architecture tries to load the app. ExpoReactHostFactory (RN-0.78+-specific under
  // node_modules/expo/android/src/rn78) is Expo's own equivalent — it explicitly requires (and
  // this app already has) a ReactNativeHostWrapper, not a plain ReactNativeHost.
  @Override
  public ReactHost getReactHost() {
    return ExpoReactHostFactory.createFromReactNativeHost(this, mReactNativeHost);
  }

  @Override
  public void onCreate() {
    super.onCreate();
    // RN 0.76+ ships several small native libraries (e.g. react_featureflagsjni) merged into
    // libreactnative.so rather than built standalone (Android-autolinking.cmake's
    // REACTNATIVE_MERGED_SO=true). SoLoader.init's old (Context, boolean) overload has no way
    // to know that, so a plain `SoLoader.loadLibrary("react_featureflagsjni")` call — which
    // Expo 53's ReactActivityDelegateWrapper makes unconditionally on every launch, reading
    // ReactNativeFeatureFlags before this app's own newArch check even runs — looks for a
    // standalone libreact_featureflagsjni.so that no longer exists, crashing with
    // "UnsatisfiedLinkError: couldn't find DSO to load". OpenSourceMergedSoMapping is RN's own
    // shipped mapping (ReactAndroid/soloader/OpenSourceMergedSoMapping.kt) redirecting exactly
    // this set of merged libraries to their real file.
    // Application.onCreate() can't declare `throws IOException`, and SoLoader failing to load
    // its native libraries here is unrecoverable regardless — same treatment RN's own template
    // uses for this call.
    try {
      SoLoader.init(this, OpenSourceMergedSoMapping.INSTANCE);
    } catch (java.io.IOException e) {
      throw new RuntimeException("Failed to initialize SoLoader", e);
    }

    if (BuildConfig.IS_NEW_ARCHITECTURE_ENABLED) {
      // If you opted-in for the New Architecture, we load the native entry point for this app.
      DefaultNewArchitectureEntryPoint.load();
    }


    if (BuildConfig.DEBUG) {
      Timber.plant(new Timber.DebugTree());
    }
    BundledJsonLdDocumentLoader.install(this);
    ApplicationLifecycleDispatcher.onApplicationCreate(this);
  }

  @Override
  public void onConfigurationChanged(Configuration newConfig) {
    super.onConfigurationChanged(newConfig);
    ApplicationLifecycleDispatcher.onConfigurationChanged(this, newConfig);
  }
}
