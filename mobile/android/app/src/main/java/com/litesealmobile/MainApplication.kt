package com.litesealmobile

import android.app.Application
import com.facebook.react.PackageList
import com.facebook.react.ReactApplication
import com.facebook.react.ReactHost
import com.facebook.react.ReactNativeApplicationEntryPoint.loadReactNative
import com.facebook.react.defaults.DefaultReactHost.getDefaultReactHost

class MainApplication : Application(), ReactApplication {

  override val reactHost: ReactHost by lazy {
    getDefaultReactHost(
      context = applicationContext,
      packageList =
        PackageList(this).packages.apply {
          // Legacy credentials are migrated by Kotlin/Rust only. The keychain
          // module must never offer old identity JSON to JavaScript again.
          removeAll { it is com.oblador.keychain.KeychainPackage }
          add(LitesealPathsPackage())
        },
    )
  }

  override fun onCreate() {
    super.onCreate()
    com.liteseal.NativeSecretStorage.initializeApplication(this)
    loadReactNative(this)
    com.liteseal.NativeMobileSync.initialize(this)
  }
}
