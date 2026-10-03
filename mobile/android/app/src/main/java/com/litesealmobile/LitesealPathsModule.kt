package com.litesealmobile

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.uimanager.ViewManager

// Exposes the app's private files directory so the shared Rust core can
// place its SQLite database there.
class LitesealPathsModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext), LifecycleEventListener {

  init {
    com.liteseal.NativeSecretStorage.initialize(reactContext)
    reactContext.addLifecycleEventListener(this)
  }
  override fun onHostResume() = com.liteseal.NativeMobileSync.foreground(reactContext, true)
  override fun onHostPause() = com.liteseal.NativeMobileSync.foreground(reactContext, false)
  override fun onHostDestroy() = com.liteseal.NativeMobileSync.foreground(reactContext, false)
  override fun invalidate() { reactContext.removeLifecycleEventListener(this); super.invalidate() }

  override fun getName() = "LitesealPaths"

  override fun getConstants(): Map<String, Any> =
    mapOf("filesDir" to reactContext.filesDir.absolutePath)
}

class LitesealPathsPackage : ReactPackage {
  override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
    listOf(LitesealPathsModule(reactContext))

  override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> =
    emptyList()
}
