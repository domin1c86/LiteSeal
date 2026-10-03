package com.liteseal

import android.content.Context
import androidx.work.*
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.io.File

// Native lifecycle and wake-up only. No React/JS methods or WorkData secrets.
object NativeMobileSync {
  private const val PERIODIC = "liteseal.native.sync.periodic.v1"
  private const val WAKE = "liteseal.native.sync.wake.v1"
  private val active = AtomicBoolean(false)
  init { System.loadLibrary("react-native-liteseal") }
  private external fun nativeForeground(value: Boolean)
  @JvmName("nativeSync") internal external fun nativeSync(path: String): Int
  private fun constraints() = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED)
    .setRequiresStorageNotLow(true).build()
  fun foreground(context: Context, value: Boolean) {
    active.set(value); nativeForeground(value)
    if (!value) wake(context)
  }
  fun initialize(context: Context) {
    WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP,
      PeriodicWorkRequestBuilder<NativeMessageSyncWorker>(15, TimeUnit.MINUTES)
        .setConstraints(constraints()).setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build())
  }
  // A future push adapter may only call this wake-up, never submit a body/key.
  fun wake(context: Context) {
    WorkManager.getInstance(context).enqueueUniqueWork(WAKE, ExistingWorkPolicy.KEEP,
      OneTimeWorkRequestBuilder<NativeMessageSyncWorker>().setConstraints(constraints())
        .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build())
  }
  internal fun isForeground() = active.get()
}
class NativeMessageSyncWorker(context: Context, parameters: WorkerParameters) : Worker(context, parameters) {
  override fun doWork(): Result {
    if (isStopped || NativeMobileSync.isForeground()) return Result.success()
    if (!File(applicationContext.filesDir, "mobile-identity.bin").isFile) return Result.success()
    return try {
      if (NativeMobileSync.nativeSync(File(applicationContext.filesDir, "liteseal.db").absolutePath) == 0)
        Result.success() else Result.retry()
    } catch (_: Exception) { Result.retry() }
  }
}
