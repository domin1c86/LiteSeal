package com.liteseal

import android.security.keystore.KeyGenParameterSpec
import android.content.Context
import android.security.keystore.KeyProperties
import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Callback
import com.facebook.react.bridge.PromiseImpl
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.oblador.keychain.KeychainModule
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// No ReactModule, ReactMethod or JSI export. Called only by the native adapter.
object NativeSecretStorage {
  private const val ALIAS = "liteseal.native.identity.wrap.v1"
  private const val LIMIT = 8 * 1024 * 1024
  private val magic = "LSAK01".toByteArray(Charsets.US_ASCII)
  private val aad = "LiteSeal/Android/native-secret/v1".toByteArray(Charsets.US_ASCII)
  @Volatile private var context: ReactApplicationContext? = null
  @Volatile private var application: Context? = null

  @JvmStatic fun initialize(value: ReactApplicationContext) { context = value; initializeApplication(value) }
  fun initializeApplication(value: Context) { application = value.applicationContext }
  @JvmStatic fun privateStorageRoot(): ByteArray = checkNotNull(application).filesDir.canonicalPath.toByteArray(Charsets.UTF_8)
  @Synchronized private fun key(create: Boolean): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (store.containsAlias(ALIAS)) return store.getKey(ALIAS, null) as SecretKey
    check(create) { "native wrapping key unavailable" }
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
    return generator.generateKey()
  }
  @JvmStatic fun protect(plain: ByteArray): ByteArray {
    require(plain.size <= LIMIT)
    try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, key(true)); cipher.updateAAD(aad)
      check(cipher.iv.size == 12)
      return magic + cipher.iv + cipher.doFinal(plain)
    } finally { plain.fill(0) }
  }
  @JvmStatic fun unprotect(ciphertext: ByteArray): ByteArray {
    require(ciphertext.size in 34..(LIMIT + 34) && ciphertext.copyOfRange(0, 6).contentEquals(magic))
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, ciphertext, 6, 12)); cipher.updateAAD(aad)
    return cipher.doFinal(ciphertext, 18, ciphertext.size - 18)
  }
  private fun legacy(reset: Boolean): ByteArray {
    val reactContext = checkNotNull(context) { "native legacy context unavailable" }
    val done = CountDownLatch(1); val result = AtomicReference<ByteArray?>(null)
    val failed = AtomicReference(false)
    val options = Arguments.createMap().apply { putString("service", "liteseal.keystore") }
    val module = KeychainModule(reactContext)
    val promise = PromiseImpl(Callback { values ->
      try {
        if (!reset) {
          val value = values.firstOrNull()
          if (value is ReadableMap) result.set(checkNotNull(value.getString("password")).toByteArray(Charsets.UTF_8))
          else result.set(ByteArray(0))
        } else result.set(ByteArray(0))
      } catch (_: Exception) { failed.set(true) } finally { done.countDown() }
    }, Callback { failed.set(true); done.countDown() })
    try {
      if (reset) module.resetGenericPasswordForOptions(options, promise)
      else module.getGenericPasswordForOptions(options, promise)
      check(done.await(10, TimeUnit.SECONDS) && !failed.get()) { "native legacy operation unavailable" }
      val bytes = checkNotNull(result.get()); require(bytes.size <= 64 * 1024); return bytes
    } finally { module.invalidate() }
  }
  @JvmStatic fun legacyIdentity(): ByteArray = legacy(false)
  @JvmStatic fun clearLegacyIdentity(): ByteArray = legacy(true)

  private data class Witness(val alias: String, val revision: Long, val value: ByteArray)
  private fun witnesses(store: KeyStore, binding: ByteArray): List<Witness> {
    require(binding.size == 32)
    val prefix = "liteseal.witness.v1." + binding.joinToString("") { "%02x".format(it.toInt() and 255) } + "."
    val owned = store.aliases().toList().filter { it.startsWith(prefix) }
    check(owned.size <= 32) { "native witness ledger unavailable" }
    val records = owned.map { alias ->
      val parts = alias.removePrefix(prefix).split('.', limit = 2)
      check(parts.size == 2)
      val revision = parts[0].toLong(); check(revision in 1..1_000_000_000)
      check(parts[0] == revision.toString())
      val value = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
      check(value.size in 1..4096)
      check(Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) == parts[1])
      Witness(alias, revision, value)
    }
    check(records.groupBy { it.revision }.all { (_, same) -> same.size == 1 })
    return records.sortedBy { it.revision }
  }
  // Witness values contain only a public state digest/marker/journal digest.
  // Keeping this small record in a generational key alias makes SQLite and
  // app-file rollback detectable without a rollbackable preference counter.
  @Synchronized @JvmStatic fun readWitness(binding: ByteArray): ByteArray {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return witnesses(store, binding).lastOrNull()?.value ?: ByteArray(0)
  }
  @Synchronized @JvmStatic fun writeWitness(input: ByteArray): ByteArray {
    require(input.size in 33..4128)
    val binding = input.copyOfRange(0, 32); val value = input.copyOfRange(32, input.size)
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val prior = witnesses(store, binding)
    val revision = (prior.lastOrNull()?.revision ?: 0) + 1; check(revision <= 1_000_000_000)
    val alias = "liteseal.witness.v1." + binding.joinToString("") { "%02x".format(it.toInt() and 255) } + "." + revision + "." +
      Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
    generator.generateKey()
    // Unknown write results retain the highest record. Create precedes cleanup;
    // a power loss may leave older aliases, which never become the current head.
    check(witnesses(store, binding).last().value.contentEquals(value))
    prior.forEach { try { store.deleteEntry(it.alias) } catch (_: Exception) { /* bounded stale ledger */ } }
    return ByteArray(0)
  }
}
