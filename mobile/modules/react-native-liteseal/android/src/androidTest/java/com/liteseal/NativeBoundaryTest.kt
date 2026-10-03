package com.liteseal

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import android.util.Base64
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

// Run only in the library's dedicated test APK, never the installed messenger.
@RunWith(AndroidJUnit4::class)
class NativeBoundaryTest {
  private fun isolatedContext() = InstrumentationRegistry.getInstrumentation().targetContext.also {
    check(it.packageName == "com.liteseal.nativeisolatedtests")
  }
  @Test fun protectedBytesRoundTripAndTamperingIsRejected() {
    isolatedContext()
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val alias = "liteseal.native.identity.wrap.v1"
    val existed = store.containsAlias(alias)
    val original = "synthetic native fixture seal".toByteArray()
    val input = original.copyOf()
    try {
    val ciphertext = NativeSecretStorage.protect(input)
    assertTrue(input.all { it == 0.toByte() })
    assertArrayEquals(original, NativeSecretStorage.unprotect(ciphertext))
    ciphertext[ciphertext.lastIndex] = (ciphertext.last().toInt() xor 1).toByte()
    try { NativeSecretStorage.unprotect(ciphertext); fail("tampered ciphertext accepted") }
    catch (_: java.security.GeneralSecurityException) { }
    } finally { if (!existed && store.containsAlias(alias)) store.deleteEntry(alias) }
  }
  @Test fun generationalWitnessRetainsLatestPublicRecordAndRejectsAmbiguity() {
    isolatedContext()
    val binding = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val prefix = "liteseal.witness.v1." + binding.joinToString("") { "%02x".format(it.toInt() and 255) } + "."
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    try {
      assertEquals(0, NativeSecretStorage.readWitness(binding).size)
      val first = "synthetic public head 1".toByteArray()
      val second = ByteArray(4096) { (it % 251).toByte() }
      NativeSecretStorage.writeWitness(binding + first)
      assertArrayEquals(first, NativeSecretStorage.readWitness(binding))
      NativeSecretStorage.writeWitness(binding + second)
      assertArrayEquals(second, NativeSecretStorage.readWitness(binding))
      // Duplicate highest revisions fail closed; this exact random test prefix
      // is owned by this fixture and is cleaned even if the assertion fails.
      val latest = store.aliases().toList().single { it.startsWith(prefix) }
      val counter = latest.removePrefix(prefix).substringBefore('.')
      val duplicate = prefix + counter + "." + Base64.encodeToString(first, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
      val generator = javax.crypto.KeyGenerator.getInstance("AES", "AndroidKeyStore")
      generator.init(android.security.keystore.KeyGenParameterSpec.Builder(duplicate, 3)
        .setKeySize(256).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build())
      generator.generateKey()
      try { NativeSecretStorage.readWitness(binding); fail("ambiguous head accepted") }
      catch (_: IllegalStateException) { }
    } finally { store.aliases().toList().filter { it.startsWith(prefix) }.forEach { store.deleteEntry(it) } }
  }
  @Test fun privateJniWakeWithoutIdentityDoesNotCreateCredentials() {
    val context = isolatedContext()
    NativeSecretStorage.initializeApplication(context)
    val fixture = File(context.filesDir, "native-boundary-" + UUID.randomUUID()).apply { check(mkdir()) }
    try {
      assertEquals(0, NativeMobileSync.nativeSync(File(fixture, "liteseal.db").absolutePath))
      assertTrue(fixture.listFiles()!!.isEmpty())
      // A false identity-presence hint cannot turn the private worker into an
      // arbitrary-path Core factory. The native constructor checks app storage.
      val hint = File(fixture, "mobile-identity.bin")
      hint.writeText("synthetic invalid hint")
      assertEquals(-1, NativeMobileSync.nativeSync(File(fixture, "liteseal.db").absolutePath))
      assertFalse(File(fixture, "liteseal.db").exists())
      check(hint.delete())
    } finally {
      val hint = File(fixture, "mobile-identity.bin")
      if (hint.exists()) check(hint.delete())
      check(fixture.delete())
    }
  }
}
