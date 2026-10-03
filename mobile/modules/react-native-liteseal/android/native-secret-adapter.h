#pragma once
#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <mutex>

// Private C ABI to Rust. This adapter has no JSI method or secret return value.
using LitesealSecretProvider = int32_t (*)(uint32_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*);
extern "C" int32_t liteseal_install_android_secret_provider(LitesealSecretProvider);
namespace liteseal_secret {
inline JavaVM* vm = nullptr;
inline jclass storage = nullptr;
inline jmethodID methods[7] = {};
inline int32_t crypt(uint32_t operation, const uint8_t* input, size_t size, uint8_t* output, size_t capacity, size_t* written) {
  if (!vm || !storage || operation < 1 || operation > 7 || size > 8 * 1024 * 1024 + (operation == 2 ? 34 : 0) || !written || (!input && size) || (!output && capacity)) return -1;
  *written = 0; JNIEnv* env = nullptr; bool attached = false;
  auto status = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  if (status == JNI_EDETACHED) { if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return -1; attached = true; }
  else if (status != JNI_OK) return -1;
  jbyteArray argument = nullptr;
  jbyteArray result = nullptr;
  int32_t code = -1;
  if (env->PushLocalFrame(4) == JNI_OK) {
    if (operation <= 2 || (operation >= 5 && operation <= 6)) {
      argument = env->NewByteArray(static_cast<jsize>(size));
      if (argument && !env->ExceptionCheck()) {
        env->SetByteArrayRegion(argument, 0, static_cast<jsize>(size), reinterpret_cast<const jbyte*>(input));
        if (!env->ExceptionCheck()) result = static_cast<jbyteArray>(env->CallStaticObjectMethod(storage, methods[operation-1], argument));
      }
    } else result = static_cast<jbyteArray>(env->CallStaticObjectMethod(storage, methods[operation-1]));
    if (!env->ExceptionCheck() && result) {
      const auto length = env->GetArrayLength(result);
      if (length >= 0 && static_cast<size_t>(length) <= capacity) {
        env->GetByteArrayRegion(result, 0, length, reinterpret_cast<jbyte*>(output));
        if (!env->ExceptionCheck()) { *written = static_cast<size_t>(length); code = 0; }
      }
    }
    // Never describe Java exceptions: legacy failures can carry credentials.
    if (env->ExceptionCheck()) env->ExceptionClear();
    for (auto bytes : {argument, result}) if (bytes) {
      const auto length = env->GetArrayLength(bytes);
      const jbyte zero[4096] = {};
      for (jsize offset = 0; offset < length;) {
        const auto count = std::min<jsize>(length - offset, sizeof(zero));
        env->SetByteArrayRegion(bytes, offset, count, zero);
        if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
        offset += count;
      }
    }
    env->PopLocalFrame(nullptr);
  } else if (env->ExceptionCheck()) env->ExceptionClear();
  if (attached) vm->DetachCurrentThread();
  return code;
}
inline bool install(JNIEnv* env) {
  static std::mutex installMutex;
  std::lock_guard<std::mutex> lock(installMutex);
  if (storage) return true;
  if (env->GetJavaVM(&vm) != JNI_OK) return false;
  auto local = env->FindClass("com/liteseal/NativeSecretStorage");
  if (!local || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
  storage = static_cast<jclass>(env->NewGlobalRef(local)); env->DeleteLocalRef(local);
  if (!storage || env->ExceptionCheck()) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (storage) env->DeleteGlobalRef(storage);
    storage = nullptr;
    return false;
  }
  const char* names[] = {"protect", "unprotect", "legacyIdentity", "clearLegacyIdentity", "readWitness", "writeWitness", "privateStorageRoot"};
  for (size_t i = 0; i < 7; ++i) {
    methods[i] = env->GetStaticMethodID(storage, names[i], i < 2 || i == 4 || i == 5 ? "([B)[B" : "()[B");
    if (!methods[i] || env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteGlobalRef(storage); storage = nullptr; return false; }
  }
  if (liteseal_install_android_secret_provider(crypt) != 0) { env->DeleteGlobalRef(storage); storage = nullptr; return false; }
  return true;
}
}
