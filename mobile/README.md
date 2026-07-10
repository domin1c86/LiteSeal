# LiteSeal Mobile (Android · React Native)

React Native 0.86 Android client sharing the Rust core (`liteseal-core`) with the
desktop app via UniFFI. 安卓客户端，通过 UniFFI 与桌面端共享 Rust 业务核心。

```
mobile/
├── src/                          # app UI (screens, theme, navigation)
├── modules/react-native-liteseal # turbo-module wrapping liteseal-core
│   ├── ubrn.config.yaml          # uniffi-bindgen-react-native config
│   ├── src/generated/            # generated TS bindings (committed)
│   ├── cpp/generated/            # generated C++ bindings (committed)
│   └── android/                  # generated gradle/CMake/Kotlin glue (committed)
└── android/                      # app shell
```

## Prerequisites 构建环境

- Node ≥ 22, JDK 17, Android Studio with SDK + **NDK 27+** and an emulator/device.
- Rust with Android targets and cargo-ndk:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
export ANDROID_HOME=~/Android/Sdk          # or your SDK path
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
```

> **libsodium note 注意:** `libsodium-sys` builds libsodium from source with
> autotools, which needs a Unix-ish shell (make, autoconf). Building the Rust
> `.a` files works out of the box in WSL/Linux/macOS with the NDK installed;
> on native Windows either use WSL for step 2 below (the produced
> `jniLibs/*.a` are portable) or install a prebuilt Android libsodium and set
> `SODIUM_LIB_DIR`/`SODIUM_INCLUDE_DIR` per target.

## Build & run 构建运行

```sh
# 1. install JS dependencies
cd mobile && npm install

# 2. build the Rust core for Android + regenerate bindings
#    (produces android/src/main/jniLibs/{arm64-v8a,x86_64}/libliteseal_core.a)
cd modules/react-native-liteseal
npm run ubrn:android

# 3. run the app (Metro + gradle) with an emulator running
cd ../..
npm run android
```

The relay server on the host machine is reachable from the emulator at
`http://10.0.2.2:3000` (use that as the Server URL on the login screen).
模拟器中访问宿主机服务器请使用 `10.0.2.2`。

## Regenerating bindings 重新生成绑定

After changing the FFI surface in `core/src/ffi.rs`:

- `npm run ubrn:android` inside `modules/react-native-liteseal` rebuilds and
  regenerates everything, or, without an NDK (host-only check):

```sh
cargo build -p liteseal-core --features ffi        # from the repo root
./mobile/modules/react-native-liteseal/node_modules/.bin/ubrn \
  generate jsi bindings target/debug/libliteseal_core.so --library \
  --ts-dir mobile/modules/react-native-liteseal/src/generated \
  --cpp-dir mobile/modules/react-native-liteseal/cpp/generated
cd mobile/modules/react-native-liteseal && npx ubrn generate jsi turbo-module liteseal_core --config ubrn.config.yaml
```

If `codegenConfig` in the module's package.json changes, refresh the committed
codegen output: `npx react-native codegen --path . --platform android --source library`.

## Version pinning 版本锁定

`uniffi-bindgen-react-native` (0.31.x) pins `uniffi = 0.31.0`; the same version
is pinned in `core/Cargo.toml`. Upgrade both together.
