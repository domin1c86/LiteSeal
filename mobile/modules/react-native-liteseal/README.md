# react-native-liteseal

Internal turbo-module exposing the shared Rust core (`liteseal-core`, built
with the `ffi` feature) to the React Native app via
[uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native).

Everything under `src/generated/`, `cpp/generated/`, `android/` (build.gradle,
CMakeLists.txt, cpp-adapter, Kotlin glue, codegen output) is **generated** —
edit `core/src/ffi.rs` and regenerate instead of editing by hand.

See `mobile/README.md` for the build pipeline.

```sh
npm run ubrn:android   # build Rust for Android ABIs + regenerate bindings
```
