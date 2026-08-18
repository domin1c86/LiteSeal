# Security policy

## Dependency advisory exceptions for the Windows beta

The following RustSec findings are present in the cross-platform lockfile but
are not reachable in the Windows desktop or relay runtime. They are temporary
exceptions, not accepted production risk, and must be reviewed by **2026-09-30**.

- `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` (`quick-xml 0.39.4`) enter through
  `plist -> tauri-utils`. LiteSeal does not parse attacker-controlled XML or
  plist data at runtime; the Windows beta bundles static Tauri configuration.
  Upgrade as soon as `plist` accepts `quick-xml >= 0.41`.
- `RUSTSEC-2023-0071` (`rsa 0.9.10`) is absent from
  `cargo tree --target x86_64-pc-windows-msvc` and from the relay target. It is
  retained only by dependencies for non-Windows targets and is deferred with
  the Android milestone.

Release checks must continue to run `cargo audit` and verify these dependency
paths. Any new reachable high-severity advisory blocks the Windows beta.

## Reporting

Do not include keys, tokens, message content, or invitation codes in issue
reports or logs. Share a minimal reproduction and affected version privately
with the project maintainer.
