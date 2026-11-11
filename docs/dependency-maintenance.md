# Dependency maintenance baseline

Reviewed on 2026-11-11. The product retains minSdk 23, compile/target SDK 36,
AGP 8.13.2, Temurin 21 and its existing runtime permissions.

| Area | Selected update | Reason and boundary |
| --- | --- | --- |
| Native crypto | vodozemac 0.11.2; required Serde/JSON/zeroize pins | Published security fix; [ADR 0003](adr/0003-crypto-library-0.11.2.md) records provenance and old stored-state tests. |
| Gradle | 8.14.6, verified distribution and regenerated wrapper | Security fixes on the existing supported 8.14 line. |
| Kotlin | 2.3.21 for compiler, Compose and serialization plugins | Aligned patch update within the existing AGP compatibility range. |
| AndroidX | Core 1.18.0, Fragment 1.9.1 | Published AAR metadata fits minSdk 23 / compileSdk 36 / AGP 8.13.2. |
| Tests | Robolectric 4.17, Mockito 5.24.0, proptest 1.11.0 | Compatible test tools; Robolectric brings patched Bouncy Castle 1.85. |
| Unit-test JVM | Robolectric's documented JDK 17+ module openings | Applied only to the three Robolectric unit-test JVMs; no Android/runtime permission change. |
| Test-only Guava | 33.7.2-jre constraint in all three Robolectric modules | Robolectric 4.17 still requests affected 33.6.0-jre; the floor addresses GHSA-xxph-c9ww-hj94. It does not add Guava to APK runtime. |
| CI actions | Verified full-SHA checkout, Java, Python and CodeQL pins | Supported upstream releases; Python 3.12 and Java 21 toolchains remain selected. |

The packageable application graphs remain strictly locked. Refresh all of them
intentionally with the command in [BUILD.md](../BUILD.md), then inspect the
lockfile and SBOM. In addition to Cargo audit and dependency review, the
maintenance audit queries every Maven package/version in the app lockfile
against the public OSV database. This includes test graphs; it is not proof that
every listed package is shipped in the APK. Use Gradle `dependencyInsight` on
the exact runtime or unit-test configuration to establish that boundary.

## Deliberately deferred migrations

Newer version numbers alone are not sufficient to change platform support:

- Gradle 9 requires a coordinated AGP migration; existing deprecations and build
  behavior must be addressed in that migration rather than merging only the
  wrapper bot update.
- Kotlin 2.4 needs a newer R8 than the AGP 8.13.2 baseline supplies. Updating only
  Compose or serialization plugins also splits their versions from the compiler.
- Core 1.19.x declares compileSdk 37 / AGP 9.1; Navigation 2.10 also raises
  minSdk to 24. A grouped update cannot silently remove Android 6 support.
- Colorpicker 1.3.0 brings a newer Kotlin/Compose line whose AAR metadata requires
  SDK 37 / AGP 9.1. Keep the existing 1.1.3 until the platform migration is tested.

These constraints are recorded when resolving older dependency PRs. Their
unmerged branches are retained; supported changes are forward-ported to the
current source instead of merging stale branches wholesale.

## Verification boundaries

The library's old-state fixtures are explicitly synthetic. Android lint, unit
tests, APK policy and the existing single API 36 instrumentation suite are
separate checks. Two physical-device exchange and hardware Keystore acceptance
are not established by an emulator or by the Rust tests. This update does not
publish an APK or claim an independent applied-cryptography audit.

Primary compatibility references:

- [Gradle 8.14.6 release notes](https://docs.gradle.org/8.14.6/release-notes.html)
- [Kotlin Gradle compatibility](https://kotlinlang.org/docs/gradle-configure-project.html)
- [Android Kotlin/R8 support](https://developer.android.com/build/kotlin-support)
- [Navigation releases](https://developer.android.com/jetpack/androidx/releases/navigation)
- [Core releases](https://developer.android.com/jetpack/androidx/releases/core)
- [Fragment releases](https://developer.android.com/jetpack/androidx/releases/fragment)
- [Robolectric 4.17 metadata](https://repo.maven.apache.org/maven2/org/robolectric/robolectric/4.17/robolectric-4.17.module)
- [Robolectric JDK 17+ setup](https://robolectric.org/getting-started/#running-with-java-17-and-higher)
- [Guava advisory](https://github.com/advisories/GHSA-xxph-c9ww-hj94)
