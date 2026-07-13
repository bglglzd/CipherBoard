-dontoptimize

# Debug-only contracts called from the separately shrunk instrumentation APK.
-keep class helium314.keyboard.secure.testfixture.ProcessTextHostActivity { *; }
-keep class org.cipherboard.securestorage.VaultRecordStore { *; }
