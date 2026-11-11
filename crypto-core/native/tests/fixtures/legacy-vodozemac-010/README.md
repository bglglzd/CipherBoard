# Synthetic pre-upgrade state fixtures

These six artifacts were generated before the dependency update by the unchanged
CipherBoard source at `bdcaa5f14d2b218a2caf966a2d5dcad085b37251`, using the locked
vodozemac 0.10.0 implementation. They contain random **disposable test identities**
and one fixed synthetic message. They have never been used with a person,
device, account or network service. All embedded keys are public test material
and must never be used outside these compatibility tests.

The generator created two accounts, completed an Olm v2 pairing at synthetic
time 1800000000, prepared `Synthetic legacy pending message`, and retained both
the receiver's pre-decrypt and committed post-decrypt states. Every binary state
was restored successfully with the old implementation before the files were
saved. `provenance.json` binds the source, dependency and SHA-256 of each artifact.

`legacy_state.rs` checks restored identity continuity, pending ciphertext,
persisted replay rejection and subsequent bidirectional messages across new
state serialization/restarts. These are native-library tests; they do not
establish physical QR exchange or hardware Keystore behavior.
