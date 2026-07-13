## Summary

<!-- What problem does this solve? Keep the pull request to one coherent change. -->

Closes #

## Behavior and Design

<!-- Describe user-visible behavior, important implementation choices, and
failure handling. Link an ADR/design issue for protocol, permission, dependency,
or trust-boundary changes. -->

## Security and Privacy Impact

<!-- Identify affected plaintext, identity, ratchet, storage, pairing, IME,
Intent, clipboard, backup, permission, exported-component, or supply-chain
boundaries. "No impact" needs a short reason. -->

## Test Evidence

<!-- List exact commands, devices/emulators, API versions, and pass/fail results.
Use only disposable identities and synthetic content. -->

- [ ] `./scripts/build-debug.sh` or `.\scripts\build-debug.ps1`
- [ ] Relevant Rust format, Clippy, unit, property, or fuzz checks
- [ ] Relevant Android instrumentation and process-death tests
- [ ] Manual ordinary-keyboard and Secure Composer regression checks

## Documentation and Localization

- [ ] User-visible strings are present in both `values/` and `values-ru/`, or
      this change adds no user-visible string.
- [ ] Architecture, protocol, threat model, checklist, test plan, notices, and
      release documentation are updated where applicable.

## Author Checklist

- [ ] I read `CONTRIBUTING.md`, `THREAT_MODEL.md`, and the relevant architecture
      documentation.
- [ ] The change adds no runtime network path, forbidden permission, Google Play
      dependency, telemetry, advertising, or remote crash reporting.
- [ ] Secure plaintext cannot reach host input, clipboard, logs, Intent extras,
      saved state, learning, backup, notifications, filenames, or test output.
- [ ] Ratchet/replay/pending state remains atomic across failure and retry, or
      this change does not affect those transitions.
- [ ] Exported components, parser limits, backup rules, Keystore policy, and
      release ABI/signing policy remain fail-closed.
- [ ] New dependencies are exact-versioned, locked, licensed, documented, and
      included in security/SBOM review, or no dependency was added.
- [ ] The pull request contains no real messages, QR payloads, full fingerprints,
      Safety Numbers, keys, session state, Vault data, signing material, APKs,
      or unrelated formatting changes.
- [ ] I have described remaining limitations without absolute security claims.
