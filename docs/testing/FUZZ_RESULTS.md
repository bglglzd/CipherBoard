# Transport Parser Fuzz Evidence

Date: 2026-07-14

Target: `crypto-core/native/fuzz/fuzz_targets/transport_parser.rs`

The target compiles the production transport envelope and presentation parsers
from `crypto-core/native/src/envelope.rs` and `presentation.rs`. It exercises
arbitrary UTF-8 `CB1:`/word-like input, arbitrary canonical-CBOR candidates,
valid envelope round trips, and valid Russian/English word-presentation round
trips. Input and allocation sizes are bounded.

## Campaign

- Runner: `cargo-fuzz 0.13.2`, libFuzzer with AddressSanitizer
- Toolchain: Rust nightly, `x86_64-pc-windows-msvc`
- Seed corpus: 9 checked-in cases
- Limits: `max_len=393216`, per-input timeout 5 seconds
- Duration: 61 seconds
- Executions: 236,453
- Coverage counters: 1,141
- Features: 3,089
- Peak RSS: 596 MB
- Crashes: 0
- Timeouts: 0
- Artifacts: 0

Reproduction from `crypto-core/native`:

```text
cargo +nightly-x86_64-pc-windows-msvc fuzz run transport_parser fuzz/corpus/transport_parser -- -max_total_time=60 -max_len=393216 -timeout=5
```

The generated corpus was kept outside the repository; the nine reviewed seeds remain after the
bounded campaign. A longer independent campaign and additional platforms are
still recommended before high-risk use. Absence of a crash in this campaign
does not prove the parser is free of vulnerabilities.
