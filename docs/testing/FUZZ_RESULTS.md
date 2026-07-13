# Transport Parser Fuzz Evidence

Date: 2026-07-13

Target: `crypto-core/native/fuzz/fuzz_targets/transport_parser.rs`

The target compiles the production transport envelope parser and encoder from
`crypto-core/native/src/envelope.rs`. It exercises arbitrary UTF-8 `CB1:`
input, arbitrary canonical-CBOR candidates wrapped in strict base64url, and
valid encode/decode round trips. Input and allocation sizes are bounded.

## Campaign

- Runner: `cargo-fuzz 0.13.2`, libFuzzer with AddressSanitizer
- Toolchain: Rust nightly, `x86_64-pc-windows-msvc`
- Seed corpus: 3 checked-in cases
- Limits: `max_len=32768`, per-input timeout 5 seconds
- Duration: 31 seconds
- Executions: 601,574
- Coverage counters: 776
- Features: 2,384
- Peak RSS: 744 MB
- Crashes: 0
- Timeouts: 0

Reproduction from `crypto-core/native`:

```text
cargo +nightly-x86_64-pc-windows-msvc fuzz run transport_parser fuzz/corpus/transport_parser -- -max_total_time=60 -max_len=32768 -timeout=5
```

The generated corpus was reduced back to the three reviewed seeds after the
bounded campaign. A longer independent campaign and additional platforms are
still recommended before high-risk use. Absence of a crash in this campaign
does not prove the parser is free of vulnerabilities.
