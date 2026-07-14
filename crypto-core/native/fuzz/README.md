# Transport parser fuzzing

This `cargo-fuzz` package targets CipherBoard's untrusted `CB1:` and `CBW1`
transport presentation parsers and deterministic envelope encoders. It does not fuzz or reimplement
cryptographic primitives. The target compiles the production `src/envelope.rs`,
`src/presentation.rs`, and `src/error.rs` files directly, keeping unrelated Olm and JNI code out of the
fuzz executable.

Prerequisites (pinned runner, Rust nightly required by sanitizers):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
```

Run a bounded local campaign from `crypto-core/native`:

```sh
cargo +nightly fuzz run transport_parser fuzz/corpus/transport_parser -- \
  -max_total_time=60 -max_len=393216 -timeout=5
```

On Windows, use the MSVC nightly and put Visual Studio's AddressSanitizer runtime
directory (the directory containing `clang_rt.asan_dynamic-x86_64.dll`) on
`PATH` before running the same command:

```powershell
$asan = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll" | Select-Object -Last 1
$env:PATH = "$(Split-Path $asan.FullName);$env:PATH"
cargo +nightly-x86_64-pc-windows-msvc fuzz run transport_parser fuzz\corpus\transport_parser -- -max_total_time=60 -max_len=393216 -timeout=5
```

Run longer by increasing `-max_total_time`. A crash is written under
`fuzz/artifacts/transport_parser`; preserve the artifact and reproduce it with:

```sh
cargo +nightly fuzz run transport_parser fuzz/artifacts/transport_parser/<artifact>
```

The five input modes cover arbitrary `CB1` text, arbitrary decoded CBOR,
valid envelope round trips, arbitrary UTF-8 word text, and valid word-presentation round trips. The
harness caps allocations before constructing an encoded envelope.
