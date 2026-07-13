# Transport parser fuzzing

This `cargo-fuzz` package targets only CipherBoard's untrusted `CB1:` transport
parser and deterministic CBOR envelope encoder. It does not fuzz or reimplement
cryptographic primitives. The target compiles the production `src/envelope.rs`
and `src/error.rs` files directly, keeping unrelated Olm and JNI code out of the
fuzz executable.

Prerequisites (pinned runner, Rust nightly required by sanitizers):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
```

Run a bounded local campaign from `crypto-core/native`:

```sh
cargo +nightly fuzz run transport_parser fuzz/corpus/transport_parser -- \
  -max_total_time=60 -max_len=32768 -timeout=5
```

On Windows, use the MSVC nightly and put Visual Studio's AddressSanitizer runtime
directory (the directory containing `clang_rt.asan_dynamic-x86_64.dll`) on
`PATH` before running the same command:

```powershell
$asan = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\*\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll" | Select-Object -Last 1
$env:PATH = "$(Split-Path $asan.FullName);$env:PATH"
cargo +nightly-x86_64-pc-windows-msvc fuzz run transport_parser fuzz\corpus\transport_parser -- -max_total_time=60 -max_len=32768 -timeout=5
```

Run longer by increasing `-max_total_time`. A crash is written under
`fuzz/artifacts/transport_parser`; preserve the artifact and reproduce it with:

```sh
cargo +nightly fuzz run transport_parser fuzz/artifacts/transport_parser/<artifact>
```

The three input modes cover arbitrary UTF-8 transport text, arbitrary decoded
CBOR bytes wrapped in strict base64url, and valid encode/decode round trips. The
harness caps allocations before constructing an encoded envelope.
