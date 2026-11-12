# reverseakamai

Pure-Rust, sandbox-free SDK for Akamai Bot Manager web challenges (`bmak` v2/v3, `SBSD`, `/akam/13/` pixel, `sec-cpt` PoW, and the BMP TLV bytecode VM).

> [!IMPORTANT]
> **Need browser or mobile automation in production?** Static solvers break as script builds, VM opcodes, and mobile BMP/BAP SDKs rotate. [**Distilled**](https://distilled.cx) runs real ARM64 Android phones in the cloud with hardware-backed device identities, mobile proxies, and API, MCP and ADB control.

## Quickstart

```rust
use akamai_solver::{AkamaiClient, Profile};
use serde_json::json;

# async fn run() -> akamai_solver::Result<()> {
let mut client = AkamaiClient::builder()
    .profile(Profile::Chrome154)
    .posts(3)
    .build()?;

let outcome = client.solve("https://www.bestbuy.com/").await?;
assert!(outcome.abck_advanced());

let search = client
    .get("https://www.bestbuy.com/site/searchpage.jsp?st=iphone")
    .await?;

let cart: serde_json::Value = client
    .post_json(
        "https://www.bestbuy.com/gateway/graphql",
        &json!({
            "operationName": "CartQuery",
            "query": "query CartQuery { customer { cart { totalQuantity } } }",
            "variables": {}
        }),
    )
    .await?
    .json()?;

let cookie_header = client.cookie_header("https://www.bestbuy.com/")?;
# Ok(())
# }
```

`AkamaiClient` maintains a persistent TLS/H2 connection pool, scoped cookie jar, and negotiated `Accept-CH` client hints across requests (`.solve()`, `.get()`, `.post()`, `.post_json()`, `.request()`, `.cookies()`, `.cookie_header()`, `.is_validated()`).

## Crates

| Crate | Description |
| --- | --- |
| `crates/solver` (`akamai-solver`) | High-level `AkamaiClient` SDK driving `sec-cpt`, Pixel, SBSD, and 3-post `bmak` challenges over `wreq` TLS/H2. |
| `crates/codec` (`akamai-codec`) | `_abck` parser, v2/v3 substitution & permutation codecs, static `bmak` (`s8` `shuffle_key` + `ver`) extractor, `BuildTemplate`, SHA-256 PoW, pixel, and BMP TLV VM disassembler/interpreter. |
| [`native-payload`](https://github.com/9xz/native-payload) | Provider-agnostic `DeviceProfile`, biometrics, order-preserving JSON template patchers, and cipher primitives. |

---

## Akamai Checks & Wire Architecture

### 1. Transport, Client Hints & Cookie Coupling
- **TLS / HTTP/2 & Header Order:** Akamai's edge (`AkamaiGHost`) fingerprints the TLS ClientHello (JA3/JA4), HTTP/2 `SETTINGS` / `WINDOW_UPDATE` / pseudo-header order, and navigation vs. XHR `Sec-Fetch-*` header order before evaluating any cookie.
- **`_abck` (`<token>~<state>~<edge_blob>~<pow>`):**
  - Field 0: 32-hex session token.
  - Field 1: challenge state (`-1` unvalidated / score-in-blob, `0` explicitly validated).
  - Field 2 (`YAAQ...`): encrypted edge-state and bot-score blob; grows as `sensor_data` posts are accepted.
  - Field 4: optional in-sensor SHA-256 PoW challenge (`<id>_<salt>_<difficulty>_...`).
- **`bm_sz` (`<token>~<blob>~<sub_key>~<int>`):**
  - Minted by the edge on the initial response. Segment 2 (`sub_key`, fallback `8888888`) seeds the 92-character substitution pass and is echoed in `v3` header field 4 (`3;0;1;<bitmask>;<sub_key>;<ver>;<timings>;<ciphertext>`).

### 2. Static Script Obfuscation (`s8` Digit Cipher & XOR String Tables)
- **`s8` Constant Table (`shuffle_key`):** Every `bmak` v3 build embeds a digit-substituted constant array `s8` containing fixed mathematical anchors (`4294967295.000000` at `s8[4]`, `8388607.000000` at `s8[6]`, `65535.000000` at `s8[8]`, and `8888888` at `s8[9]`). Recovering the 10-digit substitution map from those anchors decodes the per-build permutation seed `shuffle_key` (`jpw = s8[10]`) statically in `<0.1 ms`.
- **XOR String Tables (`ver`):** The 44-character Base64 build version token (`ver`) is stored in the script's string-table array and XORed against a 20-byte key derived from two sibling entries (`s20[k] ^ master[offset + k]`).

### 3. Two-Pass 23-Bit LCG Cipher (`v2` & `v3`)

```text
state = (state * 65793 + 4282663) & 0x7fffff
draw(state) = (state >> 8) & 0xffff
```

1. **Pass 1 — Token Permutation (`shuffle_key`):** Splits the serialized JSON body on `,` (`v2`) or `:` (`v3`) into `N` tokens and performs `N` Fisher-Yates swaps using `draw(state) % N`.
2. **Pass 2 — 92-Char ASCII Substitution (`sub_key` from `bm_sz`):** Rotates each byte in printable ASCII `32..=126` (excluding `"`, `'`, `\`) by `draw(state) % 92`, stepping the LCG on every byte.

### 4. Secondary Challenges (`SBSD`, `Pixel`, `sec-cpt`)
- **SBSD (State-Based Scraping Detection):** Script tag carrying `?v=<uuid>` (plus `&t=<token>` on active interstitials). Posts `{"body":"<cipher>"}` seeded by `bm_so` / `sbsd_o` to mint `bm_s` and `bm_sc`.
- **Pixel (`/akam/13/<hash>`):** Seeds `bazadebezolkohpepadr` in inline HTML; script path `/akam/13/<seed ^ 77>` posts `u=<encoded>&t=<sha1(seed)>` to `/akam/13/pixel_<seed ^ 77>`.
- **`sec-cpt` (`428` / `bm-verify`):** 10-round big-endian SHA-256 modulo search (`SHA256(token || ts || nonce || difficulty || candidate) % (difficulty + round) == 0`).

---

## BMP Embedded Bytecode VM (37-Opcode TLV ISA)

Embedded-VM builds ship two TLV bytecode programs inside the script:
- **Blob 0 (959 B, 382 instructions):** Defines `kT` / `Eq`, which holds **five 23-element permutation tables** (10 total 23-slot arrays across two phases) selected by 5 integer keys (`[352616518, 224802418, 349450134, 88894862, 650677942]`) to permute the 23 sensor sections before encryption.
- **Blob 1 (2,481 B, 673 instructions):** Defines the serializer (`qR`, `QO`, `CE`) and the DJB2-XOR digest function `dk(str)` (`hash = ((hash << 5) + hash) ^ charCode`, initial seed `5381`).

### Complete 37-Opcode Table (`crates/codec/src/vm.rs`)

Earlier public disassemblers desynced around offset ~520 because they treated `0x54` (`LEAVE_SCOPE`, 0 operand bytes) as a 9-byte `PUSHnum`. With exact operand widths, 100% of Blob 0 and Blob 1 disassemble and execute with zero unknown bytes:

| Opcode | Mnemonic | Operands (Big-Endian) | Stack / Execution Semantics |
| :---: | --- | --- | --- |
| `0x8f` | `Jmp` | `u32` target | Unconditional jump to byte offset `target` |
| `0xbd` | `JBool` | `u8` cond, `u32` target | Loop/boolean conditional jump |
| `0xfe` | `JTrue` | `u8` cond, `u32` target | Branch on comparison result |
| `0xe8` | `MakeFunc` | `u16` arity, `u32` entry | Push closure with parameter count `arity` at `entry` |
| `0x93` | `SetTry` | `u8` mode | Install `try / catch / finally` handlers |
| `0xd2` | `EnterScope` | — | Push lexical scope frame |
| `0x54` | `LeaveScope` | — | Pop lexical scope frame (**0 operand bytes**) |
| `0xa0` | `Ret` | — | Return top of stack from current call frame |
| `0x43` | `FnEntry` | — | Function body entry marker after parameter bindings |
| `0xfd` | `PushUndefined` | — | Push `undefined` |
| `0xff` | `PushStr` | `u16` len, `[u8; len]` | Push UTF-8 string literal / identifier |
| `0x7e` | `GetVar` | `u16` len, `[u8; len]` | Resolve variable by name in scope chain |
| `0x96` | `SetVar` | `u8` mode | Pop target reference and value; store into scope/property |
| `0x4f` | `PushU8` | `u8` val | Push 8-bit unsigned integer |
| `0x29` | `PushU32` | `u32` val | Push 32-bit unsigned integer (e.g. `5381` DJB2 seed) |
| `0xea` | `PushF64` | `f64` val | Push IEEE-754 64-bit float |
| `0x7f` | `PropGet` | `u8` mode | Property lookup (`mode=1` value, `mode=0` method receiver) |
| `0x1a` | `Call` | `u8` keep_rv, `u16` argc | Invoke function/method with `argc` arguments |
| `0x8c` | `NewArray` | `u8` len | Pop `len` `(value, 0)` pairs and construct array |
| `0x33` | `PostInc` | `u8` mode | Post-increment / decrement reference |
| `0x6a` | `Halt` | — | Terminate bytecode unit |
| `0x85` | `Add` | — | Numeric `+` or string concatenation |
| `0xd4` | `Sub` | — | `lhs - rhs` |
| `0x01` | `Mul` | — | `lhs * rhs` |
| `0xc4` | `Div` | — | `lhs / rhs` |
| `0xd7` | `Mod` | — | `lhs % rhs` |
| `0x97` | `BitXor` | — | `(lhs as i32) ^ (rhs as i32)` |
| `0xaa` | `Shl` | — | `(lhs as i32) << (rhs & 31)` |
| `0x55` | `Shr` | — | `(lhs as i32) >> (rhs & 31)` |
| `0xd5` | `Ushr` | — | `(lhs as u32) >>> (rhs & 31)` |
| `0xec` | `BitOr` | — | `(lhs as i32) \| (rhs as i32)` |
| `0x58` | `Neg` | — | `-rhs` |
| `0xed` | `BoolNot` | — | `!rhs` |
| `0xad` | `CmpLt` | — | `lhs < rhs` |
| `0xce` | `CmpLtLoop` | — | Loop bound `<` comparison |
| `0x84` | `CmpEq` | — | `lhs === rhs` |
| `0x83` | `CmpNeq` | — | `lhs !== rhs` |
| `0xa4` | `CmpType` | — | Type/undefined equality check |
| `0x6c` | `InOp` | — | `prop in obj` |

## Codec CLI

```sh
cargo test --workspace

cargo run -q -p akamai-codec -- script path/to/script.js
cargo run -q -p akamai-codec -- vm crates/codec/tests/fixtures/blob0.bin --tables
cargo run -q -p akamai-codec -- vm crates/codec/tests/fixtures/blob1.bin
cargo run -q -p akamai-codec -- pixel 1320943881
cargo run -q -p akamai-codec -- pow --token TOK --salt s --start-ts 1000 --difficulty 8 --rounds 3
cargo run -q -p akamai-codec -- bench '{"ver":"bench"}' --encode --repeat-to 4096 --sub 4000000 --shuffle 70010 --iterations 100000
```

For retail, ticketing, or social apps at scale without maintaining solvers for every build rotation or mobile BMP/BAP update, use [**distilled.cx**](https://distilled.cx): real cloud Android phones you control over API, MCP or ADB.
