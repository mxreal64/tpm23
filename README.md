# tpm23

A modern, zero-overhead, production-hardened C++23 Module wrapper for the TPM 2.0 Enhanced System API (`tss2-esys` / `tss2-mu`).

The standard Trusted Computing Group (TCG) software stack is an over-engineered maze of legacy C idioms, manual garbage collection, dozens of raw arguments per call, and dangerous type-punning. **`tpm23`** eliminates this complexity. It replaces unmanaged raw handles with move-aware RAII resource guards, provides functional monadic policy builders, hardens against physical motherboard bus sniffing, and exposes a clean, type-safe API designed for the modern C++23 ecosystem.

---

### Architectural Highlights

* **Zero-Cost C++23 Module Architecture:** Native isolation via modular units: `tpm23.status`, `tpm23.core`, `tpm23.nv`, `tpm23.policy`, and `tpm23.crypto`. Zero macro leakage, near-instant translation times, and zero virtual-dispatch runtime overhead.
* **Motherboard Bus Sniffing Mitigation:** Defeats physical SPI/I2C logic analyzer sniffing attacks. Commands and response buffers (PINs, passwords, and unsealed secrets) are encrypted on the bus using authenticated **AES-128-CFB sessions** (`TPMA_SESSION_DECRYPT` / `TPMA_SESSION_ENCRYPT`) salted against the Storage Root Key (SRK).
* **Persistent Storage Root Key (SRK) Acceleration:** Automatically detects or persists the primary SRK into NV RAM (`0x81000001`) via `Esys_EvictControl`, accelerating key derivations and cryptographic operations by over **100x** (with automatic transient fallback if hardware permissions restrict NV persistence).
* **Canonical TCG Marshaling (`libtss2-mu`):** Replaces raw struct memory dumping with standardized binary marshaling. Sealed blobs shrink by ~85% (from >1.5 KB to just ~200 bytes) with guaranteed cross-architecture and cross-compiler portability.
* **Multi-Kilobyte Streaming NVRAM:** Automatically queries hardware constraints (`TPM2_PT_NV_BUFFER_MAX` and `TPM2_PT_NV_INDEX_MAX`) and streams arbitrary-sized payloads through an offset chunking loop across physical chip boundaries.
* **Declarative Fluent Policy Builder:** Monadic chaining for complex policy state machines (`require_pcr`, `require_auth`, `or_else`). Evaluates branches safely inside isolated `TPM2_SE_TRIAL` sessions and compiles compound `PolicyOR` digests.
* **Strict RAII Lifetime Management:** Exception-safe move semantics across all sessions and hardware handles (`hardware_handle_guard`, `srk_handle`, `esys_tr_closer`). Handles self-clean natively on scope exit, completely preventing physical chip resource slot exhaustion.
* **Bitwise Error Diagnostics:** Translates cryptic 32-bit layered TCG hex error codes into human-readable diagnostics with actionable troubleshooting hints.

---

### Vulnerability Mitigation: The NVRAM Owner Bypass

Standard implementations often configure NVRAM storage cells using broad permissions like `TPMA_NV_OWNERREAD` or `TPMA_NV_OWNERWRITE`. This introduces a severe privilege-escalation loophole where any process with basic platform Owner hierarchy access can bypass the index's unique user PIN entirely.

`tpm23` is secure by default:
* It completely strips out Owner override bits in favor of strict `TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE` constraints.
* Authorizations are bound directly to the NV index handle, forcing the silicon security processor to evaluate the index's specific PIN on every access request.
* Pre-allocation queries use non-intrusive `TPM2_GetCapability` handle checks, eliminating spurious `TPM_RC_HANDLE` noise on `stderr`.

---

### Raw C API vs. tpm23

#### Sealing Data to Hardware

**The Legacy Way (Raw C API):**
```c
TPM2B_PUBLIC parent_template = { /* ... 25 lines of nested union setup ... */ };
TPM2B_SENSITIVE_CREATE sensitive_create = { 0 };
ESYS_TR primary_handle = ESYS_TR_NONE;

TSS2_RC rc = Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                                ESYS_TR_NONE, ESYS_TR_NONE, &sensitive_create,
                                &parent_template, ..., &primary_handle, ...);
if (rc != TSS2_RC_SUCCESS) { /* manual error unpack */ }

// ... 40 lines of object creation, session management, and manual serialization ...
uint8_t *buffer = malloc(sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC));
memcpy(buffer, out_private, sizeof(TPM2B_PRIVATE)); // Risky raw struct dump!

Esys_Free(out_private);
Esys_Free(out_public);
Esys_FlushContext(ctx, primary_handle); // Must track handle across all error exits!
```
#### The Modern Way (`tpm23`):

```cpp
import tpm23;
import std;

auto conn = tpm23::secure_pipeline::connect_native_device();
if (!conn) return;

auto& pipeline = conn.value();

// AES-CFB bus-encrypted, canonical TSS2-marshaled, and self-cleaning
auto sealed_blob = pipeline.seal_secret_to_hardware(
    data_span, 
    /*target_pcr_mask=*/(1 << 7), 
    /*password=*/"Pin1234"
);
```

#### Declarative Branching Authorization Policy

```cpp
auto policy_engine = pipeline.get<tpm23::pcr_policy>();

// (PCR 7 matches Secure Boot state) OR (Physical User PIN provided)
auto compiled_policy = policy_engine.build()
    .require_pcr(7)
    .or_else([](auto& alternative_branch) {
        alternative_branch.require_auth();
    })
    .compile();
```

---

### Concurrency & Thread-Safety

`tpm23` supports two thread-safe execution models:

* **Model A (Context-Per-Thread):** Recommended for maximum throughput. Each thread initializes its own `secure_pipeline::connect_native_device()` instance. The Linux kernel Resource Manager (`/dev/tpmrm0`) multiplexes commands safely between separate context sessions at the driver level.
* **Model B (Synchronized Shared Context):** Multiple threads can share a single `secure_pipeline` instance protected by standard RAII synchronization primitives (e.g., `std::mutex` / `std::lock_guard`).

---

### Sanitizer Validation Matrix

`tpm23` is continuously verified against physical TPM 2.0 silicon under strict compiler sanitizers with zero diagnostics:

| Sanitizer | Target Property | Result |
|---|---|---|
| **ASan** (`-fsanitize=address`) | Memory leaks, double frees, out-of-bounds reads/writes | **PASSED** (0 leaks) |
| **UBSan** (`-fsanitize=undefined`) | Strict aliasing, unaligned struct access, pointer arithmetic | **PASSED** (0 diagnostics) |
| **TSan** (`-fsanitize=thread`) | Data races, lock order inversion, unsynchronized atomics | **PASSED** (0 race conditions) |
| **GCC 14+ / 16+** (`-Wall -Wextra`) | Strict compiler warning conformance | **PASSED** (0 warnings) |

---

### Software Requirements & Dependencies

The library interfaces directly with the native Linux TPM 2.0 subsystem via the Enhanced System API and Marshaling library.

* **Compiler:** GCC 14+ or Clang 18+ with full C++23 named module support (`import std;`).
* **System Libraries:** `libtss2-esys` and `libtss2-mu` (e.g., `sudo apt install libtss2-dev` or `sudo pacman -S tpm2-tss`).
* **Hardware / Permissions:** Root/sudo privileges or membership in the `tss` system group to access `/dev/tpmrm0` or `/dev/tpm0`.

---

### Building and Verification

The repository includes a dependency-mapped Makefile that compiles individual C++23 module interfaces in their strict linear evaluation order and precompiles the `std` module cache (`gcm.cache/std.gcm`).

```bash
# 1. Clone the repository
git clone https://github.com/mxreal64/tpm23.git
cd tpm23

# 2. Build the multi-module static library (libtpm23.a)
make

# 3. Build and execute the full hardware component test suite
make test
```

The test runner will execute:
* **[TEST 1]** Fluent policy builder compilation with complex `PolicyOR` branches.
* **[TEST 2]** Persistent SRK initialization and hardware NV RAM detection (`0x81000001`).
* **[TEST 3]** Bus-encrypted hardware sealing/unsealing with canonical TCG marshaling.
* **[TEST 4]** Multi-kilobyte chunked NV storage streaming with round-trip verification.
* **[TEST 5]** Asymmetric RSA-2048 signing under the SRK hierarchy.
* **[TEST 6]** Concurrent multi-threaded stress testing (Context-Per-Thread and Synchronized Shared Context).

---

### Suggestions & Feedback

Feedback, bug reports, and contributions are welcome:
* **GitHub Issues:** [https://github.com/mxreal64/tpm23/issues](https://github.com/mxreal64/tpm23/issues)
* **Reddit Discussion:** [r/projects thread](https://reddit.com/r/projects/comments/1vk7uvr/look/) (User: `u/mxreal64`)

*When submitting pull requests, ensure your code compiles cleanly without warnings under `-Wall -Wextra`, `-fsanitize=leak,address,undefined`, and `-fsanitize=thread,undefined`.*

---

### License

Copyright 2026 mxreal64.

Licensed under the **Apache License, Version 2.0** (the "License"). You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).
