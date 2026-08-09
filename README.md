# tpm23

A modern, zero-overhead C++23 Module wrapper frontend for the TPM 2.0 Enhanced System API (tss2-esys). 

The standard Trusted Computing Group stack is an over-engineered, unreadable nightmare of legacy C idioms, manual garbage collection, and dangerous type-punning. tpm23 completely eliminates this complexity. It replaces unmanaged raw pointers with strict scoped resource guards and exposes a clean, type-safe API designed for the modern C++ ecosystem. 

### Architectural Advantages

* **Strict RAII Handle Management:** No manual Esys_FlushContext tracking. Handles self-clean natively on scope exit. This prevents permanent slot lockups on the physical chip.
* **C++23 Module Architecture:** Clean translation unit boundary isolation via native modules. Includes tpm23.status, tpm23.core, tpm23.nv, and tpm23.policy.
* **Hardware Boot-State Sealing:** Locks secrets directly to Platform Configuration Registers (PCRs). It completely refuses decryption if firmware, GRUB, or Secure Boot states change.
* **Security-Hardened NVRAM Cells:** Enforces strict least-privilege PIN routing out of the box. It explicitly blocks standard Owner privilege-escalation bypass vulnerabilities.
* **Bitwise Error Diagnostics:** Translates cryptic 32-bit layered TCG hex error blocks into immediate plain text troubleshooting hints.

### Vulnerability Mitigation: The NVRAM Owner Bypass

Standard implementations often configure NVRAM storage cells using broad permissions like TPMA_NV_OWNERREAD. This introduces a severe privilege-escalation loophole where any caller with basic platform Owner authentication can bypass the index's unique user PIN entirely. 

tpm23 implements secure-by-default infrastructure. It strips out root owner overrides entirely, applying strict TPMA_NV_AUTHREAD constraints. This forces the physical hardware security processor to rigorously evaluate the cell's unique authorization key on every access request, neutralizing the bypass vector. (i actually had to deal w/ ts in testing b4 i fixed it)

### Raw C API vs. tpm23

### Sealing Data to Hardware

**The Legacy Way (Raw C API):** 

```c

TPM2B_PUBLIC parent_template = { /* ... 20 lines of template boilerplate ... */ };
ESYS_TR primary_handle = ESYS_TR_NONE;
Esys_CreatePrimary(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ..., &primary_handle, ...);
// ... tedious manual serialization layout and pointer slicing ...
*out_blob = malloc(sizeof(uint32_t) + sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC));
// ... complex error tracking and risky manual garbage collection ...
Esys_FlushContext(ctx, primary_handle);
Esys_Free(out_private);
```

**The Correct Way (tpm23):** 

```cpp

import tpm23;
import std;

// Fully safe, boundary-checked, and self-cleaning
auto encrypted_blob = pipeline.seal_secret_to_hardware(data_span);
```

### Software Requirements and Deps

The library interfaces directly with the native Linux TPM 2.0 subsystem via the Enhanced System API. 

* **Compiler:** GCC 14+ or Clang 18+ with full C++23 module support enabled.
* **System Libraries:** libtss2-esys and libtss2-mu installed via your system package manager.
* **Hardware Access:** Root/Sudo privileges or membership in the tpm system group to access /dev/tpm0.

### Building and Verification

The repository includes a deterministic dependency-mapped Makefile that handles compiling individual module interfaces in their strict linear evaluation order. 

bash

### Clone the repository

```bash
git clone https://github.com/mxreal64/tpm23.git
cd tpm23

# Compile the multi-module static library and optionally execute the hardware validation suite
make
# OR
make test
```

### License

copyright mxreal64, 2026

Licensed under the Apache License, Version 2.0 (the "License"). You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
