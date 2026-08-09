/*
 * Copyright 2026 Your Name
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://apache.org
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EXPRESS OR implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

module;

#include <tss2/tss2_esys.h>

export module tpm23.status;

import std;

export namespace tpm23 {

    struct status {
        TSS2_RC raw_code = TSS2_RC_SUCCESS;

        [[nodiscard]] constexpr bool ok() const noexcept {
            return raw_code == TSS2_RC_SUCCESS;
        }

        [[nodiscard]] std::string verbose_explain() const noexcept {
            if (ok()) return "TPM_SUCCESS: Operation executed securely.";

            // Custom high-level developer errors
            if (raw_code == 0x0001) return "TPM_FRONTEND_ERROR: Plaintext payload size exceeds the 128-byte hardware constraint.";
            if (raw_code == 0x0002) return "TPM_FRONTEND_ERROR: Serialized data blob is corrupted or too short.";
            if (raw_code == 0x0003) return "TPM_FRONTEND_ERROR: Input payload structure size fields mismatch underlying buffer allocation.";

            // Unpack standard TCG Layered Error Codes
            uint32_t layer = (raw_code >> 16) & 0xFF;
            uint32_t error = raw_code & 0xFFFF;

            // Helpful human-readable hints for common infrastructure pain points
            std::string hint = "";
            if (layer == 0x0 && error == 0x14B) {
                hint = " (Hint: Initialization failed. Ensure your app runs as administrator/root or the tpm0 device context is accessible.)";
            } else if (error == 0x9A) {
                hint = " (Hint: Authorization failed. Check that the auth parameters match the parent storage context hierarchy rules.)";
            }

            return std::format("TPM_ERROR [0x{:X}]: Layer 0x{:X} reported internal breakdown 0x{:X}.{}",
                               raw_code, layer, error, hint);
        }
    };

    template <typename T>
    using result = std::expected<T, status>;
}
