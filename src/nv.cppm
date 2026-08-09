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
#include <cstring>

export module tpm23.nv;

import tpm23.status;
import std;

export namespace tpm23 {

    class nv_storage {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;

        [[nodiscard]] static constexpr auto make_nv_handle(uint32_t index) noexcept -> TPM2_HANDLE {
            return 0x01000000 | (index & 0x00FFFFFF);
        }

    public:
        explicit nv_storage(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        [[nodiscard]] auto write_index(
            std::uint32_t index,
            std::span<const std::byte> data,
            std::string_view password = ""
        ) noexcept -> status {
            if (data.size() > 1024) [[unlikely]] {
                return status{0x0001};
            }

            TPM2_HANDLE nv_raw_handle = make_nv_handle(index);

            TPM2B_AUTH clear_auth{};
            if (!password.empty()) {
                clear_auth.size = static_cast<std::uint16_t>(password.size());
                std::memcpy(clear_auth.buffer, password.data(), password.size());
            }

            TPM2B_NV_PUBLIC nv_template{};
            nv_template.nvPublic.nvIndex = nv_raw_handle;
            nv_template.nvPublic.nameAlg = TPM2_ALG_SHA256;

            // Hardened: Removed OWNERREAD/OWNERWRITE. Strict PIN-only enforcement.
            nv_template.nvPublic.attributes = (TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE);
            nv_template.nvPublic.dataSize = static_cast<uint16_t>(data.size());

            ESYS_TR nv_handle = ESYS_TR_NONE;
            TSS2_RC rc = Esys_NV_DefineSpace(
                m_ctx, ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &clear_auth, &nv_template, &nv_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return status{rc};

            TPM2B_MAX_NV_BUFFER nv_buffer{};
            nv_buffer.size = static_cast<uint16_t>(data.size());
            std::memcpy(nv_buffer.buffer, data.data(), data.size());

            // Since we use AUTHWRITE, we authorize using the nv_handle directly
            rc = Esys_NV_Write(
                m_ctx, nv_handle, nv_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &nv_buffer, 0
            );

            Esys_TR_Close(m_ctx, &nv_handle);
            return status{rc};
        }

        [[nodiscard]] auto read_index(
            std::uint32_t index,
            std::string_view password = ""
        ) noexcept -> result<std::vector<std::byte>> {
            TPM2_HANDLE nv_raw_handle = make_nv_handle(index);

            ESYS_TR nv_handle = ESYS_TR_NONE;
            TSS2_RC rc = Esys_TR_FromTPMPublic(
                m_ctx, nv_raw_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &nv_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_AUTH clear_auth{};
            clear_auth.size = static_cast<std::uint16_t>(password.size());
            std::memcpy(clear_auth.buffer, password.data(), password.size());

            rc = Esys_TR_SetAuth(m_ctx, nv_handle, &clear_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_TR_Close(m_ctx, &nv_handle);
                return std::unexpected(status{rc});
            }

            TPM2B_NV_PUBLIC* nv_public = nullptr;
            rc = Esys_NV_ReadPublic(m_ctx, nv_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_public, nullptr);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_TR_Close(m_ctx, &nv_handle);
                return std::unexpected(status{rc});
            }
            uint16_t data_size = nv_public->nvPublic.dataSize;
            Esys_Free(nv_public);

            // Hardened: The authorizing handle (arg 2) is now nv_handle, forcing PIN evaluation!
            TPM2B_MAX_NV_BUFFER* out_buffer = nullptr;
            rc = Esys_NV_Read(
                m_ctx, nv_handle, nv_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                data_size, 0, &out_buffer
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_TR_Close(m_ctx, &nv_handle);
                return std::unexpected(status{rc});
            }

            std::vector<std::byte> content(out_buffer->size);
            std::memcpy(content.data(), out_buffer->buffer, out_buffer->size);

            Esys_Free(out_buffer);
            Esys_TR_Close(m_ctx, &nv_handle);
            return content;
        }

        [[nodiscard]] auto release_index(std::uint32_t index) noexcept -> status {
            TPM2_HANDLE nv_raw_handle = make_nv_handle(index);

            ESYS_TR nv_handle = ESYS_TR_NONE;
            TSS2_RC rc = Esys_TR_FromTPMPublic(
                m_ctx, nv_raw_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &nv_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return status{rc};

            rc = Esys_NV_UndefineSpace(
                m_ctx, ESYS_TR_RH_OWNER, nv_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE
            );

            return status{rc};
        }
    };
}
