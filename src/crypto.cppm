/*
 * Copyright 2026 mxreal64
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
#include <tss2/tss2_mu.h>
#include <cstring>

export module tpm23.crypto;

import tpm23.status;
import std;

export namespace tpm23 {

    struct signature_pair {
        std::vector<std::byte> private_blob;
        std::vector<std::byte> public_blob;
    };

    class key_engine {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;

    public:
        explicit key_engine(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        [[nodiscard]] auto generate_signing_key(ESYS_TR parent_handle) noexcept -> result<signature_pair> {
            TPM2B_SENSITIVE_CREATE object_sensitive{};
            TPM2B_DATA outside_info{};
            TPML_PCR_SELECTION pcr_selection{};
            pcr_selection.count = 0;

            TPM2B_PUBLIC object_template{};
            object_template.publicArea.type = TPM2_ALG_RSA;
            object_template.publicArea.nameAlg = TPM2_ALG_SHA256;
            object_template.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_SIGN_ENCRYPT |
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN);

            object_template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
            object_template.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
            object_template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
            object_template.publicArea.parameters.rsaDetail.keyBits = 2048;
            object_template.publicArea.parameters.rsaDetail.exponent = 0;

            TPM2B_PRIVATE* out_private = nullptr;
            TPM2B_PUBLIC* out_public = nullptr;

            TSS2_RC rc = Esys_Create(
                m_ctx, parent_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &object_sensitive, &object_template, &outside_info, &pcr_selection,
                &out_private, &out_public, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> priv_bytes(sizeof(TPM2B_PRIVATE));
            std::size_t priv_offset = 0;
            rc = Tss2_MU_TPM2B_PRIVATE_Marshal(
                out_private,
                reinterpret_cast<uint8_t*>(priv_bytes.data()),
                                               priv_bytes.size(),
                                               &priv_offset
            );
            Esys_Free(out_private);
            if (rc != TSS2_RC_SUCCESS) {
                Esys_Free(out_public);
                return std::unexpected(status{rc});
            }
            priv_bytes.resize(priv_offset);

            std::vector<std::byte> pub_bytes(sizeof(TPM2B_PUBLIC));
            std::size_t pub_offset = 0;
            rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
                out_public,
                reinterpret_cast<uint8_t*>(pub_bytes.data()),
                                              pub_bytes.size(),
                                              &pub_offset
            );
            Esys_Free(out_public);
            if (rc != TSS2_RC_SUCCESS) return std::unexpected(status{rc});
            pub_bytes.resize(pub_offset);

            return signature_pair{ .private_blob = std::move(priv_bytes), .public_blob = std::move(pub_bytes) };
        }

        [[nodiscard]] auto sign_hash(
            ESYS_TR loaded_key_handle,
            std::span<const std::byte, 32> sha256_digest
        ) noexcept -> result<std::vector<std::byte>> {
            TPM2B_DIGEST digest{};
            digest.size = 32;
            std::memcpy(digest.buffer, sha256_digest.data(), 32);

            TPMT_SIG_SCHEME in_scheme{};
            in_scheme.scheme = TPM2_ALG_RSASSA;
            in_scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

            TPMT_TK_HASHCHECK validation{};
            validation.tag = TPM2_ST_HASHCHECK;
            validation.hierarchy = TPM2_RH_NULL;
            validation.digest.size = 0;

            TPMT_SIGNATURE* signature = nullptr;
            TSS2_RC rc = Esys_Sign(
                m_ctx, loaded_key_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &digest, &in_scheme, &validation, &signature
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> raw_signature(signature->signature.rsassa.sig.size);
            std::memcpy(raw_signature.data(), signature->signature.rsassa.sig.buffer, signature->signature.rsassa.sig.size);

            Esys_Free(signature);
            return raw_signature;
        }
    };
}
