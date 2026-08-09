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

export module tpm23.core;

import tpm23.status;
import tpm23.nv;
import tpm23.policy;
import std;

export namespace tpm23 {

    struct hardware_handle_guard {
        ESYS_CONTEXT* ctx;
        ESYS_TR handle;
        ~hardware_handle_guard() {
            if (handle != ESYS_TR_NONE && ctx != nullptr) {
                Esys_FlushContext(ctx, handle);
            }
        }
    };

    class secure_pipeline {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;

        explicit secure_pipeline(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        [[nodiscard]] static auto create_storage_parent_template() noexcept -> TPM2B_PUBLIC {
            TPM2B_PUBLIC parent{};
            parent.publicArea.type = TPM2_ALG_RSA;
            parent.publicArea.nameAlg = TPM2_ALG_SHA256;

            // Added TPMA_OBJECT_SENSITIVEDATAORIGIN to prevent 0x2C2 (Inconsistent Attributes)
            parent.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_RESTRICTED |
            TPMA_OBJECT_DECRYPT |
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN);

            parent.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
            parent.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
            parent.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
            parent.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
            parent.publicArea.parameters.rsaDetail.keyBits = 2048;
            parent.publicArea.parameters.rsaDetail.exponent = 0;
            return parent;
        }

    public:
        ~secure_pipeline() noexcept {
            if (m_ctx) Esys_Finalize(&m_ctx);
        }

        secure_pipeline(const secure_pipeline&) = delete;
        secure_pipeline& operator=(const secure_pipeline&) = delete;

        secure_pipeline(secure_pipeline&& other) noexcept : m_ctx(other.m_ctx) {
            other.m_ctx = nullptr;
        }

        secure_pipeline& operator=(secure_pipeline&& other) noexcept {
            if (this != &other) {
                if (m_ctx) Esys_Finalize(&m_ctx);
                m_ctx = other.m_ctx;
                other.m_ctx = nullptr;
            }
            return *this;
        }

        [[nodiscard]] static auto connect_native_device() noexcept -> result<secure_pipeline> {
            ESYS_CONTEXT* local_ctx = nullptr;
            TSS2_RC rc = Esys_Initialize(&local_ctx, nullptr, nullptr);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            return secure_pipeline{local_ctx};
        }

        [[nodiscard]] auto seal_secret_to_hardware(
            std::span<const std::byte> plaintext_data,
            std::uint32_t target_pcr_mask = 0,
            std::string_view password = ""
        ) noexcept -> result<std::vector<std::byte>> {

            if (plaintext_data.size() > 128) [[unlikely]] {
                return std::unexpected(status{0x0001});
            }

            TPM2B_AUTH empty_auth{};
            empty_auth.size = 0;

            TSS2_RC rc = Esys_TR_SetAuth(m_ctx, ESYS_TR_RH_OWNER, &empty_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_PUBLIC parent_template = create_storage_parent_template();

            // Fixed: Keep the parent creation container blank so the Storage Root Key remains un-authed
            TPM2B_SENSITIVE_CREATE sensitive_create{};
            TPM2B_DATA outside_info{};
            TPML_PCR_SELECTION creation_pcr{};

            ESYS_TR primary_handle = ESYS_TR_NONE;
            rc = Esys_CreatePrimary(
                m_ctx, ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &sensitive_create, &parent_template, &outside_info, &creation_pcr,
                &primary_handle, nullptr, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            hardware_handle_guard primary_guard{m_ctx, primary_handle};

            rc = Esys_TR_SetAuth(m_ctx, primary_handle, &empty_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_SENSITIVE_CREATE object_sensitive{};
            object_sensitive.sensitive.data.size = static_cast<uint16_t>(plaintext_data.size());
            std::memcpy(object_sensitive.sensitive.data.buffer, plaintext_data.data(), plaintext_data.size());

            // Correct: Lock your unique custom password constraint ONLY to the child secret object data block
            if (!password.empty()) {
                object_sensitive.sensitive.userAuth.size = static_cast<std::uint16_t>(password.size());
                std::memcpy(object_sensitive.sensitive.userAuth.buffer, password.data(), password.size());
            }

            TPM2B_PUBLIC object_template{};
            object_template.publicArea.type = TPM2_ALG_KEYEDHASH;
            object_template.publicArea.nameAlg = TPM2_ALG_SHA256;

            if (target_pcr_mask != 0) {
                object_template.publicArea.objectAttributes = (TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT);
                tpm23::pcr_policy evaluator{m_ctx};
                auto digest_res = evaluator.calculate_pcr_digest(target_pcr_mask);
                if (!digest_res.has_value()) return std::unexpected(digest_res.error());
                object_template.publicArea.authPolicy = digest_res.value();
            } else {
                object_template.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT);
            }
            object_template.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

            TPML_PCR_SELECTION pcr_selection{};
            pcr_selection.count = 0; // Explicit empty initialization passing

            TPM2B_PRIVATE* out_private = nullptr;
            TPM2B_PUBLIC* out_public = nullptr;

            rc = Esys_Create(
                m_ctx, primary_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &object_sensitive, &object_template, &outside_info, &pcr_selection,
                &out_private, &out_public, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> serialized_blob(sizeof(std::uint32_t) + sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC));
            auto writer = serialized_blob.data();

            std::memcpy(writer, &target_pcr_mask, sizeof(std::uint32_t)); writer += sizeof(std::uint32_t);
            std::memcpy(writer, out_private, sizeof(TPM2B_PRIVATE)); writer += sizeof(TPM2B_PRIVATE);
            std::memcpy(writer, out_public, sizeof(TPM2B_PUBLIC));

            Esys_Free(out_private);
            Esys_Free(out_public);

            return serialized_blob;
        }

        [[nodiscard]] auto unseal_secret_from_hardware(
            std::span<const std::byte> sealed_blob,
            std::string_view password = "" // Added user-supplied authentication check parameter
        ) noexcept -> result<std::vector<std::byte>> {

            if (sealed_blob.size() < (sizeof(std::uint32_t) + sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC))) [[unlikely]] {
                return std::unexpected(status{0x0002});
            }

            std::uint32_t target_pcr_mask = 0;
            TPM2B_PRIVATE priv_struct{};
            TPM2B_PUBLIC pub_struct{};

            auto reader = sealed_blob.data();
            std::memcpy(&target_pcr_mask, reader, sizeof(std::uint32_t)); reader += sizeof(std::uint32_t);
            std::memcpy(&priv_struct, reader, sizeof(TPM2B_PRIVATE)); reader += sizeof(TPM2B_PRIVATE);
            std::memcpy(&pub_struct, reader, sizeof(TPM2B_PUBLIC));

            TPM2B_AUTH empty_auth{};
            empty_auth.size = 0;

            TSS2_RC rc = Esys_TR_SetAuth(m_ctx, ESYS_TR_RH_OWNER, &empty_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_PUBLIC parent_template = create_storage_parent_template();
            TPM2B_SENSITIVE_CREATE sensitive_create{};
            TPM2B_DATA outside_info{};
            TPML_PCR_SELECTION creation_pcr{};

            ESYS_TR primary_handle = ESYS_TR_NONE;
            rc = Esys_CreatePrimary(
                m_ctx, ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &sensitive_create, &parent_template, &outside_info, &creation_pcr,
                &primary_handle, nullptr, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            hardware_handle_guard primary_guard{m_ctx, primary_handle};

            rc = Esys_TR_SetAuth(m_ctx, primary_handle, &empty_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            ESYS_TR loaded_key_handle = ESYS_TR_NONE;
            rc = Esys_Load(
                m_ctx, primary_handle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &priv_struct, &pub_struct, &loaded_key_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            hardware_handle_guard key_guard{m_ctx, loaded_key_handle};

            ESYS_TR auth_session_handle = ESYS_TR_PASSWORD;
            hardware_handle_guard policy_session_guard{m_ctx, ESYS_TR_NONE};

            if (target_pcr_mask != 0) {
                tpm23::pcr_policy evaluator{m_ctx};
                auto session_res = evaluator.create_active_pcr_session(target_pcr_mask);
                if (!session_res.has_value()) return std::unexpected(session_res.error());

                auth_session_handle = session_res.value();
                policy_session_guard.handle = auth_session_handle;
            } else {
                // If checking an object password, convert the string view to TPM2B_AUTH and register it to the ESYS handle
                TPM2B_AUTH clear_auth{};
                clear_auth.size = static_cast<std::uint16_t>(password.size());
                std::memcpy(clear_auth.buffer, password.data(), password.size());

                rc = Esys_TR_SetAuth(m_ctx, loaded_key_handle, &clear_auth);
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            }

            TPM2B_SENSITIVE_DATA* unsealed_data = nullptr;
            rc = Esys_Unseal(
                m_ctx, loaded_key_handle,
                auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                &unsealed_data
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> plaintext(unsealed_data->size);
            std::memcpy(plaintext.data(), unsealed_data->buffer, unsealed_data->size);

            Esys_Free(unsealed_data);
            return plaintext;
        }

        [[nodiscard]] auto nv() noexcept -> tpm23::nv_storage {
            return tpm23::nv_storage{m_ctx};
        }
    };
}
