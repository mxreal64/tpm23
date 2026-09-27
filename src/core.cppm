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
/*
 * Copyright 2026 Your Name
 * Licensed under the Apache License, Version 2.0
 */

/*
 * Copyright 2026 Your Name
 * Licensed under the Apache License, Version 2.0
 */

module;

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <cstring>

export module tpm23.core;

import tpm23.status;
import tpm23.policy;
import std;

export namespace tpm23 {

    struct hardware_handle_guard {
        ESYS_CONTEXT* ctx = nullptr;
        ESYS_TR handle = ESYS_TR_NONE;

        hardware_handle_guard() = default;
        hardware_handle_guard(ESYS_CONTEXT* c, ESYS_TR h) noexcept : ctx(c), handle(h) {}

        ~hardware_handle_guard() {
            if (handle != ESYS_TR_NONE && ctx != nullptr) {
                Esys_FlushContext(ctx, handle);
                handle = ESYS_TR_NONE;
            }
        }

        hardware_handle_guard(const hardware_handle_guard&) = delete;
        hardware_handle_guard& operator=(const hardware_handle_guard&) = delete;

        hardware_handle_guard(hardware_handle_guard&& other) noexcept
        : ctx(other.ctx), handle(other.handle) {
            other.handle = ESYS_TR_NONE;
            other.ctx = nullptr;
        }

        hardware_handle_guard& operator=(hardware_handle_guard&& other) noexcept {
            if (this != &other) {
                if (handle != ESYS_TR_NONE && ctx != nullptr) {
                    Esys_FlushContext(ctx, handle);
                }
                ctx = other.ctx;
                handle = other.handle;
                other.handle = ESYS_TR_NONE;
                other.ctx = nullptr;
            }
            return *this;
        }
    };

    class srk_handle {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;
        ESYS_TR m_handle = ESYS_TR_NONE;
        bool m_is_persistent = false;

    public:
        srk_handle() = default;
        srk_handle(ESYS_CONTEXT* ctx, ESYS_TR handle, bool persistent) noexcept
        : m_ctx(ctx), m_handle(handle), m_is_persistent(persistent) {}

        ~srk_handle() {
            if (m_ctx && m_handle != ESYS_TR_NONE) {
                if (m_is_persistent) {
                    Esys_TR_Close(m_ctx, &m_handle);
                } else {
                    Esys_FlushContext(m_ctx, m_handle);
                }
                m_handle = ESYS_TR_NONE;
            }
        }

        srk_handle(const srk_handle&) = delete;
        srk_handle& operator=(const srk_handle&) = delete;

        srk_handle(srk_handle&& other) noexcept
        : m_ctx(other.m_ctx), m_handle(other.m_handle), m_is_persistent(other.m_is_persistent) {
            other.m_handle = ESYS_TR_NONE;
            other.m_ctx = nullptr;
        }

        srk_handle& operator=(srk_handle&& other) noexcept {
            if (this != &other) {
                if (m_ctx && m_handle != ESYS_TR_NONE) {
                    if (m_is_persistent) {
                        Esys_TR_Close(m_ctx, &m_handle);
                    } else {
                        Esys_FlushContext(m_ctx, m_handle);
                    }
                }
                m_ctx = other.m_ctx;
                m_handle = other.m_handle;
                m_is_persistent = other.m_is_persistent;
                other.m_handle = ESYS_TR_NONE;
                other.m_ctx = nullptr;
            }
            return *this;
        }

        [[nodiscard]] auto get() const noexcept -> ESYS_TR { return m_handle; }
        [[nodiscard]] bool is_persistent() const noexcept { return m_is_persistent; }
    };

    class secure_pipeline {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;

        explicit secure_pipeline(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        [[nodiscard]] static auto create_storage_parent_template() noexcept -> TPM2B_PUBLIC {
            TPM2B_PUBLIC parent{};
            parent.publicArea.type = TPM2_ALG_RSA;
            parent.publicArea.nameAlg = TPM2_ALG_SHA256;
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

        [[nodiscard]] auto persistent_handle_exists(TPM2_HANDLE handle) const noexcept -> bool {
            TPMS_CAPABILITY_DATA* cap_data = nullptr;
            TPMI_YES_NO more_data = TPM2_NO;

            TSS2_RC rc = Esys_GetCapability(
                m_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                TPM2_CAP_HANDLES, handle, 1,
                &more_data, &cap_data
            );

            if (rc != TSS2_RC_SUCCESS || !cap_data) return false;

            bool found = (cap_data->data.handles.count > 0 &&
            cap_data->data.handles.handle[0] == handle);

            Esys_Free(cap_data);
            return found;
        }

        [[nodiscard]] auto get_or_create_srk(TPM2_HANDLE persistent_index = 0x81000001) noexcept -> result<srk_handle> {
            if (persistent_handle_exists(persistent_index)) {
                ESYS_TR persistent_tr = ESYS_TR_NONE;
                TSS2_RC rc = Esys_TR_FromTPMPublic(
                    m_ctx, persistent_index,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &persistent_tr
                );
                if (rc == TSS2_RC_SUCCESS) {
                    return srk_handle{m_ctx, persistent_tr, true};
                }
            }

            TPM2B_AUTH empty_auth{};
            empty_auth.size = 0;
            TSS2_RC rc = Esys_TR_SetAuth(m_ctx, ESYS_TR_RH_OWNER, &empty_auth);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_PUBLIC parent_template = create_storage_parent_template();
            TPM2B_SENSITIVE_CREATE sensitive_create{};
            TPM2B_DATA outside_info{};
            TPML_PCR_SELECTION creation_pcr{};

            ESYS_TR transient_srk = ESYS_TR_NONE;
            rc = Esys_CreatePrimary(
                m_ctx, ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &sensitive_create, &parent_template, &outside_info, &creation_pcr,
                &transient_srk, nullptr, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            ESYS_TR new_persistent_tr = ESYS_TR_NONE;
            rc = Esys_EvictControl(
                m_ctx, ESYS_TR_RH_OWNER, transient_srk,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                persistent_index, &new_persistent_tr
            );

            if (rc == TSS2_RC_SUCCESS) {
                if (new_persistent_tr != ESYS_TR_NONE) {
                    Esys_TR_Close(m_ctx, &new_persistent_tr);
                }
                Esys_TR_Close(m_ctx, &transient_srk);

                ESYS_TR persistent_tr = ESYS_TR_NONE;
                rc = Esys_TR_FromTPMPublic(
                    m_ctx, persistent_index,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &persistent_tr
                );
                if (rc == TSS2_RC_SUCCESS) {
                    return srk_handle{m_ctx, persistent_tr, true};
                }
            }

            return srk_handle{m_ctx, transient_srk, false};
        }

        [[nodiscard]] auto start_bus_encrypted_session(
            ESYS_TR tpm_key,
            TPMA_SESSION session_flags
        ) noexcept -> result<hardware_handle_guard> {
            TPMT_SYM_DEF symmetric_def{
                .algorithm = TPM2_ALG_AES,
                .keyBits = {.aes = 128},
                .mode = {.aes = TPM2_ALG_CFB}
            };

            ESYS_TR session_handle = ESYS_TR_NONE;
            TSS2_RC rc = Esys_StartAuthSession(
                m_ctx, tpm_key, ESYS_TR_NONE,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, TPM2_SE_HMAC, &symmetric_def,
                TPM2_ALG_SHA256, &session_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            rc = Esys_TRSess_SetAttributes(
                m_ctx, session_handle,
                session_flags | TPMA_SESSION_CONTINUESESSION,
                0xFF
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_FlushContext(m_ctx, session_handle);
                return std::unexpected(status{rc});
            }

            return hardware_handle_guard{m_ctx, session_handle};
        }

        [[nodiscard]] auto seal_secret_to_hardware(
            std::span<const std::byte> plaintext_data,
            std::uint32_t target_pcr_mask = 0,
            std::string_view password = ""
        ) noexcept -> result<std::vector<std::byte>> {

            if (plaintext_data.size() > 128) [[unlikely]] {
                return std::unexpected(status{errors::payload_too_large});
            }

            auto srk_res = get_or_create_srk();
            if (!srk_res.has_value()) return std::unexpected(srk_res.error());
            auto& srk = srk_res.value();

            auto session_res = start_bus_encrypted_session(srk.get(), TPMA_SESSION_DECRYPT);
            if (!session_res.has_value()) return std::unexpected(session_res.error());
            auto& enc_session = session_res.value();

            TPM2B_SENSITIVE_CREATE object_sensitive{};
            object_sensitive.sensitive.data.size = static_cast<uint16_t>(plaintext_data.size());
            std::memcpy(object_sensitive.sensitive.data.buffer, plaintext_data.data(), plaintext_data.size());

            if (!password.empty()) {
                object_sensitive.sensitive.userAuth.size = static_cast<std::uint16_t>(password.size());
                std::memcpy(object_sensitive.sensitive.userAuth.buffer, password.data(), password.size());
            }

            TPM2B_PUBLIC object_template{};
            object_template.publicArea.type = TPM2_ALG_KEYEDHASH;
            object_template.publicArea.nameAlg = TPM2_ALG_SHA256;

            if (target_pcr_mask != 0) {
                object_template.publicArea.objectAttributes = (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT);
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

            TPM2B_DATA outside_info{};
            TPML_PCR_SELECTION pcr_selection{};
            pcr_selection.count = 0;

            TPM2B_PRIVATE* out_private = nullptr;
            TPM2B_PUBLIC* out_public = nullptr;

            TSS2_RC rc = Esys_Create(
                m_ctx, srk.get(),
                                     ESYS_TR_PASSWORD, enc_session.handle, ESYS_TR_NONE,
                                     &object_sensitive, &object_template, &outside_info, &pcr_selection,
                                     &out_private, &out_public, nullptr, nullptr, nullptr
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> marshaled_blob(sizeof(std::uint32_t) + sizeof(TPM2B_PRIVATE) + sizeof(TPM2B_PUBLIC));
            std::size_t offset = 0;

            rc = Tss2_MU_UINT32_Marshal(
                target_pcr_mask,
                reinterpret_cast<uint8_t*>(marshaled_blob.data()),
                                        marshaled_blob.size(),
                                        &offset
            );
            if (rc != TSS2_RC_SUCCESS) {
                Esys_Free(out_private);
                Esys_Free(out_public);
                return std::unexpected(status{errors::marshal_failure});
            }

            rc = Tss2_MU_TPM2B_PRIVATE_Marshal(
                out_private,
                reinterpret_cast<uint8_t*>(marshaled_blob.data()),
                                               marshaled_blob.size(),
                                               &offset
            );
            Esys_Free(out_private);
            if (rc != TSS2_RC_SUCCESS) {
                Esys_Free(out_public);
                return std::unexpected(status{errors::marshal_failure});
            }

            rc = Tss2_MU_TPM2B_PUBLIC_Marshal(
                out_public,
                reinterpret_cast<uint8_t*>(marshaled_blob.data()),
                                              marshaled_blob.size(),
                                              &offset
            );
            Esys_Free(out_public);
            if (rc != TSS2_RC_SUCCESS) return std::unexpected(status{errors::marshal_failure});

            marshaled_blob.resize(offset);
            return marshaled_blob;
        }

        [[nodiscard]] auto unseal_secret_from_hardware(
            std::span<const std::byte> sealed_blob,
            std::string_view password = ""
        ) noexcept -> result<std::vector<std::byte>> {

            std::uint32_t target_pcr_mask = 0;
            TPM2B_PRIVATE priv_struct{};
            TPM2B_PUBLIC pub_struct{};
            std::size_t offset = 0;

            TSS2_RC rc = Tss2_MU_UINT32_Unmarshal(
                reinterpret_cast<const uint8_t*>(sealed_blob.data()),
                                                  sealed_blob.size(),
                                                  &offset,
                                                  &target_pcr_mask
            );
            if (rc != TSS2_RC_SUCCESS) return std::unexpected(status{errors::corrupted_payload});

            rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(
                reinterpret_cast<const uint8_t*>(sealed_blob.data()),
                                                 sealed_blob.size(),
                                                 &offset,
                                                 &priv_struct
            );
            if (rc != TSS2_RC_SUCCESS) return std::unexpected(status{errors::corrupted_payload});

            rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(
                reinterpret_cast<const uint8_t*>(sealed_blob.data()),
                                                sealed_blob.size(),
                                                &offset,
                                                &pub_struct
            );
            if (rc != TSS2_RC_SUCCESS) return std::unexpected(status{errors::corrupted_payload});

            auto srk_res = get_or_create_srk();
            if (!srk_res.has_value()) return std::unexpected(srk_res.error());
            auto& srk = srk_res.value();

            ESYS_TR loaded_item_handle = ESYS_TR_NONE;
            rc = Esys_Load(
                m_ctx, srk.get(),
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &priv_struct, &pub_struct, &loaded_item_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            hardware_handle_guard item_guard{m_ctx, loaded_item_handle};

            auto session_res = start_bus_encrypted_session(srk.get(), TPMA_SESSION_ENCRYPT);
            if (!session_res.has_value()) return std::unexpected(session_res.error());
            auto& enc_session = session_res.value();

            ESYS_TR auth_session_handle = ESYS_TR_PASSWORD;
            hardware_handle_guard policy_session_guard{m_ctx, ESYS_TR_NONE};

            if (target_pcr_mask != 0) {
                tpm23::pcr_policy evaluator{m_ctx};
                auto pcr_res = evaluator.create_active_pcr_session(target_pcr_mask);
                if (!pcr_res.has_value()) return std::unexpected(pcr_res.error());

                auth_session_handle = pcr_res.value();
                policy_session_guard.handle = auth_session_handle;
            } else {
                TPM2B_AUTH clear_auth{};
                clear_auth.size = static_cast<std::uint16_t>(password.size());
                std::memcpy(clear_auth.buffer, password.data(), password.size());

                rc = Esys_TR_SetAuth(m_ctx, loaded_item_handle, &clear_auth);
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            }

            TPM2B_SENSITIVE_DATA* unsealed_data = nullptr;
            rc = Esys_Unseal(
                m_ctx, loaded_item_handle,
                auth_session_handle, enc_session.handle, ESYS_TR_NONE,
                &unsealed_data
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            std::vector<std::byte> plaintext(unsealed_data->size);
            std::memcpy(plaintext.data(), unsealed_data->buffer, unsealed_data->size);

            Esys_Free(unsealed_data);
            return plaintext;
        }

        template <typename SubsystemType>
        [[nodiscard]] auto get() noexcept -> SubsystemType {
            return SubsystemType{m_ctx};
        }

        [[nodiscard]] auto context() const noexcept -> ESYS_CONTEXT* { return m_ctx; }
    };
}
