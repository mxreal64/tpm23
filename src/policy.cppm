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
#include <cstring>

export module tpm23.policy;

import tpm23.status;
import std;

export namespace tpm23 {

    class pcr_policy {
    private:
        ESYS_CONTEXT* m_ctx = nullptr;

        [[nodiscard]] static auto build_pcr_selection(std::uint32_t pcr_mask) noexcept -> TPML_PCR_SELECTION {
            TPML_PCR_SELECTION pcr_selection{};
            if (pcr_mask == 0) return pcr_selection;

            pcr_selection.count = 1;
            pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
            pcr_selection.pcrSelections[0].sizeofSelect = 3;
            pcr_selection.pcrSelections[0].pcrSelect[0] = pcr_mask & 0xFF;
            pcr_selection.pcrSelections[0].pcrSelect[1] = (pcr_mask >> 8) & 0xFF;
            pcr_selection.pcrSelections[0].pcrSelect[2] = (pcr_mask >> 16) & 0xFF;
            return pcr_selection;
        }

        // Shared RAII utility to automatically flush temporary runtime trial sessions
        struct session_guard {
            ESYS_CONTEXT* ctx;
            ESYS_TR handle;
            ~session_guard() {
                if (handle != ESYS_TR_NONE && ctx != nullptr) {
                    Esys_FlushContext(ctx, handle);
                }
            }
        };

        // Creates a low-overhead, unauthenticated TPM policy trial session
        [[nodiscard]] auto start_trial_session() noexcept -> result<ESYS_TR> {
            // Explicitly initialize every nested union block to bypass compiler warnings
            TPMT_SYM_DEF symmetric_def{
                .algorithm = TPM2_ALG_NULL,
                .keyBits = {.aes = 0},
                .mode = {.aes = TPM2_ALG_NULL}
            };

            ESYS_TR session_handle = ESYS_TR_NONE;

            TSS2_RC rc = Esys_StartAuthSession(
                m_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, TPM2_SE_POLICY, &symmetric_def,
                TPM2_ALG_SHA256, &session_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});
            return session_handle;
        }

    public:
        explicit pcr_policy(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        // High-level fluent builder interface for complex policy chaining
        class policy_builder {
        private:
            pcr_policy& m_parent;
            ESYS_TR m_session = ESYS_TR_NONE;
            status m_internal_status{TSS2_RC_SUCCESS};
            std::vector<TPM2B_DIGEST> m_or_branches;

            // Extracts the intermediate policy digest accumulation state out of the session
            [[nodiscard]] auto capture_current_digest() noexcept -> result<TPM2B_DIGEST> {
                TPM2B_DIGEST* real_digest = nullptr;
                TSS2_RC rc = Esys_PolicyGetDigest(
                    m_parent.m_ctx, m_session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &real_digest
                );
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

                TPM2B_DIGEST local_digest{};
                std::memcpy(&local_digest, real_digest, sizeof(TPM2B_DIGEST));
                Esys_Free(real_digest);
                return local_digest;
            }

        public:
            explicit policy_builder(pcr_policy& parent) noexcept : m_parent(parent) {
                auto session_res = m_parent.start_trial_session();
                if (!session_res.has_value()) [[unlikely]] {
                    m_internal_status = session_res.error();
                } else {
                    m_session = session_res.value();
                }
            }

            ~policy_builder() {
                if (m_session != ESYS_TR_NONE) {
                    Esys_FlushContext(m_parent.m_ctx, m_session);
                }
            }

            // Chaining Node: Add a structural PCR check requirement
            auto require_pcr(std::uint32_t pcr_mask) noexcept -> policy_builder& {
                if (!m_internal_status.ok()) return *this;

                TPML_PCR_SELECTION pcr_selection = build_pcr_selection(pcr_mask);
                TSS2_RC rc = Esys_PolicyPCR(
                    m_parent.m_ctx, m_session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    nullptr, &pcr_selection
                );
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] m_internal_status = status{rc};
                return *this;
            }

            // Chaining Node: Force physical PIN validation rules
            auto require_auth() noexcept -> policy_builder& {
                if (!m_internal_status.ok()) return *this;

                TSS2_RC rc = Esys_PolicyAuthValue(
                    m_parent.m_ctx, m_session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE
                );
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] m_internal_status = status{rc};
                return *this;
            }

            // Chaining Node: Logical OR branch evaluator
            auto or_else(std::move_only_function<void(policy_builder&)> alternative_path) noexcept -> policy_builder& {
                if (!m_internal_status.ok()) return *this;

                // 1. Snapshot the digest calculated by the current branch so far
                auto first_branch_digest = capture_current_digest();
                if (!first_branch_digest.has_value()) [[unlikely]] {
                    m_internal_status = first_branch_digest.error();
                    return *this;
                }
                m_or_branches.push_back(first_branch_digest.value());

                // 2. Spawn a clean, parallel builder pipeline to evaluate the fallback condition
                policy_builder alternative_builder{m_parent};
                alternative_path(alternative_builder);

                auto second_branch_digest = alternative_builder.capture_current_digest();
                if (!second_branch_digest.has_value()) [[unlikely]] {
                    m_internal_status = second_branch_digest.error();
                    return *this;
                }
                m_or_branches.push_back(second_branch_digest.value());

                // 3. Flatten the compiled sub-digests into a standard TCG list package layout
                TPML_DIGEST digest_list{};
                digest_list.count = static_cast<std::uint32_t>(m_or_branches.size());
                if (digest_list.count > 8) [[unlikely]] {
                    m_internal_status = status{0x0003}; // Error code for size field mismatch
                    return *this;
                }

                for (std::size_t i = 0; i < m_or_branches.size(); ++i) {
                    std::memcpy(&digest_list.digests[i], &m_or_branches[i], sizeof(TPM2B_DIGEST));
                }

                // 4. Submit the complete array to update the primary session context topology
                TSS2_RC rc = Esys_PolicyOR(
                    m_parent.m_ctx, m_session,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &digest_list
                );
                if (rc != TSS2_RC_SUCCESS) [[unlikely]] m_internal_status = status{rc};

                // Clear structural accumulation trackers to allow downstream chaining
                m_or_branches.clear();
                return *this;
            }

            // Finalizer Node: Extracts and yields the fully compiled multi-branch hash block
            [[nodiscard]] auto compile() noexcept -> result<TPM2B_DIGEST> {
                if (!m_internal_status.ok()) [[unlikely]] return std::unexpected(m_internal_status);
                return capture_current_digest();
            }
        };

        // Factory entrypoint to spawn a clean builder node sequence
        [[nodiscard]] auto build() noexcept -> policy_builder {
            return policy_builder{*this};
        }

        // Legacy compatibility entrypoints preserved for structural layout
        [[nodiscard]] auto calculate_pcr_digest(std::uint32_t pcr_mask) noexcept -> result<TPM2B_DIGEST> {
            auto session_res = start_trial_session();
            if (!session_res.has_value()) [[unlikely]] return std::unexpected(session_res.error());

            ESYS_TR session_handle = session_res.value();
            session_guard guard{m_ctx, session_handle};

            TPML_PCR_SELECTION pcr_selection = build_pcr_selection(pcr_mask);
            TSS2_RC rc = Esys_PolicyPCR(m_ctx, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &pcr_selection);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_DIGEST* real_digest = nullptr;
            rc = Esys_PolicyGetDigest(m_ctx, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &real_digest);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPM2B_DIGEST policy_digest{};
            std::memcpy(&policy_digest, real_digest, sizeof(TPM2B_DIGEST));
            Esys_Free(real_digest);

            return policy_digest;
        }

        [[nodiscard]] auto create_active_pcr_session(std::uint32_t pcr_mask) noexcept -> result<ESYS_TR> {
            auto session_res = start_trial_session();
            if (!session_res.has_value()) [[unlikely]] return std::unexpected(session_res.error());

            ESYS_TR session_handle = session_res.value();
            TPML_PCR_SELECTION pcr_selection = build_pcr_selection(pcr_mask);

            TSS2_RC rc = Esys_PolicyPCR(m_ctx, session_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &pcr_selection);
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_FlushContext(m_ctx, session_handle);
                return std::unexpected(status{rc});
            }

            return session_handle;
        }
    };
}
