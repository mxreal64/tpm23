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

            // Fixed: Access the fields via the first slot [0] of the pcrSelections array
            pcr_selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
            pcr_selection.pcrSelections[0].sizeofSelect = 3;
            pcr_selection.pcrSelections[0].pcrSelect[0] = pcr_mask & 0xFF;
            pcr_selection.pcrSelections[0].pcrSelect[1] = (pcr_mask >> 8) & 0xFF;
            pcr_selection.pcrSelections[0].pcrSelect[2] = (pcr_mask >> 16) & 0xFF;
            return pcr_selection;
        }

    public:
        explicit pcr_policy(ESYS_CONTEXT* ctx) noexcept : m_ctx(ctx) {}

        [[nodiscard]] auto calculate_pcr_digest(std::uint32_t pcr_mask) noexcept -> result<TPM2B_DIGEST> {
            TPM2B_DIGEST policy_digest{};
            if (pcr_mask == 0) return policy_digest;

            TPMT_SYM_DEF symmetric_def{};
            symmetric_def.algorithm = TPM2_ALG_NULL;

            ESYS_TR session_handle = ESYS_TR_NONE;
            TSS2_RC rc = Esys_StartAuthSession(
                m_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, TPM2_SE_POLICY, &symmetric_def,
                TPM2_ALG_SHA256, &session_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPML_PCR_SELECTION pcr_selection = build_pcr_selection(pcr_mask);
            rc = Esys_PolicyPCR(
                m_ctx, session_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, &pcr_selection
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_FlushContext(m_ctx, session_handle);
                return std::unexpected(status{rc});
            }

            TPM2B_DIGEST* real_digest = nullptr;
            rc = Esys_PolicyGetDigest(
                m_ctx, session_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                &real_digest
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_FlushContext(m_ctx, session_handle);
                return std::unexpected(status{rc});
            }

            std::memcpy(&policy_digest, real_digest, sizeof(TPM2B_DIGEST));

            Esys_Free(real_digest);
            Esys_FlushContext(m_ctx, session_handle);

            return policy_digest;
        }

        [[nodiscard]] auto create_active_pcr_session(std::uint32_t pcr_mask) noexcept -> result<ESYS_TR> {
            ESYS_TR session_handle = ESYS_TR_NONE;

            TPMT_SYM_DEF symmetric_def{};
            symmetric_def.algorithm = TPM2_ALG_NULL;

            TSS2_RC rc = Esys_StartAuthSession(
                m_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, TPM2_SE_POLICY, &symmetric_def,
                TPM2_ALG_SHA256, &session_handle
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] return std::unexpected(status{rc});

            TPML_PCR_SELECTION pcr_selection = build_pcr_selection(pcr_mask);
            rc = Esys_PolicyPCR(
                m_ctx, session_handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                nullptr, &pcr_selection
            );
            if (rc != TSS2_RC_SUCCESS) [[unlikely]] {
                Esys_FlushContext(m_ctx, session_handle);
                return std::unexpected(status{rc});
            }

            return session_handle;
        }
    };
}
