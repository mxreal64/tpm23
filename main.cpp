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

#include <tss2/tss2_esys.h>
#include <cstring>
import tpm23;
import std;

int main() {
    // 1. Initialize native device connection
    auto connection = tpm23::secure_pipeline::connect_native_device();
    if (!connection.has_value()) {
        std::println(std::cerr, "Hardware connection failed: {}", connection.error().verbose_explain());
        return 1;
    }
    auto& pipeline = connection.value();

    std::println("=================================================");
    std::println("[TEST 1] VALIDATING FLUENT POLICY BUILDER CHAIN...");
    std::println("=================================================");

    auto policy_engine = pipeline.get<tpm23::pcr_policy>();

    // Monadic policy builder chaining
    auto compiled_policy_res = policy_engine.build()
    .require_pcr(7)
    .or_else([](auto& alternative_branch) {
        alternative_branch.require_auth();
    })
    .compile();

    if (!compiled_policy_res.has_value()) {
        std::println(std::cerr, " Fluent Policy Builder Compilation Failed: {}", compiled_policy_res.error().verbose_explain());
        return 1;
    }
    std::println(" Success! Complex branching policy digest generated safely.");

    std::println("\n=================================================");
    std::println("[TEST 2] GENERATING SILICON-BOUND ASYMMETRIC KEY PAIR...");
    std::println("=================================================");

    auto crypto_engine = pipeline.get<tpm23::key_engine>();

    // Manual parent template setup
    TPM2B_PUBLIC parent_template{};
    parent_template.publicArea.type = TPM2_ALG_RSA;
    parent_template.publicArea.nameAlg = TPM2_ALG_SHA256;
    parent_template.publicArea.objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED |
    TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDTPM |
    TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN);
    parent_template.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    parent_template.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    parent_template.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    parent_template.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    parent_template.publicArea.parameters.rsaDetail.keyBits = 2048;
    parent_template.publicArea.parameters.rsaDetail.exponent = 0;

    TPM2B_SENSITIVE_CREATE sensitive_create{};
    TPM2B_DATA outside_info{};
    TPML_PCR_SELECTION creation_pcr{};
    ESYS_TR primary_handle = ESYS_TR_NONE;

    // Create primary root handle in owner hierarchy
    TSS2_RC rc = Esys_CreatePrimary(
        pipeline.context(), ESYS_TR_RH_OWNER,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &sensitive_create, &parent_template, &outside_info, &creation_pcr,
                                    &primary_handle, nullptr, nullptr, nullptr, nullptr
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::println(std::cerr, "Primary generation failed: 0x{:X}", rc);
        return 1;
    }

    // Generate asymmetric key pair
    auto key_res = crypto_engine.generate_signing_key(primary_handle);
    if (!key_res.has_value()) {
        std::println(std::cerr, "Asymmetric generation failed: {}", key_res.error().verbose_explain());
        Esys_FlushContext(pipeline.context(), primary_handle);
        return 1;
    }
    auto [priv_blob, pub_blob] = std::move(key_res.value());
    std::println(" Success! RSA-2048 signing parameters generated inside chip.");

    // Load key parameters back to hardware
    ESYS_TR signing_key_handle = ESYS_TR_NONE;
    TPM2B_PRIVATE priv_struct_aligned{};
    TPM2B_PUBLIC pub_struct_aligned{};
    std::memcpy(&priv_struct_aligned, priv_blob.data(), sizeof(TPM2B_PRIVATE));
    std::memcpy(&pub_struct_aligned, pub_blob.data(), sizeof(TPM2B_PUBLIC));

    rc = Esys_Load(
        pipeline.context(), primary_handle,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &priv_struct_aligned, &pub_struct_aligned, &signing_key_handle
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::println(std::cerr, "Failed to load key, code: 0x{:X}", rc);
        Esys_FlushContext(pipeline.context(), primary_handle);
        return 1;
    }

    // Perform signing operation
    std::array<std::byte, 32> mock_sha256_digest{};
    std::fill(mock_sha256_digest.begin(), mock_sha256_digest.end(), std::byte{0xA5});
    auto sig_res = crypto_engine.sign_hash(signing_key_handle, mock_sha256_digest);
    if (!sig_res.has_value()) {
        std::println(std::cerr, "Hardware sign operation failed: {}", sig_res.error().verbose_explain());
    } else {
        std::println(" Success! Digital Signature produced by silicon.");
        std::println(" Signature Size: {} bytes.", sig_res.value().size());
    }

    // Cleanup handles
    Esys_FlushContext(pipeline.context(), signing_key_handle);
    Esys_FlushContext(pipeline.context(), primary_handle);
    return 0;
}
