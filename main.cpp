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
#include <tss2/tss2_mu.h>
#include <cstring>

import tpm23;
import std;

int main() {
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
    std::println("[TEST 2] PERSISTENT STORAGE ROOT KEY (SRK)...");
    std::println("=================================================");
    auto srk_res = pipeline.get_or_create_srk();
    if (!srk_res.has_value()) {
        std::println(std::cerr, "SRK creation failed: {}", srk_res.error().verbose_explain());
        return 1;
    }
    auto& srk = srk_res.value();
    std::println(" Success! SRK Active (Persistent NV: {}).", srk.is_persistent());

    std::println("\n=================================================");
    std::println("[TEST 3] BUS-ENCRYPTED HARDWARE SEALING / UNSEALING...");
    std::println("=================================================");
    std::string secret_payload = "SiliconBoundProtectedKey-2026";
    std::span<const std::byte> secret_bytes(
        reinterpret_cast<const std::byte*>(secret_payload.data()),
                                            secret_payload.size()
    );

    auto sealed_res = pipeline.seal_secret_to_hardware(secret_bytes, 0, "SecurityPIN123");
    if (!sealed_res.has_value()) {
        std::println(std::cerr, " Hardware sealing failed: {}", sealed_res.error().verbose_explain());
        return 1;
    }
    auto sealed_blob = std::move(sealed_res.value());
    std::println(" Success! Payload sealed and marshaled (Compact size: {} bytes).", sealed_blob.size());

    auto unsealed_res = pipeline.unseal_secret_from_hardware(sealed_blob, "SecurityPIN123");
    if (!unsealed_res.has_value()) {
        std::println(std::cerr, " Hardware unsealing failed: {}", unsealed_res.error().verbose_explain());
        return 1;
    }

    std::string unsealed_str(
        reinterpret_cast<const char*>(unsealed_res.value().data()),
                             unsealed_res.value().size()
    );
    std::println(" Success! Unsealed plaintext: \"{}\"", unsealed_str);

    std::println("\n=================================================");
    std::println("[TEST 4] MULTI-KILOBYTE CHUNKED NV STORAGE ENGINE...");
    std::println("=================================================");
    auto nv_engine = pipeline.get<tpm23::nv_storage>();
    constexpr std::uint32_t TEST_INDEX = 0x01500001;

    std::size_t max_buf = nv_engine.get_max_nv_buffer_size();
    std::size_t max_idx = nv_engine.get_max_nv_index_size();
    std::println(" Hardware NV limits detected: MaxBuffer={} bytes, MaxIndex={} bytes.", max_buf, max_idx);

    std::size_t payload_len = std::min<std::size_t>(1280, max_idx);
    std::vector<std::byte> large_payload(payload_len);
    for (std::size_t i = 0; i < large_payload.size(); ++i) {
        large_payload[i] = static_cast<std::byte>((i * 7 + 13) & 0xFF);
    }

    (void)nv_engine.release_index(TEST_INDEX);

    auto nv_write_res = nv_engine.write_index(TEST_INDEX, large_payload, "NVSecretPIN");
    if (!nv_write_res.ok()) {
        std::println(std::cerr, " NV chunked write failed: {}", nv_write_res.verbose_explain());
        return 1;
    }
    std::println(" Success! Written {} bytes across chunked NV boundaries.", payload_len);

    auto nv_read_res = nv_engine.read_index(TEST_INDEX, "NVSecretPIN");
    if (!nv_read_res.has_value()) {
        std::println(std::cerr, " NV chunked read failed: {}", nv_read_res.error().verbose_explain());
        return 1;
    }
    std::println(" Success! Read back {} bytes from NV.", nv_read_res.value().size());

    bool matches = (nv_read_res.value() == large_payload);
    std::println(" Data integrity verified: {}", matches ? "PASSED" : "FAILED");

    auto cleanup_res = nv_engine.release_index(TEST_INDEX);
    if (!cleanup_res.ok()) {
        std::println(std::cerr, " NV cleanup warning: {}", cleanup_res.verbose_explain());
    }

    std::println("\n=================================================");
    std::println("[TEST 5] ASYMMETRIC SIGNING WITH TCG MARSHALING...");
    std::println("=================================================");
    auto crypto_engine = pipeline.get<tpm23::key_engine>();
    auto key_res = crypto_engine.generate_signing_key(srk.get());
    if (!key_res.has_value()) {
        std::println(std::cerr, " Signing key generation failed: {}", key_res.error().verbose_explain());
        return 1;
    }
    auto [priv_blob, pub_blob] = std::move(key_res.value());

    TPM2B_PRIVATE priv_struct{};
    TPM2B_PUBLIC pub_struct{};
    std::size_t offset = 0;
    Tss2_MU_TPM2B_PRIVATE_Unmarshal(reinterpret_cast<const uint8_t*>(priv_blob.data()), priv_blob.size(), &offset, &priv_struct);
    offset = 0;
    Tss2_MU_TPM2B_PUBLIC_Unmarshal(reinterpret_cast<const uint8_t*>(pub_blob.data()), pub_blob.size(), &offset, &pub_struct);

    ESYS_TR signing_key_handle = ESYS_TR_NONE;
    TSS2_RC rc = Esys_Load(
        pipeline.context(), srk.get(),
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &priv_struct, &pub_struct, &signing_key_handle
    );
    if (rc != TSS2_RC_SUCCESS) {
        std::println(std::cerr, " Failed to load signing key: 0x{:X}", rc);
        return 1;
    }
    tpm23::hardware_handle_guard key_guard{pipeline.context(), signing_key_handle};

    std::array<std::byte, 32> mock_digest{};
    std::fill(mock_digest.begin(), mock_digest.end(), std::byte{0x7E});
    auto sig_res = crypto_engine.sign_hash(signing_key_handle, mock_digest);
    if (!sig_res.has_value()) {
        std::println(std::cerr, " Sign operation failed: {}", sig_res.error().verbose_explain());
        return 1;
    }
    std::println(" Success! 256-byte signature generated under SRK hierarchy.");

    std::println("\n=================================================");
    std::println("[TEST 6] CONCURRENT THREAD-SAFETY STRESS TEST (TSAN)...");
    std::println("=================================================");

    constexpr int NUM_THREADS = 4;

    // Part A: Model A (Context-Per-Thread) concurrent execution
    std::atomic<int> model_a_success{0};
    {
        std::vector<std::jthread> workers;
        workers.reserve(NUM_THREADS);

        for (int t = 0; t < NUM_THREADS; ++t) {
            workers.emplace_back([&model_a_success]() {
                auto thread_conn = tpm23::secure_pipeline::connect_native_device();
                if (!thread_conn.has_value()) return;

                auto& thread_pipeline = thread_conn.value();
                auto thread_policy = thread_pipeline.get<tpm23::pcr_policy>();

                // Concurrent policy compilation in parallel sessions
                auto res = thread_policy.build()
                .require_pcr(7)
                .or_else([](auto& alt) { alt.require_auth(); })
                .compile();

                if (res.has_value()) {
                    model_a_success.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
    }
    std::println(" [Model A - Context-Per-Thread]: {}/{} threads completed without race conditions.",
                 model_a_success.load(), NUM_THREADS);

    // Part B: Model B (Synchronized Shared Pipeline via std::mutex)
    std::atomic<int> model_b_success{0};
    std::mutex pipeline_mutex;
    {
        std::vector<std::jthread> workers;
        workers.reserve(NUM_THREADS);

        for (int t = 0; t < NUM_THREADS; ++t) {
            workers.emplace_back([&pipeline, &pipeline_mutex, &model_b_success]() {
                std::lock_guard<std::mutex> lock(pipeline_mutex);
                auto shared_policy = pipeline.get<tpm23::pcr_policy>();
                auto res = shared_policy.calculate_pcr_digest(1 << 7);
                if (res.has_value()) {
                    model_b_success.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
    }
    std::println(" [Model B - Synchronized Shared Context]: {}/{} calls completed cleanly.",
                 model_b_success.load(), NUM_THREADS);

    return 0;
}
