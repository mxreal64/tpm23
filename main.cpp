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

import tpm23;
import std;

int main() {
    auto connection = tpm23::secure_pipeline::connect_native_device();
    if (!connection.has_value()) {
        std::println(std::cerr, "Hardware connection failed: {}", connection.error().verbose_explain());
        return 1;
    }
    auto& pipeline = connection.value();

    std::string secret = "Highly_Sensitive_Data_With_PIN_Protection";
    auto data_span = std::as_bytes(std::span{secret});

    std::string user_pin = "SecurePIN123!";
    std::string wrong_pin = "WrongPIN999";

    std::println("=================================================");
    std::println("[TEST 1] SEALING PAYLOAD OBJECT WITH AN EXPLICIT PIN...");
    std::println("=================================================");

    auto seal_res = pipeline.seal_secret_to_hardware(data_span, 0, user_pin);
    if (!seal_res.has_value()) {
        std::println(std::cerr, "Failed to seal data with password: {}", seal_res.error().verbose_explain());
        return 1;
    }
    auto encrypted_blob = seal_res.value();
    std::println("Success! Blob generated and bound to PIN rules.");

    // Intentional verification failure check
    std::println("\nTesting intentional security block by passing an invalid PIN...");
    auto bad_unseal_res = pipeline.unseal_secret_from_hardware(encrypted_blob, wrong_pin);
    if (!bad_unseal_res.has_value()) {
        std::println("Confirmed Secure: TPM blocked extraction loop completely! Reported Code Details: \n  -> {}",
                     bad_unseal_res.error().verbose_explain());
    } else {
        std::println(std::cerr, "CRITICAL ERROR: Hardware released secret data despite an invalid PIN!");
        return 1;
    }

    // Verified correct path recovery check
    std::println("\nTesting verified access tracking loop by passing the accurate PIN...");
    auto clean_unseal_res = pipeline.unseal_secret_from_hardware(encrypted_blob, user_pin);
    if (!clean_unseal_res.has_value()) {
        std::println(std::cerr, "Failed valid unsealing step: {}", clean_unseal_res.error().verbose_explain());
        return 1;
    }
    std::string recovered_string(reinterpret_cast<char*>(clean_unseal_res.value().data()), clean_unseal_res.value().size());
    std::println("Success! Recovered Protected Payload string: \n  -> {}", recovered_string);

    std::println("\n=================================================");
    std::println("[TEST 2] WRITING TO NVRAM STORAGE UNDER PIN AUTH RULES...");
    std::println("=================================================");

    auto nv_hardware = pipeline.nv();
    std::uint32_t slot_id = 15;
    std::string nv_payload = "Persistent_Protected_NVRAM_Payload";
    auto nv_span = std::as_bytes(std::span{nv_payload});

    std::println("Burning string payload into silicon storage slot 15 locked by PIN authentication...");
    auto write_err = nv_hardware.write_index(slot_id, nv_span, user_pin);
    if (!write_err.ok()) {
        std::println(std::cerr, "NV Write Failed: {}", write_err.verbose_explain());
        return 1;
    }

    std::println("\nTesting intentional security block by trying to read NVRAM via an invalid PIN...");
    auto bad_nv_read = nv_hardware.read_index(slot_id, wrong_pin);
    if (!bad_nv_read.has_value()) {
        std::println("Confirmed Secure: TPM blocked NVRAM flash extraction! Reported Code Details: \n  -> {}",
                     bad_nv_read.error().verbose_explain());
    } else {
        std::println(std::cerr, "CRITICAL ERROR: Hardware released persistent NV RAM content despite an invalid PIN!");
        auto purge_status = nv_hardware.release_index(slot_id);
        if (!purge_status.ok()) std::println(std::cerr, "Emergency purge breakdown.");
        return 1;
    }

    std::println("\nTesting verified access to NVRAM flash using the accurate PIN...");
    auto clear_nv_read = nv_hardware.read_index(slot_id, user_pin);
    if (!clear_nv_read.has_value()) {
        std::println(std::cerr, "Failed valid NV read step: {}", clear_nv_read.error().verbose_explain());
        auto purge_status = nv_hardware.release_index(slot_id);
        if (!purge_status.ok()) std::println(std::cerr, "Emergency purge breakdown.");
        return 1;
    }

    std::string recovered_nv_string(reinterpret_cast<char*>(clear_nv_read.value().data()), clear_nv_read.value().size());
    std::println("Success! Recovered Persistent NV RAM Payload: \n  -> {}", recovered_nv_string);

    std::println("\nPurging hardware flash index allocation space...");
    auto release_err = nv_hardware.release_index(slot_id);
    if (!release_err.ok()) {
        std::println(std::cerr, "Final NV Release Failed: {}", release_err.verbose_explain());
        return 1;
    }
    std::println("Full verification suite completed successfully!");
}
