#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "security/api/crypto_module.hpp"

namespace {

security::core::ByteBuffer ToBytes(const std::string& input) {
    return security::core::ByteBuffer(input.begin(), input.end());
}

std::string ToHex(const security::core::ByteBuffer& data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t b : data) {
        out << std::setw(2) << static_cast<int>(b);
    }
    return out.str();
}

bool Assert(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "Validation failed: " << message << std::endl;
        return false;
    }
    return true;
}

bool AssertStatus(const security::core::Status& status, const std::string& context) {
    if (!status.ok()) {
        std::cerr << "Validation failed: " << context << " | " << status.message << std::endl;
        return false;
    }
    return true;
}

} // namespace

int main() {
    const auto module_result = security::api::CreateCryptoModule();
    if (!AssertStatus(module_result.status, "CreateCryptoModule")) {
        return 1;
    }
    const auto& module = module_result.value;

    const auto providers_result = module->ListProviders();
    if (!AssertStatus(providers_result.status, "ListProviders")) {
        return 1;
    }
    const auto& providers = providers_result.value;

    if (!Assert(std::find(providers.begin(), providers.end(), "openssl") != providers.end(), "openssl backend not registered")) {
        return 1;
    }

    const auto provider_result = module->CreateProvider("openssl");
    if (!AssertStatus(provider_result.status, "CreateProvider(openssl)")) {
        return 1;
    }
    const auto& provider = provider_result.value;

    const auto provider_info_result = module->GetProviderInfo("openssl");
    if (!AssertStatus(provider_info_result.status, "GetProviderInfo(openssl)")) {
        return 1;
    }
    const auto& provider_info = provider_info_result.value;

    if (!Assert(provider_info.name == "openssl", "provider name mismatch")) {
        return 1;
    }
    if (!Assert(!provider_info.version.empty(), "provider version is empty")) {
        return 1;
    }
    if (!Assert(provider_info.sn.empty(), "provider SN should be empty for OpenSSL validation backend")) {
        return 1;
    }
    if (!Assert(provider_info.userdata_capability == 4096, "provider userdata capability mismatch")) {
        return 1;
    }

    const auto sample = ToBytes("abc");

    const auto sha256_result = provider->Digest(security::core::DigestAlgorithm::SHA256, sample);
    if (!AssertStatus(sha256_result.status, "Digest(SHA256)")) {
        return 1;
    }
    const auto sm3_result = provider->Digest(security::core::DigestAlgorithm::SM3, sample);
    if (!AssertStatus(sm3_result.status, "Digest(SM3)")) {
        return 1;
    }

    if (!Assert(ToHex(sha256_result.value) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 mismatch")) {
        return 1;
    }
    if (!Assert(ToHex(sm3_result.value) == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "SM3 mismatch")) {
        return 1;
    }

    std::string rsa_key_id;
    const auto rsa_keys_result = provider->GenerateKeyPair(security::core::KeyAlgorithm::RSA, 2048, rsa_key_id);
    if (!AssertStatus(rsa_keys_result.status, "GenerateKeyPair(RSA)")) {
        return 1;
    }
    if (!Assert(!rsa_key_id.empty(), "RSA key id is empty")) {
        return 1;
    }
    const auto rsa_sig_result = provider->Sign(security::core::SignatureAlgorithm::RSA_SHA256, rsa_key_id, sample);
    if (!AssertStatus(rsa_sig_result.status, "Sign(RSA_SHA256)")) {
        return 1;
    }
    const auto rsa_verify_result = provider->Verify(
        security::core::SignatureAlgorithm::RSA_SHA256,
        rsa_key_id,
        sample,
        rsa_sig_result.value);
    if (!AssertStatus(rsa_verify_result.status, "Verify(RSA_SHA256)")) {
        return 1;
    }
    if (!Assert(rsa_verify_result.value, "RSA verify failed")) {
        return 1;
    }

    std::string sm2_key_id;
    const auto sm2_keys_result = provider->GenerateKeyPair(security::core::KeyAlgorithm::SM2, 0, sm2_key_id);
    if (!AssertStatus(sm2_keys_result.status, "GenerateKeyPair(SM2)")) {
        return 1;
    }
    if (!Assert(!sm2_key_id.empty(), "SM2 key id is empty")) {
        return 1;
    }
    const auto sm2_sig_result = provider->Sign(security::core::SignatureAlgorithm::SM2_SM3, sm2_key_id, sample);
    if (!AssertStatus(sm2_sig_result.status, "Sign(SM2_SM3)")) {
        return 1;
    }
    const auto sm2_verify_result = provider->Verify(
        security::core::SignatureAlgorithm::SM2_SM3,
        sm2_key_id,
        sample,
        sm2_sig_result.value);
    if (!AssertStatus(sm2_verify_result.status, "Verify(SM2_SM3)")) {
        return 1;
    }
    if (!Assert(sm2_verify_result.value, "SM2 verify failed")) {
        return 1;
    }

    const auto user_data = ToBytes("userdata-demo");
    const auto write_status = provider->WriteUserData(32, user_data.size(), user_data);
    if (!AssertStatus(write_status, "WriteUserData")) {
        return 1;
    }
    const auto loaded_user_data_result = provider->ReadUserData(32, user_data.size());
    if (!AssertStatus(loaded_user_data_result.status, "ReadUserData")) {
        return 1;
    }
    if (!Assert(loaded_user_data_result.value == user_data, "user data read/write mismatch")) {
        return 1;
    }

    std::cout << "Provider: " << provider_info.name
              << " | Version: " << provider_info.version
              << " | SN: " << (provider_info.sn.empty() ? "<empty>" : provider_info.sn)
              << " | UserDataCapability: " << provider_info.userdata_capability
              << std::endl;
    std::cout << "Validation passed: SHA256/SM3 digest, RSA/SM2 sign verify, and 4KB user data storage access are successful." << std::endl;
    return 0;
}
