#include <algorithm>
#include <cstdint>
#include <exception>
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

void Assert(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() {
    try {
        const auto module = security::api::CreateCryptoModule();
        const auto providers = module->ListProviders();

        Assert(std::find(providers.begin(), providers.end(), "openssl") != providers.end(), "openssl backend not registered");
        const auto provider = module->CreateProvider("openssl");
        const auto provider_info = module->GetProviderInfo("openssl");
        Assert(provider_info.name == "openssl", "provider name mismatch");
        Assert(!provider_info.version.empty(), "provider version is empty");
        Assert(provider_info.sn.empty(), "provider SN should be empty for OpenSSL validation backend");
        Assert(provider_info.userdata_capability == 4096, "provider userdata capability mismatch");

        const auto sample = ToBytes("abc");

        const auto sha256 = provider->Digest(security::core::DigestAlgorithm::SHA256, sample);
        const auto sm3 = provider->Digest(security::core::DigestAlgorithm::SM3, sample);

        Assert(ToHex(sha256) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA256 mismatch");
        Assert(ToHex(sm3) == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "SM3 mismatch");

        const auto rsa_keys = provider->GenerateKeyPair(security::core::KeyAlgorithm::RSA, 2048);
        const auto rsa_sig = provider->Sign(security::core::SignatureAlgorithm::RSA_SHA256, rsa_keys.private_key_pem, sample);
        Assert(
            provider->Verify(security::core::SignatureAlgorithm::RSA_SHA256, rsa_keys.public_key_pem, sample, rsa_sig),
            "RSA verify failed");

        const auto sm2_keys = provider->GenerateKeyPair(security::core::KeyAlgorithm::SM2, 0);
        const auto sm2_sig = provider->Sign(security::core::SignatureAlgorithm::SM2_SM3, sm2_keys.private_key_pem, sample);
        Assert(
            provider->Verify(security::core::SignatureAlgorithm::SM2_SM3, sm2_keys.public_key_pem, sample, sm2_sig),
            "SM2 verify failed");

        const auto user_data = ToBytes("userdata-demo");
        provider->WriteUserData(32, user_data.size(), user_data);
        const auto loaded_user_data = provider->ReadUserData(32, user_data.size());
        Assert(loaded_user_data == user_data, "user data read/write mismatch");

        std::cout << "Provider: " << provider_info.name
              << " | Version: " << provider_info.version
              << " | SN: " << (provider_info.sn.empty() ? "<empty>" : provider_info.sn)
              << " | UserDataCapability: " << provider_info.userdata_capability
              << std::endl;
        std::cout << "Validation passed: SHA256/SM3 digest, RSA/SM2 sign verify, and 4KB user data storage access are successful." << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Validation failed: " << ex.what() << std::endl;
        return 1;
    }
}
