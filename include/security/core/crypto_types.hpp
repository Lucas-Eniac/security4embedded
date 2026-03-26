#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace security::core {

using ByteBuffer = std::vector<std::uint8_t>;

enum class DigestAlgorithm {
    SHA256,
    SM3,
};

enum class KeyAlgorithm {
    RSA,
    SM2,
};

enum class SignatureAlgorithm {
    RSA_SHA256,
    SM2_SM3,
};

struct KeyPairPem {
    std::string public_key_pem;
    std::string private_key_pem;
};

struct ProviderInfo {
    std::string name;
    std::string version;
    std::string sn;
    std::uint32_t userdata_capability = 0;
};

} // namespace security::core
