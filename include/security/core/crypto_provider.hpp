#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "security/core/crypto_types.hpp"

namespace security::core {

class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    virtual Result<std::string> Name() const = 0;
    virtual Result<ProviderInfo> GetProviderInfo() const = 0;

    virtual Result<ByteBuffer> Digest(DigestAlgorithm algorithm, const ByteBuffer& data) const = 0;

    virtual Result<KeyPairPem> GenerateKeyPair(KeyAlgorithm algorithm, int bits, std::string& id) const = 0;

    virtual Result<ByteBuffer> Sign(
        SignatureAlgorithm algorithm,
        std::string_view id,
        const ByteBuffer& data) const = 0;

    virtual Result<ByteBuffer> ReadUserData(std::size_t offset, std::size_t length) const = 0;

    virtual Status WriteUserData(std::size_t offset, std::size_t length, const ByteBuffer& data) const = 0;

    virtual Result<bool> Verify(
        SignatureAlgorithm algorithm,
        std::string_view id,
        const ByteBuffer& data,
        const ByteBuffer& signature) const = 0;
};

class ICryptoProviderFactory {
public:
    virtual ~ICryptoProviderFactory() = default;
    virtual std::string Name() const = 0;
    virtual Result<std::unique_ptr<ICryptoProvider>> Create() const = 0;
};

} // namespace security::core
