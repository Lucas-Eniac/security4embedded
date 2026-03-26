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

    virtual std::string Name() const = 0;
    virtual ProviderInfo GetProviderInfo() const = 0;

    virtual ByteBuffer Digest(DigestAlgorithm algorithm, const ByteBuffer& data) const = 0;

    virtual KeyPairPem GenerateKeyPair(KeyAlgorithm algorithm, int bits) const = 0;

    virtual ByteBuffer Sign(
        SignatureAlgorithm algorithm,
        std::string_view private_key_pem,
        const ByteBuffer& data) const = 0;

    virtual ByteBuffer ReadUserData(std::size_t offset, std::size_t length) const = 0;

    virtual void WriteUserData(std::size_t offset, std::size_t length, const ByteBuffer& data) const = 0;

    virtual bool Verify(
        SignatureAlgorithm algorithm,
        std::string_view public_key_pem,
        const ByteBuffer& data,
        const ByteBuffer& signature) const = 0;
};

class ICryptoProviderFactory {
public:
    virtual ~ICryptoProviderFactory() = default;
    virtual std::string Name() const = 0;
    virtual std::unique_ptr<ICryptoProvider> Create() const = 0;
};

} // namespace security::core
