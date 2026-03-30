#include "providers/openssl/openssl_provider.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "core/error_utils.hpp"
#include "providers/openssl/openssl_helpers.hpp"

namespace security::providers::openssl_impl {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using SharedEvpPkeyPtr = std::shared_ptr<EVP_PKEY>;

constexpr const char* kDefaultSm2Id = "1234567812345678";
constexpr std::size_t kUserDataSizeBytes = 4 * 1024;
constexpr const char* kUserDataFilePath = "/tmp/openssl_userdata.bin";

const EVP_MD* ResolveDigest(security::core::DigestAlgorithm algorithm) {
    switch (algorithm) {
        case security::core::DigestAlgorithm::SHA256:
            return EVP_sha256();
        case security::core::DigestAlgorithm::SM3:
            return EVP_sm3();
        default:
            throw security::core::detail::StatusException(
                security::core::ErrorCode::UnsupportedAlgorithm,
                "digest algorithm is not supported by the OpenSSL backend");
    }
}

const EVP_MD* ResolveSignatureDigest(security::core::SignatureAlgorithm algorithm) {
    switch (algorithm) {
        case security::core::SignatureAlgorithm::RSA_SHA256:
            return EVP_sha256();
        case security::core::SignatureAlgorithm::SM2_SM3:
            return EVP_sm3();
        default:
            throw security::core::detail::StatusException(
                security::core::ErrorCode::UnsupportedAlgorithm,
                "signature algorithm is not supported by the OpenSSL backend");
    }
}

bool IsSm2Algorithm(security::core::SignatureAlgorithm algorithm) {
    return algorithm == security::core::SignatureAlgorithm::SM2_SM3;
}

void ValidateUserDataRange(std::size_t offset, std::size_t length) {
    if (offset > kUserDataSizeBytes || length > kUserDataSizeBytes - offset) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::OutOfRange,
            "user data access exceeds 4KB storage size");
    }
}

void EnsureUserDataFile() {
    namespace fs = std::filesystem;

    const fs::path path(kUserDataFilePath);
    if (!fs::exists(path)) {
        std::ofstream create_stream(path, std::ios::binary | std::ios::trunc);
        if (!create_stream) {
            throw security::core::detail::StatusException(
                security::core::ErrorCode::StorageIoError,
                "failed to create OpenSSL user data file");
        }

        security::core::ByteBuffer zeros(kUserDataSizeBytes, 0);
        create_stream.write(reinterpret_cast<const char*>(zeros.data()), static_cast<std::streamsize>(zeros.size()));
        if (!create_stream) {
            throw security::core::detail::StatusException(
                security::core::ErrorCode::StorageIoError,
                "failed to initialize OpenSSL user data file");
        }
        return;
    }

    const auto file_size = fs::file_size(path);
    if (file_size != kUserDataSizeBytes) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "OpenSSL user data file size is invalid; expected 4096 bytes");
    }
}

security::core::ByteBuffer ReadUserDataFromFile(std::size_t offset, std::size_t length) {
    ValidateUserDataRange(offset, length);
    EnsureUserDataFile();

    std::ifstream input(kUserDataFilePath, std::ios::binary);
    if (!input) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to open OpenSSL user data file for reading");
    }

    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to seek OpenSSL user data file for reading");
    }

    security::core::ByteBuffer data(length);
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(length));
    if (input.gcount() != static_cast<std::streamsize>(length)) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to read requested OpenSSL user data range");
    }
    return data;
}

void WriteUserDataToFile(std::size_t offset, std::size_t length, const security::core::ByteBuffer& data) {
    if (data.size() != length) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::InvalidArgument,
            "user data write length does not match buffer size");
    }

    ValidateUserDataRange(offset, length);
    EnsureUserDataFile();

    std::fstream output(kUserDataFilePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!output) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to open OpenSSL user data file for writing");
    }

    output.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!output) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to seek OpenSSL user data file for writing");
    }

    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(length));
    if (!output) {
        throw security::core::detail::StatusException(
            security::core::ErrorCode::StorageIoError,
            "failed to write requested OpenSSL user data range");
    }
}

EvpPkeyPtr GenerateKeyWithContext(EVP_PKEY_CTX* ctx, const char* error_prefix) {
    if (!ctx) {
        ThrowOpenSslError(std::string(error_prefix) + " context creation failed");
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        ThrowOpenSslError(std::string(error_prefix) + " keygen init failed");
    }

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &raw) != 1) {
        ThrowOpenSslError(std::string(error_prefix) + " key generation failed");
    }

    return EvpPkeyPtr(raw, &EVP_PKEY_free);
}

EvpPkeyPtr GenerateRsaKey(int bits) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), &EVP_PKEY_CTX_free);
    if (!ctx) {
        ThrowOpenSslError("failed to create RSA keygen context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        ThrowOpenSslError("RSA keygen init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) {
        ThrowOpenSslError("failed to set RSA key size");
    }

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        ThrowOpenSslError("RSA key generation failed");
    }

    return EvpPkeyPtr(raw, &EVP_PKEY_free);
}

EvpPkeyPtr GenerateSm2Key() {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr), &EVP_PKEY_CTX_free);
    return GenerateKeyWithContext(ctx.get(), "SM2");
}

security::core::KeyPairPem ExportPem(EVP_PKEY* pkey) {
    BioPtr public_bio(BIO_new(BIO_s_mem()), &BIO_free);
    BioPtr private_bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!public_bio || !private_bio) {
        ThrowOpenSslError("failed to create BIO for PEM export");
    }

    if (PEM_write_bio_PUBKEY(public_bio.get(), pkey) != 1) {
        ThrowOpenSslError("failed to export public key PEM");
    }
    if (PEM_write_bio_PrivateKey(private_bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        ThrowOpenSslError("failed to export private key PEM");
    }

    security::core::KeyPairPem pair;
    pair.public_key_pem = ReadBioToString(public_bio.get());
    pair.private_key_pem = ReadBioToString(private_bio.get());
    return pair;
}

void SetSm2IdIfNeeded(EVP_PKEY_CTX* pkey_ctx, security::core::SignatureAlgorithm algorithm) {
    if (!IsSm2Algorithm(algorithm)) {
        return;
    }
    if (EVP_PKEY_CTX_set1_id(pkey_ctx, kDefaultSm2Id, static_cast<int>(std::strlen(kDefaultSm2Id))) != 1) {
        ThrowOpenSslError("failed to set SM2 signer id");
    }
}

class OpenSslProvider final : public security::core::ICryptoProvider {
public:
    security::core::Result<std::string> Name() const override {
        return security::core::Result<std::string>::Success("openssl");
    }

    security::core::Result<security::core::ProviderInfo> GetProviderInfo() const override {
        security::core::ProviderInfo info;
        info.name = "openssl";
        info.version = OpenSSL_version(OPENSSL_VERSION);
        info.sn = {};
        info.userdata_capability = static_cast<std::uint32_t>(kUserDataSizeBytes);
        return security::core::Result<security::core::ProviderInfo>::Success(std::move(info));
    }

    security::core::Result<security::core::ByteBuffer> Digest(
        security::core::DigestAlgorithm algorithm,
        const security::core::ByteBuffer& data) const override {
        try {
            const EVP_MD* md = ResolveDigest(algorithm);

            unsigned int digest_len = EVP_MD_size(md);
            security::core::ByteBuffer digest(digest_len);

            if (EVP_Digest(data.data(), data.size(), digest.data(), &digest_len, md, nullptr) != 1) {
                ThrowOpenSslError("digest calculation failed");
            }

            digest.resize(digest_len);
            return security::core::Result<security::core::ByteBuffer>::Success(std::move(digest));
        } catch (...) {
            return security::core::detail::ResultFromCurrentException<security::core::ByteBuffer>();
        }
    }

    security::core::Result<security::core::KeyPairPem> GenerateKeyPair(
        security::core::KeyAlgorithm algorithm,
        int bits,
        std::string& id) const override {
        try {
            id.clear();
            EvpPkeyPtr key(nullptr, &EVP_PKEY_free);

            if (algorithm == security::core::KeyAlgorithm::RSA) {
                key = GenerateRsaKey(bits);
            } else if (algorithm == security::core::KeyAlgorithm::SM2) {
                key = GenerateSm2Key();
            } else {
                throw security::core::detail::StatusException(
                    security::core::ErrorCode::UnsupportedAlgorithm,
                    "key algorithm is not supported by the OpenSSL backend");
            }

            auto pair = ExportPem(key.get());
            id = StoreKeyPair(std::move(key));
            return security::core::Result<security::core::KeyPairPem>::Success(std::move(pair));
        } catch (...) {
            id.clear();
            return security::core::detail::ResultFromCurrentException<security::core::KeyPairPem>();
        }
    }

    security::core::Result<security::core::ByteBuffer> Sign(
        security::core::SignatureAlgorithm algorithm,
        std::string_view id,
        const security::core::ByteBuffer& data) const override {
        try {
            SharedEvpPkeyPtr key = LookupKeyPair(id);
            EvpMdCtxPtr md_ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
            if (!md_ctx) {
                ThrowOpenSslError("failed to create sign context");
            }

            EVP_PKEY_CTX* pkey_ctx = nullptr;
            if (EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, ResolveSignatureDigest(algorithm), nullptr, key.get()) != 1) {
                ThrowOpenSslError("DigestSignInit failed");
            }
            SetSm2IdIfNeeded(pkey_ctx, algorithm);

            if (EVP_DigestSignUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
                ThrowOpenSslError("DigestSignUpdate failed");
            }

            size_t sig_len = 0;
            if (EVP_DigestSignFinal(md_ctx.get(), nullptr, &sig_len) != 1) {
                ThrowOpenSslError("DigestSignFinal length query failed");
            }

            security::core::ByteBuffer signature(sig_len);
            if (EVP_DigestSignFinal(md_ctx.get(), signature.data(), &sig_len) != 1) {
                ThrowOpenSslError("DigestSignFinal failed");
            }
            signature.resize(sig_len);
            return security::core::Result<security::core::ByteBuffer>::Success(std::move(signature));
        } catch (...) {
            return security::core::detail::ResultFromCurrentException<security::core::ByteBuffer>();
        }
    }

    security::core::Result<security::core::ByteBuffer> ReadUserData(std::size_t offset, std::size_t length) const override {
        try {
            return security::core::Result<security::core::ByteBuffer>::Success(ReadUserDataFromFile(offset, length));
        } catch (...) {
            return security::core::detail::ResultFromCurrentException<security::core::ByteBuffer>();
        }
    }

    security::core::Status WriteUserData(
        std::size_t offset,
        std::size_t length,
        const security::core::ByteBuffer& data) const override {
        try {
            WriteUserDataToFile(offset, length, data);
            return security::core::Status::Success();
        } catch (...) {
            return security::core::detail::StatusFromCurrentException();
        }
    }

    security::core::Result<bool> Verify(
        security::core::SignatureAlgorithm algorithm,
        std::string_view id,
        const security::core::ByteBuffer& data,
        const security::core::ByteBuffer& signature) const override {
        try {
            SharedEvpPkeyPtr key = LookupKeyPair(id);
            EvpMdCtxPtr md_ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
            if (!md_ctx) {
                ThrowOpenSslError("failed to create verify context");
            }

            EVP_PKEY_CTX* pkey_ctx = nullptr;
            if (EVP_DigestVerifyInit(md_ctx.get(), &pkey_ctx, ResolveSignatureDigest(algorithm), nullptr, key.get()) != 1) {
                ThrowOpenSslError("DigestVerifyInit failed");
            }
            SetSm2IdIfNeeded(pkey_ctx, algorithm);

            if (EVP_DigestVerifyUpdate(md_ctx.get(), data.data(), data.size()) != 1) {
                ThrowOpenSslError("DigestVerifyUpdate failed");
            }

            const int rc = EVP_DigestVerifyFinal(md_ctx.get(), signature.data(), signature.size());
            if (rc == 1) {
                return security::core::Result<bool>::Success(true);
            }
            if (rc == 0) {
                return security::core::Result<bool>::Success(false);
            }
            ThrowOpenSslError("DigestVerifyFinal failed");
            return security::core::Result<bool>::Failure(security::core::ErrorCode::CryptoBackendError);
        } catch (...) {
            return security::core::detail::ResultFromCurrentException<bool>();
        }
    }

private:
    std::string StoreKeyPair(EvpPkeyPtr key) const {
        if (!key) {
            throw security::core::detail::StatusException(
                security::core::ErrorCode::InvalidArgument,
                "cannot store empty key pair");
        }

        std::lock_guard<std::mutex> lock(key_pairs_mutex_);
        const std::string id = "keypair-" + std::to_string(next_key_pair_id_++);
        key_pairs_.emplace(id, SharedEvpPkeyPtr(key.release(), &EVP_PKEY_free));
        return id;
    }

    SharedEvpPkeyPtr LookupKeyPair(std::string_view id) const {
        std::lock_guard<std::mutex> lock(key_pairs_mutex_);
        const auto it = key_pairs_.find(std::string(id));
        if (it == key_pairs_.end()) {
            throw security::core::detail::StatusException(security::core::ErrorCode::KeyNotFound, std::string(id));
        }
        return it->second;
    }

    mutable std::mutex key_pairs_mutex_;
    mutable std::unordered_map<std::string, SharedEvpPkeyPtr> key_pairs_;
    mutable std::uint64_t next_key_pair_id_ = 1;
};

} // namespace

std::unique_ptr<security::core::ICryptoProvider> CreateOpenSslProvider() {
    return std::make_unique<OpenSslProvider>();
}

} // namespace security::providers::openssl_impl
