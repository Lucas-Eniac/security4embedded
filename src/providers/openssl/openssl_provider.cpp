#include "providers/openssl/openssl_provider.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "providers/openssl/openssl_helpers.hpp"

namespace security::providers::openssl_impl {
namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

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
            throw std::invalid_argument("unsupported digest algorithm");
    }
}

const EVP_MD* ResolveSignatureDigest(security::core::SignatureAlgorithm algorithm) {
    switch (algorithm) {
        case security::core::SignatureAlgorithm::RSA_SHA256:
            return EVP_sha256();
        case security::core::SignatureAlgorithm::SM2_SM3:
            return EVP_sm3();
        default:
            throw std::invalid_argument("unsupported signature algorithm");
    }
}

bool IsSm2Algorithm(security::core::SignatureAlgorithm algorithm) {
    return algorithm == security::core::SignatureAlgorithm::SM2_SM3;
}

void ValidateUserDataRange(std::size_t offset, std::size_t length) {
    if (offset > kUserDataSizeBytes || length > kUserDataSizeBytes - offset) {
        throw std::out_of_range("user data access exceeds 4KB storage size");
    }
}

void EnsureUserDataFile() {
    namespace fs = std::filesystem;

    const fs::path path(kUserDataFilePath);
    if (!fs::exists(path)) {
        std::ofstream create_stream(path, std::ios::binary | std::ios::trunc);
        if (!create_stream) {
            throw std::runtime_error("failed to create OpenSSL user data file");
        }

        security::core::ByteBuffer zeros(kUserDataSizeBytes, 0);
        create_stream.write(reinterpret_cast<const char*>(zeros.data()), static_cast<std::streamsize>(zeros.size()));
        if (!create_stream) {
            throw std::runtime_error("failed to initialize OpenSSL user data file");
        }
        return;
    }

    const auto file_size = fs::file_size(path);
    if (file_size != kUserDataSizeBytes) {
        throw std::runtime_error("OpenSSL user data file size is invalid; expected 4096 bytes");
    }
}

security::core::ByteBuffer ReadUserDataFromFile(std::size_t offset, std::size_t length) {
    ValidateUserDataRange(offset, length);
    EnsureUserDataFile();

    std::ifstream input(kUserDataFilePath, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open OpenSSL user data file for reading");
    }

    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) {
        throw std::runtime_error("failed to seek OpenSSL user data file for reading");
    }

    security::core::ByteBuffer data(length);
    input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(length));
    if (input.gcount() != static_cast<std::streamsize>(length)) {
        throw std::runtime_error("failed to read requested OpenSSL user data range");
    }
    return data;
}

void WriteUserDataToFile(std::size_t offset, std::size_t length, const security::core::ByteBuffer& data) {
    if (data.size() != length) {
        throw std::invalid_argument("user data write length does not match buffer size");
    }

    ValidateUserDataRange(offset, length);
    EnsureUserDataFile();

    std::fstream output(kUserDataFilePath, std::ios::binary | std::ios::in | std::ios::out);
    if (!output) {
        throw std::runtime_error("failed to open OpenSSL user data file for writing");
    }

    output.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!output) {
        throw std::runtime_error("failed to seek OpenSSL user data file for writing");
    }

    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(length));
    if (!output) {
        throw std::runtime_error("failed to write requested OpenSSL user data range");
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

EvpPkeyPtr LoadPrivateKey(std::string_view private_key_pem) {
    BioPtr bio(BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size())), &BIO_free);
    if (!bio) {
        ThrowOpenSslError("failed to create BIO for private key");
    }

    EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        ThrowOpenSslError("failed to parse private key PEM");
    }
    return EvpPkeyPtr(raw, &EVP_PKEY_free);
}

EvpPkeyPtr LoadPublicKey(std::string_view public_key_pem) {
    BioPtr bio(BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size())), &BIO_free);
    if (!bio) {
        ThrowOpenSslError("failed to create BIO for public key");
    }

    EVP_PKEY* raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        ThrowOpenSslError("failed to parse public key PEM");
    }
    return EvpPkeyPtr(raw, &EVP_PKEY_free);
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
    std::string Name() const override {
        return "openssl";
    }

    security::core::ProviderInfo GetProviderInfo() const override {
        security::core::ProviderInfo info;
        info.name = "openssl";
        info.version = OpenSSL_version(OPENSSL_VERSION);
        info.sn = {};
        info.userdata_capability = static_cast<std::uint32_t>(kUserDataSizeBytes);
        return info;
    }

    security::core::ByteBuffer Digest(
        security::core::DigestAlgorithm algorithm,
        const security::core::ByteBuffer& data) const override {
        const EVP_MD* md = ResolveDigest(algorithm);

        unsigned int digest_len = EVP_MD_size(md);
        security::core::ByteBuffer digest(digest_len);

        if (EVP_Digest(data.data(), data.size(), digest.data(), &digest_len, md, nullptr) != 1) {
            ThrowOpenSslError("digest calculation failed");
        }

        digest.resize(digest_len);
        return digest;
    }

    security::core::KeyPairPem GenerateKeyPair(security::core::KeyAlgorithm algorithm, int bits) const override {
        if (algorithm == security::core::KeyAlgorithm::RSA) {
            EvpPkeyPtr key = GenerateRsaKey(bits);
            return ExportPem(key.get());
        }

        if (algorithm == security::core::KeyAlgorithm::SM2) {
            EvpPkeyPtr key = GenerateSm2Key();
            return ExportPem(key.get());
        }

        throw std::invalid_argument("unsupported key algorithm");
    }

    security::core::ByteBuffer Sign(
        security::core::SignatureAlgorithm algorithm,
        std::string_view private_key_pem,
        const security::core::ByteBuffer& data) const override {
        EvpPkeyPtr key = LoadPrivateKey(private_key_pem);
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
        return signature;
    }

    security::core::ByteBuffer ReadUserData(std::size_t offset, std::size_t length) const override {
        return ReadUserDataFromFile(offset, length);
    }

    void WriteUserData(std::size_t offset, std::size_t length, const security::core::ByteBuffer& data) const override {
        WriteUserDataToFile(offset, length, data);
    }

    bool Verify(
        security::core::SignatureAlgorithm algorithm,
        std::string_view public_key_pem,
        const security::core::ByteBuffer& data,
        const security::core::ByteBuffer& signature) const override {
        EvpPkeyPtr key = LoadPublicKey(public_key_pem);
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
            return true;
        }
        if (rc == 0) {
            return false;
        }
        ThrowOpenSslError("DigestVerifyFinal failed");
        return false;
    }
};

} // namespace

std::unique_ptr<security::core::ICryptoProvider> CreateOpenSslProvider() {
    return std::make_unique<OpenSslProvider>();
}

} // namespace security::providers::openssl_impl
