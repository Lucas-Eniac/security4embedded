#include "providers/openssl/openssl_provider.hpp"

#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
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
            EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free);
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
            EvpPkeyPtr key(raw, &EVP_PKEY_free);
            return ExportPem(key.get());
        }

        if (algorithm == security::core::KeyAlgorithm::SM2) {
            std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(EC_KEY_new_by_curve_name(NID_sm2), &EC_KEY_free);
            if (!ec_key) {
                ThrowOpenSslError("failed to create SM2 EC key");
            }
            if (EC_KEY_generate_key(ec_key.get()) != 1) {
                ThrowOpenSslError("SM2 key generation failed");
            }

            EvpPkeyPtr key(EVP_PKEY_new(), &EVP_PKEY_free);
            if (!key) {
                ThrowOpenSslError("failed to create EVP_PKEY for SM2");
            }
            if (EVP_PKEY_assign_EC_KEY(key.get(), ec_key.release()) != 1) {
                ThrowOpenSslError("failed to assign SM2 key to EVP_PKEY");
            }
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
