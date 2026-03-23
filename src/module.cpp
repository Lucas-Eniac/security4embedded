#include "security/api/crypto_module.hpp"

#include <stdexcept>
#include <string>

#include "providers/openssl/openssl_factory.hpp"
#include "security/core/provider_factory.hpp"

namespace security::api {
namespace {

class CryptoModule final : public ICryptoModule {
public:
    CryptoModule() {
        security::providers::openssl_impl::RegisterOpenSslFactory();
    }

    std::unique_ptr<security::core::ICryptoProvider> CreateProvider(std::string_view backend) const override {
        return security::core::ProviderRegistry::Instance().CreateProvider(std::string(backend));
    }

    security::core::ProviderInfo GetProviderInfo(std::string_view backend) const override {
        const auto provider = CreateProvider(backend);
        return provider->GetProviderInfo();
    }

    std::vector<std::string> ListProviders() const override {
        return security::core::ProviderRegistry::Instance().ListProviders();
    }
};

} // namespace

std::unique_ptr<ICryptoModule> CreateCryptoModule() {
    return std::make_unique<CryptoModule>();
}

} // namespace security::api
