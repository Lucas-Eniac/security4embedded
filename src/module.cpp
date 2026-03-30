#include "security/api/crypto_module.hpp"

#include <string>

#include "core/error_utils.hpp"
#include "providers/openssl/openssl_factory.hpp"
#include "security/core/provider_factory.hpp"

namespace security::api {
namespace {

class CryptoModule final : public ICryptoModule {
public:
    security::core::Result<std::unique_ptr<security::core::ICryptoProvider>> CreateProvider(std::string_view backend) const override {
        return security::core::ProviderRegistry::Instance().CreateProvider(std::string(backend));
    }

    security::core::Result<security::core::ProviderInfo> GetProviderInfo(std::string_view backend) const override {
        const auto provider = CreateProvider(backend);
        if (!provider.ok()) {
            return security::core::Result<security::core::ProviderInfo>::Failure(provider.status);
        }
        return provider.value->GetProviderInfo();
    }

    security::core::Result<std::vector<std::string>> ListProviders() const override {
        return security::core::ProviderRegistry::Instance().ListProviders();
    }
};

} // namespace

security::core::Result<std::unique_ptr<ICryptoModule>> CreateCryptoModule() {
    const auto registration_status = security::providers::openssl_impl::RegisterOpenSslFactory();
    if (!registration_status.ok()) {
        return security::core::Result<std::unique_ptr<ICryptoModule>>::Failure(registration_status);
    }

    try {
        return security::core::Result<std::unique_ptr<ICryptoModule>>::Success(std::make_unique<CryptoModule>());
    } catch (...) {
        return security::core::Result<std::unique_ptr<ICryptoModule>>::Failure(
            security::core::detail::StatusFromCurrentException(security::core::ErrorCode::InternalError));
    }
}

} // namespace security::api
