#include "providers/openssl/openssl_factory.hpp"

#include <memory>

#include "core/error_utils.hpp"
#include "providers/openssl/openssl_provider.hpp"
#include "security/core/provider_factory.hpp"

namespace security::providers::openssl_impl {
namespace {

class OpenSslProviderFactory final : public security::core::ICryptoProviderFactory {
public:
    std::string Name() const override {
        return "openssl";
    }

    security::core::Result<std::unique_ptr<security::core::ICryptoProvider>> Create() const override {
        try {
            return security::core::Result<std::unique_ptr<security::core::ICryptoProvider>>::Success(CreateOpenSslProvider());
        } catch (...) {
            return security::core::detail::ResultFromCurrentException<std::unique_ptr<security::core::ICryptoProvider>>(
                security::core::ErrorCode::ProviderCreationFailed);
        }
    }
};

} // namespace

security::core::Status RegisterOpenSslFactory() {
    static const security::core::Status registration_status =
        security::core::ProviderRegistry::Instance().RegisterFactory(std::make_unique<OpenSslProviderFactory>());
    return registration_status;
}

} // namespace security::providers::openssl_impl
