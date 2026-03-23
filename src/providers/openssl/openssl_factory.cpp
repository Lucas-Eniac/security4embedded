#include "providers/openssl/openssl_factory.hpp"

#include <mutex>
#include <memory>

#include "providers/openssl/openssl_provider.hpp"
#include "security/core/provider_factory.hpp"

namespace security::providers::openssl_impl {
namespace {

class OpenSslProviderFactory final : public security::core::ICryptoProviderFactory {
public:
    std::string Name() const override {
        return "openssl";
    }

    std::unique_ptr<security::core::ICryptoProvider> Create() const override {
        return CreateOpenSslProvider();
    }
};

} // namespace

void RegisterOpenSslFactory() {
    static std::once_flag once;
    std::call_once(once, []() {
        security::core::ProviderRegistry::Instance().RegisterFactory(std::make_unique<OpenSslProviderFactory>());
    });
}

} // namespace security::providers::openssl_impl
