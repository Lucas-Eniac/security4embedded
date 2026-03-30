#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "security/api/export.hpp"
#include "security/core/crypto_provider.hpp"

namespace security::api {

class ICryptoModule {
public:
    virtual ~ICryptoModule() = default;

    virtual security::core::Result<std::unique_ptr<security::core::ICryptoProvider>> CreateProvider(std::string_view backend) const = 0;
    virtual security::core::Result<security::core::ProviderInfo> GetProviderInfo(std::string_view backend) const = 0;
    virtual security::core::Result<std::vector<std::string>> ListProviders() const = 0;
};

SECURITY_MODULE_EXPORT security::core::Result<std::unique_ptr<ICryptoModule>> CreateCryptoModule();

} // namespace security::api
