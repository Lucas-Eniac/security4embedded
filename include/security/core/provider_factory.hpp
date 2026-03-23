#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "security/core/crypto_provider.hpp"

namespace security::core {

class ProviderRegistry {
public:
    static ProviderRegistry& Instance();

    void RegisterFactory(std::unique_ptr<ICryptoProviderFactory> factory);

    std::unique_ptr<ICryptoProvider> CreateProvider(const std::string& backend_name) const;

    std::vector<std::string> ListProviders() const;

private:
    ProviderRegistry() = default;
    ProviderRegistry(const ProviderRegistry&) = delete;
    ProviderRegistry& operator=(const ProviderRegistry&) = delete;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<ICryptoProviderFactory>> factories_;
};

} // namespace security::core
