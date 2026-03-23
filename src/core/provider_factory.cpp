#include "security/core/provider_factory.hpp"

#include <stdexcept>

namespace security::core {

ProviderRegistry& ProviderRegistry::Instance() {
    static ProviderRegistry registry;
    return registry;
}

void ProviderRegistry::RegisterFactory(std::unique_ptr<ICryptoProviderFactory> factory) {
    if (!factory) {
        throw std::invalid_argument("factory must not be null");
    }

    const std::string backend = factory->Name();
    std::lock_guard<std::mutex> lock(mutex_);
    factories_[backend] = std::move(factory);
}

std::unique_ptr<ICryptoProvider> ProviderRegistry::CreateProvider(const std::string& backend_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = factories_.find(backend_name);
    if (it == factories_.end()) {
        throw std::runtime_error("backend not found: " + backend_name);
    }
    return it->second->Create();
}

std::vector<std::string> ProviderRegistry::ListProviders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(factories_.size());
    for (const auto& entry : factories_) {
        names.push_back(entry.first);
    }
    return names;
}

} // namespace security::core
