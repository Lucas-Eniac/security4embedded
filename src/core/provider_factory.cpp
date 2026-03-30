#include "security/core/provider_factory.hpp"

#include "core/error_utils.hpp"
#include "core/exclusive_provider.hpp"

namespace security::core {

ProviderRegistry& ProviderRegistry::Instance() {
    static ProviderRegistry registry;
    return registry;
}

Status ProviderRegistry::RegisterFactory(std::unique_ptr<ICryptoProviderFactory> factory) {
    if (!factory) {
        return Status::Failure(ErrorCode::InvalidArgument, "factory must not be null");
    }

    try {
        const std::string backend = factory->Name();
        std::lock_guard<std::mutex> lock(mutex_);
        factories_[backend] = std::move(factory);
        return Status::Success();
    } catch (...) {
        return detail::StatusFromCurrentException(ErrorCode::ProviderRegistrationFailed);
    }
}

Result<std::unique_ptr<ICryptoProvider>> ProviderRegistry::CreateProvider(const std::string& backend_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = factories_.find(backend_name);
    if (it == factories_.end()) {
        return Result<std::unique_ptr<ICryptoProvider>>::Failure(ErrorCode::ProviderNotFound, backend_name);
    }

    auto provider_result = it->second->Create();
    if (!provider_result.ok()) {
        return provider_result;
    }

    try {
        return Result<std::unique_ptr<ICryptoProvider>>::Success(MakeExclusiveProvider(std::move(provider_result.value)));
    } catch (...) {
        return detail::ResultFromCurrentException<std::unique_ptr<ICryptoProvider>>(ErrorCode::ProviderCreationFailed);
    }
}

Result<std::vector<std::string>> ProviderRegistry::ListProviders() const {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> names;
        names.reserve(factories_.size());
        for (const auto& entry : factories_) {
            names.push_back(entry.first);
        }
        return Result<std::vector<std::string>>::Success(std::move(names));
    } catch (...) {
        return detail::ResultFromCurrentException<std::vector<std::string>>(ErrorCode::InternalError);
    }
}

} // namespace security::core
