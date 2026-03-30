#pragma once

#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <memory>
#include <semaphore.h>
#include <string>
#include <string_view>
#include <utility>

#include "core/error_utils.hpp"
#include "security/core/crypto_provider.hpp"

namespace security::core {
namespace detail {

constexpr long kSemaphoreWaitTimeoutSeconds = 5;

[[noreturn]] inline void ThrowSemaphoreError(ErrorCode code, std::string_view message) {
    throw StatusException(code, std::string(message) + ": " + std::strerror(errno));
}

inline timespec MakeSemaphoreDeadline() {
    timespec deadline{};
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
        ThrowSemaphoreError(ErrorCode::SemaphoreAcquireFailed, "failed to get semaphore timeout clock");
    }

    deadline.tv_sec += kSemaphoreWaitTimeoutSeconds;
    return deadline;
}

class LinuxNamedSemaphore final {
public:
    explicit LinuxNamedSemaphore(const char* name) : handle_(sem_open(name, O_CREAT, 0600, 1)) {
        if (handle_ == SEM_FAILED) {
            ThrowSemaphoreError(ErrorCode::SemaphoreOpenFailed, "failed to open module semaphore");
        }
    }

    LinuxNamedSemaphore(const LinuxNamedSemaphore&) = delete;
    LinuxNamedSemaphore& operator=(const LinuxNamedSemaphore&) = delete;

    ~LinuxNamedSemaphore() {
        if (handle_ != SEM_FAILED) {
            sem_close(handle_);
        }
    }

    void Acquire() {
        const timespec deadline = MakeSemaphoreDeadline();
        while (sem_timedwait(handle_, &deadline) == -1) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ETIMEDOUT) {
                throw StatusException(ErrorCode::SemaphoreTimeout, "module semaphore wait exceeded 5 seconds");
            }
            ThrowSemaphoreError(ErrorCode::SemaphoreAcquireFailed, "failed to acquire module semaphore");
        }
    }

    void Release() noexcept {
        if (handle_ != SEM_FAILED) {
            sem_post(handle_);
        }
    }

private:
    sem_t* handle_ = SEM_FAILED;
};

inline LinuxNamedSemaphore& ModuleSemaphore() {
    static LinuxNamedSemaphore semaphore("/security_module_hw_lock");
    return semaphore;
}

class SemaphoreLock final {
public:
    explicit SemaphoreLock(LinuxNamedSemaphore& semaphore) : semaphore_(semaphore) {
        semaphore_.Acquire();
    }

    SemaphoreLock(const SemaphoreLock&) = delete;
    SemaphoreLock& operator=(const SemaphoreLock&) = delete;

    ~SemaphoreLock() {
        semaphore_.Release();
    }

private:
    LinuxNamedSemaphore& semaphore_;
};

} // namespace detail

class ExclusiveCryptoProvider final : public ICryptoProvider {
public:
    explicit ExclusiveCryptoProvider(std::unique_ptr<ICryptoProvider> provider) : provider_(std::move(provider)) {
        if (!provider_) {
            throw detail::StatusException(ErrorCode::InvalidArgument, "provider must not be null");
        }
    }

    Result<std::string> Name() const override {
        return WithExclusiveResult<std::string>([this]() { return provider_->Name(); });
    }

    Result<ProviderInfo> GetProviderInfo() const override {
        return WithExclusiveResult<ProviderInfo>([this]() { return provider_->GetProviderInfo(); });
    }

    Result<ByteBuffer> Digest(DigestAlgorithm algorithm, const ByteBuffer& data) const override {
        return WithExclusiveResult<ByteBuffer>([this, algorithm, &data]() { return provider_->Digest(algorithm, data); });
    }

    Result<KeyPairPem> GenerateKeyPair(KeyAlgorithm algorithm, int bits, std::string& id) const override {
        return WithExclusiveResult<KeyPairPem>(
            [this, algorithm, bits, &id]() { return provider_->GenerateKeyPair(algorithm, bits, id); });
    }

    Result<ByteBuffer> Sign(SignatureAlgorithm algorithm, std::string_view id, const ByteBuffer& data) const override {
        return WithExclusiveResult<ByteBuffer>([this, algorithm, id, &data]() { return provider_->Sign(algorithm, id, data); });
    }

    Result<ByteBuffer> ReadUserData(std::size_t offset, std::size_t length) const override {
        return WithExclusiveResult<ByteBuffer>([this, offset, length]() { return provider_->ReadUserData(offset, length); });
    }

    Status WriteUserData(std::size_t offset, std::size_t length, const ByteBuffer& data) const override {
        return WithExclusiveStatus([this, offset, length, &data]() { return provider_->WriteUserData(offset, length, data); });
    }

    Result<bool> Verify(
        SignatureAlgorithm algorithm,
        std::string_view id,
        const ByteBuffer& data,
        const ByteBuffer& signature) const override {
        return WithExclusiveResult<bool>(
            [this, algorithm, id, &data, &signature]() {
                return provider_->Verify(algorithm, id, data, signature);
            });
    }

private:
    template <typename T, typename Operation>
    Result<T> WithExclusiveResult(Operation&& operation) const {
        try {
            detail::SemaphoreLock lock(detail::ModuleSemaphore());
            return std::forward<Operation>(operation)();
        } catch (...) {
            return detail::ResultFromCurrentException<T>();
        }
    }

    template <typename Operation>
    Status WithExclusiveStatus(Operation&& operation) const {
        try {
            detail::SemaphoreLock lock(detail::ModuleSemaphore());
            return std::forward<Operation>(operation)();
        } catch (...) {
            return detail::StatusFromCurrentException();
        }
    }

    std::unique_ptr<ICryptoProvider> provider_;
};

inline std::unique_ptr<ICryptoProvider> MakeExclusiveProvider(std::unique_ptr<ICryptoProvider> provider) {
    return std::make_unique<ExclusiveCryptoProvider>(std::move(provider));
}

} // namespace security::core