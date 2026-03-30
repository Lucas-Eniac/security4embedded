#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace security::core {

using ByteBuffer = std::vector<std::uint8_t>;

enum class DigestAlgorithm {
    SHA256,
    SM3,
};

enum class KeyAlgorithm {
    RSA,
    SM2,
};

enum class SignatureAlgorithm {
    RSA_SHA256,
    SM2_SM3,
};

struct KeyPairPem {
    std::string public_key_pem;
    std::string private_key_pem;
};

struct ProviderInfo {
    std::string name;
    std::string version;
    std::string sn;
    std::uint32_t userdata_capability = 0;
};

enum class ErrorCode {
    Ok,
    InvalidArgument,
    OutOfRange,
    UnsupportedAlgorithm,
    ProviderNotFound,
    ProviderRegistrationFailed,
    ProviderCreationFailed,
    SemaphoreOpenFailed,
    SemaphoreTimeout,
    SemaphoreAcquireFailed,
    StorageIoError,
    KeyNotFound,
    CryptoBackendError,
    InternalError,
};

inline const char* ErrorMessage(ErrorCode code) {
    switch (code) {
        case ErrorCode::Ok:
            return "success";
        case ErrorCode::InvalidArgument:
            return "invalid argument";
        case ErrorCode::OutOfRange:
            return "value is out of range";
        case ErrorCode::UnsupportedAlgorithm:
            return "unsupported algorithm";
        case ErrorCode::ProviderNotFound:
            return "provider not found";
        case ErrorCode::ProviderRegistrationFailed:
            return "provider registration failed";
        case ErrorCode::ProviderCreationFailed:
            return "provider creation failed";
        case ErrorCode::SemaphoreOpenFailed:
            return "failed to open exclusive-access semaphore";
        case ErrorCode::SemaphoreTimeout:
            return "timed out waiting for exclusive access";
        case ErrorCode::SemaphoreAcquireFailed:
            return "failed to acquire exclusive access";
        case ErrorCode::StorageIoError:
            return "user data storage I/O failed";
        case ErrorCode::KeyNotFound:
            return "key pair id not found";
        case ErrorCode::CryptoBackendError:
            return "cryptographic backend operation failed";
        case ErrorCode::InternalError:
            return "internal error";
        default:
            return "unknown error";
    }
}

inline std::string ComposeErrorMessage(ErrorCode code, const std::string& detail) {
    if (detail.empty()) {
        return ErrorMessage(code);
    }
    return std::string(ErrorMessage(code)) + ": " + detail;
}

struct Status {
    ErrorCode code = ErrorCode::Ok;
    std::string message = ErrorMessage(ErrorCode::Ok);

    bool ok() const {
        return code == ErrorCode::Ok;
    }

    static Status Success() {
        return {};
    }

    static Status Failure(ErrorCode code, std::string detail = {}) {
        return Status{code, ComposeErrorMessage(code, detail)};
    }
};

template <typename T>
struct Result {
    Status status = Status::Success();
    T value{};

    bool ok() const {
        return status.ok();
    }

    static Result Success(T result_value) {
        return Result{Status::Success(), std::move(result_value)};
    }

    static Result Failure(ErrorCode code, std::string detail = {}) {
        return Result{Status::Failure(code, std::move(detail)), {}};
    }

    static Result Failure(Status failure_status) {
        return Result{std::move(failure_status), {}};
    }
};

} // namespace security::core
