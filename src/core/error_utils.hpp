#pragma once

#include <exception>
#include <stdexcept>
#include <string>
#include <utility>

#include "security/core/crypto_types.hpp"

namespace security::core::detail {

class StatusException final : public std::exception {
public:
    StatusException(ErrorCode code, std::string detail)
        : code_(code), detail_(std::move(detail)), message_(ComposeErrorMessage(code_, detail_)) {}

    ErrorCode code() const noexcept {
        return code_;
    }

    const std::string& detail() const noexcept {
        return detail_;
    }

    const char* what() const noexcept override {
        return message_.c_str();
    }

private:
    ErrorCode code_;
    std::string detail_;
    std::string message_;
};

inline Status StatusFromException(const StatusException& ex) {
    return Status::Failure(ex.code(), ex.detail());
}

inline Status StatusFromCurrentException(ErrorCode fallback = ErrorCode::InternalError) {
    try {
        throw;
    } catch (const StatusException& ex) {
        return StatusFromException(ex);
    } catch (const std::invalid_argument& ex) {
        return Status::Failure(ErrorCode::InvalidArgument, ex.what());
    } catch (const std::out_of_range& ex) {
        return Status::Failure(ErrorCode::OutOfRange, ex.what());
    } catch (const std::exception& ex) {
        return Status::Failure(fallback, ex.what());
    } catch (...) {
        return Status::Failure(fallback, "unknown exception");
    }
}

template <typename T>
inline Result<T> ResultFromCurrentException(ErrorCode fallback = ErrorCode::InternalError) {
    return Result<T>::Failure(StatusFromCurrentException(fallback));
}

} // namespace security::core::detail