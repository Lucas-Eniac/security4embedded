#pragma once

#include <string>

#include "core/error_utils.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

namespace security::providers::openssl_impl {

inline std::string GetOpenSslErrorString() {
    std::string out;
    unsigned long code = 0;
    while ((code = ERR_get_error()) != 0) {
        char buffer[256] = {0};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        if (!out.empty()) {
            out += " | ";
        }
        out += buffer;
    }
    return out;
}

inline void ThrowOpenSslError(const std::string& message) {
    const std::string details = GetOpenSslErrorString();
    if (details.empty()) {
        throw security::core::detail::StatusException(security::core::ErrorCode::CryptoBackendError, message);
    }
    throw security::core::detail::StatusException(
        security::core::ErrorCode::CryptoBackendError,
        message + ": " + details);
}

inline std::string ReadBioToString(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (!mem || !mem->data || mem->length == 0) {
        return {};
    }
    return std::string(mem->data, mem->length);
}

} // namespace security::providers::openssl_impl
