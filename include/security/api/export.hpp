#pragma once

#if defined(_WIN32)
#if defined(SECURITY_MODULE_BUILD)
#define SECURITY_MODULE_EXPORT __declspec(dllexport)
#else
#define SECURITY_MODULE_EXPORT __declspec(dllimport)
#endif
#else
#define SECURITY_MODULE_EXPORT __attribute__((visibility("default")))
#endif
