// SPDX-License-Identifier: GPL-2.0

#ifndef NBD_DEBUG_H
#define NBD_DEBUG_H
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Debugging macros */
#ifdef DODBG
#define NBD_DEBUG(...) printf(__VA_ARGS__)
#else
#define NBD_DEBUG(...)
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif

#ifdef __cplusplus
}
#endif
#endif
