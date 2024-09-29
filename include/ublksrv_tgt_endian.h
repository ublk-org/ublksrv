// SPDX-License-Identifier: MIT or GPL-2.0-only
#ifndef UBLK_TGT_ENDIAN_H
#define UBLK_TGT_ENDIAN_H

#include <byteswap.h>

/* ublksrv target code private header, not for libublksrv user */

#define HOST_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
	return endian ## size ## toh(v); \
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
	return hto ## endian ## size(v); \
}\

HOST_CONVERT(be, 16, uint16_t)
HOST_CONVERT(be, 32, uint32_t)
HOST_CONVERT(be, 64, uint64_t)

HOST_CONVERT(le, 16, uint16_t)
HOST_CONVERT(le, 32, uint32_t)
HOST_CONVERT(le, 64, uint64_t)

#endif
