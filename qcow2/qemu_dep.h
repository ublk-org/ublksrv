// SPDX-License-Identifier: GPL-2.0
#ifndef QEMU_DEP_H 
#define QEMU_DEP_H

#include <stdint.h>

#define	 u64	uint64_t
#define	 u32	uint32_t
#define	 u16	uint16_t
#define	 u8	uint8_t

#define	 s64	int64_t
#define	 s32	int32_t
#define	 s16	int16_t
#define	 s8	int8_t

#define MiB (1U << 20)

#define QEMU_PACKED __attribute__((packed))

#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)

#include "ublksrv_tgt_endian.h"

#endif
