// SPDX-License-Identifier: GPL-2.0
#ifndef UBLK_TGT_ENDIAN_H
#define UBLK_TGT_ENDIAN_H

#include <byteswap.h>

/* ublksrv target code private header, not for libublksrv user */

static inline uint16_t bswap16(uint16_t x)
{
    return bswap_16(x);
}
static inline uint32_t bswap32(uint32_t x)
{
    return bswap_32(x);
}
static inline uint64_t bswap64(uint64_t x)
{
    return bswap_64(x);
}

static inline void bswap16s(uint16_t *s)
{
    *s = bswap16(*s);
}

static inline void bswap32s(uint32_t *s)
{
    *s = bswap32(*s);
}

static inline void bswap64s(uint64_t *s)
{
    *s = bswap64(*s);
}

#ifndef glue
#define xglue(x, y) x ## y
#define glue(x, y) xglue(x, y)
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define be_bswap(v, size) (v)
#define le_bswap(v, size) glue(bswap, size)(v)
#define be_bswaps(v, size)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#else
#define le_bswap(v, size) (v)
#define be_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(v, size)
#define be_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)
#endif

/**
 * Endianness conversion functions between host cpu and specified endianness.
 * (We list the complete set of prototypes produced by the macros below
 * to assist people who search the headers to find their definitions.)
 *
 * uint16_t le16_to_cpu(uint16_t v);
 * uint32_t le32_to_cpu(uint32_t v);
 * uint64_t le64_to_cpu(uint64_t v);
 * uint16_t be16_to_cpu(uint16_t v);
 * uint32_t be32_to_cpu(uint32_t v);
 * uint64_t be64_to_cpu(uint64_t v);
 *
 * Convert the value @v from the specified format to the native
 * endianness of the host CPU by byteswapping if necessary, and
 * return the converted value.
 *
 * uint16_t cpu_to_le16(uint16_t v);
 * uint32_t cpu_to_le32(uint32_t v);
 * uint64_t cpu_to_le64(uint64_t v);
 * uint16_t cpu_to_be16(uint16_t v);
 * uint32_t cpu_to_be32(uint32_t v);
 * uint64_t cpu_to_be64(uint64_t v);
 *
 * Convert the value @v from the native endianness of the host CPU to
 * the specified format by byteswapping if necessary, and return
 * the converted value.
 *
 * void le16_to_cpus(uint16_t *v);
 * void le32_to_cpus(uint32_t *v);
 * void le64_to_cpus(uint64_t *v);
 * void be16_to_cpus(uint16_t *v);
 * void be32_to_cpus(uint32_t *v);
 * void be64_to_cpus(uint64_t *v);
 *
 * Do an in-place conversion of the value pointed to by @v from the
 * specified format to the native endianness of the host CPU.
 *
 * void cpu_to_le16s(uint16_t *v);
 * void cpu_to_le32s(uint32_t *v);
 * void cpu_to_le64s(uint64_t *v);
 * void cpu_to_be16s(uint16_t *v);
 * void cpu_to_be32s(uint32_t *v);
 * void cpu_to_be64s(uint64_t *v);
 *
 * Do an in-place conversion of the value pointed to by @v from the
 * native endianness of the host CPU to the specified format.
 *
 * Both X_to_cpu() and cpu_to_X() perform the same operation; you
 * should use whichever one is better documenting of the function your
 * code is performing.
 *
 * Do not use these functions for conversion of values which are in guest
 * memory, since the data may not be sufficiently aligned for the host CPU's
 * load and store instructions. Instead you should use the ld*_p() and
 * st*_p() functions, which perform loads and stores of data of any
 * required size and endianness and handle possible misalignment.
 */

#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}

CPU_CONVERT(be, 16, uint16_t)
CPU_CONVERT(be, 32, uint32_t)
CPU_CONVERT(be, 64, uint64_t)

CPU_CONVERT(le, 16, uint16_t)
CPU_CONVERT(le, 32, uint32_t)
CPU_CONVERT(le, 64, uint64_t)

#endif
