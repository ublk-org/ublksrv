// SPDX-License-Identifier: MIT or LGPL-2.1-only

#ifndef UBLKSRV_UTILS_INC_H
#define UBLKSRV_UTILS_INC_H

#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int ublksrv_gettid(void)
{
	return syscall(SYS_gettid);
}

static inline void ublksrv_log(int priority, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
static inline void ublksrv_printf(FILE *stream, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#ifdef DEBUG
static inline void ublksrv_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
}

static inline void ublksrv_printf(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
}
#else
static inline void ublksrv_log(int priority, const char *fmt, ...) { }
static inline void ublksrv_printf(FILE *stream, const char *fmt, ...) {}
#endif

extern void ublk_err(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

#define round_up(val, rnd) \
	(((val) + ((rnd) - 1)) & ~((rnd) - 1))

#ifndef offsetof
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                              \
	unsigned long __mptr = (unsigned long)(ptr);                    \
	((type *)(__mptr - offsetof(type, member))); })
#endif

#ifdef __cplusplus
}
#endif

#endif
