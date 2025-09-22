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

cpu_set_t *ublk_make_cpuset(int num_sets, const char *cpuset);

static inline int ublksrv_gettid(void)
{
	return syscall(SYS_gettid);
}

/* The following two are obsolete, use new ublk_err/ublk_dbg/ublk_log */
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
    va_end(ap);
}

static inline void ublksrv_printf(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
    va_end(ap);
}
#else
static inline void ublksrv_log(int priority, const char *fmt, ...) { }
static inline void ublksrv_printf(FILE *stream, const char *fmt, ...) {}
#endif

/* 32bit debug mask, high 16 bits are for target code, and low 16 bits for lib */
#define	UBLK_DBG_DEV		(1U << 0)
#define	UBLK_DBG_QUEUE		(1U << 1)
#define	UBLK_DBG_IO_CMD		(1U << 2)
#define	UBLK_DBG_IO		(1U << 3)
#define	UBLK_DBG_CTRL_CMD	(1U << 4)

#ifdef DEBUG
extern void ublk_dbg(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern void ublk_ctrl_dbg(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
#else
static inline void ublk_dbg(int level, const char *fmt, ...) { }
static inline void ublk_ctrl_dbg(int level, const char *fmt, ...) { }
#endif

extern void ublk_set_debug_mask(unsigned mask);
extern unsigned ublk_get_debug_mask(unsigned mask);

extern void ublk_log(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
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

#define ublk_ignore_result(x) ({ typeof(x) z = x; (void)sizeof z; })

#ifdef __cplusplus
}
#endif

#endif
