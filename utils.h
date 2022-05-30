#ifndef UBDSRV_UTILS_INC
#define UBDSRV_UTILS_INC

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
static inline void ubdsrv_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
}

static inline void ubdsrv_printf(FILE *stream, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
}
#else
static inline void ubdsrv_log(int priority, const char *fmt, ...) { }
static inline void ubdsrv_printf(FILE *stream, const char *fmt, ...) {}
#endif

static inline unsigned ilog2(unsigned x)
{
    return sizeof(unsigned) * 8 - 1 - __builtin_clz(x);
}

#define round_up(val, rnd) \
	(((val) + (rnd - 1)) & ~(rnd - 1))

#ifndef offsetof
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#endif
#define container_of(ptr, type, member) ({                              \
	unsigned long __mptr = (unsigned long)(ptr);                    \
	((type *)(__mptr - offsetof(type, member))); })

void die(const char *fmt, ...);
char *mprintf(const char *fmt, ...);

/* Bit-mask values for 'flags' argument of create_daemon() */
#define BD_NO_CHDIR           01    /* Don't chdir("/") */
#define BD_NO_CLOSE_FILES     02    /* Don't close all open files */
#define BD_NO_REOPEN_STD_FDS  04    /* Don't reopen stdin, stdout, and
                                       stderr to /dev/null */
#define BD_NO_UMASK0         010    /* Don't do a umask(0) */
#define BD_MAX_CLOSE  8192          /* Maximum file descriptors to close if
                                       sysconf(_SC_OPEN_MAX) is indeterminate */
int start_daemon(int flags, void (*child_entry)(void *), void *data);

/* create pid file */
#define CPF_CLOEXEC 1
int create_pid_file(const char *pidFile, int flags, int *pid_fd);

#ifdef __cplusplus
}
#endif

#endif
