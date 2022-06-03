#ifndef UBDSRV_UTILS_INC
#define UBDSRV_UTILS_INC

#include <coroutine>
#include <iostream>

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

/* For using C++20 coroutine */
/*
 * Due to the use of std::cout, the member functions await_ready,
 * await_suspend, and await_resume cannot be declared as constexpr.
 */
struct ubd_suspend_always {
    bool await_ready() const noexcept {
        return false;
    }
    void await_suspend(std::coroutine_handle<>) const noexcept {
    }
    void await_resume() const noexcept {
    }
};

/*
 * When you don't resume the Awaitable such as the coroutine object returned
 * by the member function final_suspend, the function await_resume is not
 * processed. In contrast, the Awaitable's ubd_suspend_never the function is
 * immediately ready because await_ready returns true and, hence, does
 * not suspend.
 */
struct ubd_suspend_never {
    bool await_ready() const noexcept {
        return true;
    }
    void await_suspend(std::coroutine_handle<>) const noexcept {
    }
    void await_resume() const noexcept {
    }
};

using co_handle_type = std::coroutine_handle<>;
struct co_io_job {
    struct promise_type {
        co_io_job get_return_object() {
            return {std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        ubd_suspend_never initial_suspend() {
            return {};
        }
        ubd_suspend_never final_suspend() noexcept {
            return {};
        }
        void return_void() {}
        void unhandled_exception() {}
    };

    co_handle_type coro;

    co_io_job(co_handle_type h): coro(h){}

    void resume() {
        coro.resume();
    }

    operator co_handle_type() const { return coro; }
};

/*
 * c++20 is stackless coroutine, and can't handle nested coroutine, so
 * the following two have to be defined as macro
 */
#define co_io_job_submit_and_wait() do {		\
	co_await ubd_suspend_always();			\
} while (0)

#define co_io_job_return() do {		\
	co_return;			\
} while (0)

#endif
