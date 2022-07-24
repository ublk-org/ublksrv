#ifndef UBLKSRV_UTILS_INC
#define UBLKSRV_UTILS_INC

#ifdef __cplusplus
extern "C" {
#endif

/* create pid file */
#define CPF_CLOEXEC 1
int create_pid_file(const char *pidFile, int flags, int *pid_fd);

#ifdef __cplusplus
}
#endif

#endif
