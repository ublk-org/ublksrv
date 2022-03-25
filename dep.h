#ifndef UBDSRV_DEP_H
#define UBDSRV_DEP_H

/* from fio */

#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif

/*********type************/
typedef int bool;

#ifndef false
#define false   0
#endif

#ifndef true
#define true    1
#endif

/************ arch **************/
#ifdef __cplusplus
#define atomic_add(p, v)						\
	std::atomic_fetch_add(p, (v))
#define atomic_sub(p, v)						\
	std::atomic_fetch_sub(p, (v))
#define atomic_load_relaxed(p)					\
	std::atomic_load_explicit(p,				\
			     std::memory_order_relaxed)
#define atomic_load_acquire(p)					\
	std::atomic_load_explicit(p,				\
			     std::memory_order_acquire)
#define atomic_store_release(p, v)				\
	std::atomic_store_explicit(p, (v),			\
			     std::memory_order_release)
#else
#define atomic_add(p, v)					\
	atomic_fetch_add((_Atomic typeof(*(p)) *)(p), v)
#define atomic_sub(p, v)					\
	atomic_fetch_sub((_Atomic typeof(*(p)) *)(p), v)
#define atomic_load_relaxed(p)					\
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p),	\
			     memory_order_relaxed)
#define atomic_load_acquire(p)					\
	atomic_load_explicit((_Atomic typeof(*(p)) *)(p),	\
			     memory_order_acquire)
#define atomic_store_release(p, v)				\
	atomic_store_explicit((_Atomic typeof(*(p)) *)(p), (v),	\
			      memory_order_release)
#endif

/* just for x86_64 */
#if defined(__i386__)
#define read_barrier()            __asm__ __volatile__("": : :"memory")
#elif defined(__x86_64__)
#define read_barrier()            __asm__ __volatile__("": : :"memory")
#elif defined(__aarch64__)
#define read_barrier()   do { __sync_synchronize(); } while (0)
#elif defined(__powerpc__) || defined(__powerpc64__) || defined(__ppc__)
#define read_barrier()       __asm__ __volatile__ ("sync" : : : "memory")
#elif defined(__s390x__) || defined(__s390__)
#define read_barrier()       asm volatile("bcr 15,0" : : : "memory")
#endif

#endif
