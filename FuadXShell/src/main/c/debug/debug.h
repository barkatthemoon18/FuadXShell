#ifndef DEBUG_H
#define DEBUG_H

/* Default includes */
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

/* Android includes */
#include <sys/system_properties.h>

/* Logger */
#include <logger.h>

/* Defs */
#include <defs.h>

/* Macro debug error values */
#define DEBUG_PTRACE_TRACEME_ACTIVE (90)
#define DEBUG_TRACER_PID (91)
#define DEBUG_TRACE_STOP (92)
#define DEBUG_JDWP_ALLOWED (93)
#define DEBUG_JDWP_LIB (94)
#define DEBUG_BRKT_HIT (95)
#define DEBUG_TRACE_EVENT_WCHAN (96)
#define DEBUG_IDA_SOCKET (97)

typedef struct trap_event_t trap_event_t;

ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void get_random(uint32_t *, size_t);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void trap_handler(int, siginfo_t *, void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline int set_handlers(void);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_ptrace_traceme(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_debug_property(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_brk(void *);
_Noreturn ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *monitor_signal_handler(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) int detect_debug(void);

ATTRIBUTES(always_inline, used) static inline bool check_port(int, int);
ATTRIBUTES(always_inline, used) static inline void *check_traceme(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_jdwp(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_jdwp_so(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_tracepid(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_ptrace_stop(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_trace_stop(void *arg);
ATTRIBUTES(always_inline, used) static inline void *check_ida(void *arg);
ATTRIBUTES(always_inline, used) int check_precon(void);

#endif /* DEBUG_H */