#ifndef LOGGER_H
#define LOGGER_H

/* Default includes */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Time-related includes */
#include <sys/time.h>
#include <time.h>

/* Process control includes */
#include <sys/prctl.h>

/* Android props */
#include <sys/system_properties.h>

/* Poll */
#include <poll.h>

/* JSON-C includes */
#include <json.h>

/* Defs */
#include <defs.h>

/* FuadXShell Utils includes */
#include <fuadxshell_utils.h>

ATTRIBUTES(always_inline, used) static inline void *logger(void *arg);
ATTRIBUTES(always_inline, used) static inline void collect_data(log_entry_t *, json_object *);
ATTRIBUTES(always_inline, used) void set_heuristic(char *, size_t, const char *__restrict__, ...);
ATTRIBUTES(always_inline, used) int log_msg(log_level_t level, const char *, const char *, const char *__restrict__, ...);
ATTRIBUTES(always_inline, used) int logger_init(const char *);
ATTRIBUTES(always_inline, used) void logger_shutdown(void);

#endif /* LOGGER_H */