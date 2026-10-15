#ifndef ROOT_H
#define ROOT_H

#include <stdlib.h>
#include <jni.h>
#include <android/log.h>
#include <unistd.h>

#define ATTRIBUTES(...) __attribute__((__VA_ARGS__))

ATTRIBUTES(always_inline, constructor(100), used) static inline void init(void);
ATTRIBUTES(always_inline, constructor(101), section(".textld"), used) static inline void init_sd(void);

/* Load JNIEnv */
ATTRIBUTES(always_inline, section(".textld"), used) static inline int loadenv(JavaVM *, void *);

/* Main root check */
ATTRIBUTES(always_inline, section(".textld"), used) static inline void *chk(void *);

#endif /* ROOT_H */