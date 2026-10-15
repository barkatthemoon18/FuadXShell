#include "root.h"

static JavaVM *_vmGbl = NULL;

ATTRIBUTES(always_inline, constructor(100), used) static inline void init(void)
{

}

ATTRIBUTES(always_inline, constructor(101), section(".textld"), used) static inline void init_sd(void)
{

}

ATTRIBUTES(always_inline, section(".textld"), used) static inline int loadenv(JavaVM *_vm, void *_unused)
{
    static uid_t appUid = 0;
    static JNIEnv *_env;

    if ((*_vm)->GetEnv(_vm, (void **)&_env, JNI_VERSION_1_6) != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, "FuadX", "Failed to get JNIEnv");
        return JNI_ERR;
    }
    appUid = getuid();

}

/* Main root check */
ATTRIBUTES(always_inline, section(".textld"), used) static inline void *chk(void *)
{

}