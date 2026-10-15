#ifndef HOOK_H
#define HOOK_H

/* Default includes */
#include <pthread.h>

#include <defs.h>

/* Reflection includes */
#include <../reflection/reflection.h>

/* Macro frida error values */
#define ERROR_FRIDA_MEMFD (1)
#define ERROR_FRIDA_AGENT (2)
#define ERROR_FRIDA_INJECTS (3)
#define ERROR_FRIDA_NET (6)

/* Macro Xposed error values */
#define ERROR_XPOSED_APP_INSTALLED (1)
#define ERROR_XPOSED_TEST_CLASSES (2)
#define ERROR_XPOSED_EXCEPTION_TRACE (3)
#define ERROR_XPOSED_PROPERTY (4)
#define ERROR_XPOSED_ENVIRON (5)
#define ERROR_XPOSED_MAPS (6)

#ifdef REQUIRE_FRIDA_SPECIFICS
    #define ERROR_FRIDA_GMAIN (2)
    #define ERROR_FRIDA_GUM (3)
    #define ERROR_FRIDA_LINJECTOR (4)
    #define ERROR_FRIDA_SO (5)
#endif

/* Frida related */
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline ssize_t read_line(int, char *, size_t);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline int traverse_file(const char *, const char [][64]);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline int traverse_injected_directories(const char [][64]);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline int traverse_agent_port(const char [][64], const int []);
/* Xposed related */
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *get_app_ctx(JNIEnv *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_app_installed(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_test_classes(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_exception_trace(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_property(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *check_environ(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *detect_frida(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *detect_xposed(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) int detect_hook(JavaVM *);

#endif /* HOOK_H */