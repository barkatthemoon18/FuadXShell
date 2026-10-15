#ifndef UNPACK_H
#define UNPACK_H

/* Root includes */
#include <root.h>

/* Whitebox includes */
#include <aes_wb.h>

/* FuadXShell Utils includes */
#include <fuadxshell_utils.h>

/* Default includes */
#include <link.h>
#include <threads.h>

/* Defs */
#include <defs.h>

/* Reflection includes */
#include <reflection.h>

/* Debug includes */
#include <debug/debug.h>

/* Pinning includes */
#include <pinning.h>

/* Logger includes */
#include <logger.h>

/* RC4 includes */
#include <rc4.h>

/* Emulator includes */
#include <emulator.h>

/* Hook includes */
#include <hook.h>

/* Define constants */
#define MAIN_APPLICATION_NAME ".MainApplication"
#define FUADXSHELL_MAIN_APP_NAME "com/fuad/fuadxshell/MainApplication"
#define FUADXSHELL_RUNTIME_EXCEPTION_NAME "com/fuad/fuadxshell/exception/FuadXShellRuntimeException"
#define PROC_CMDLINE "/proc/self/cmdline"
#define PROC_MAPS_FILE "/proc/self/maps"

enum
{
    APK_INFO_EXTRACT_NATIVE_LIBS_TRUE = 1 << 24,
    APK_INFO_EXTRACT_NATIVE_LIBS_FALSE = 1 << 25,
};

/* Function declarations */
ATTRIBUTES(constructor(1)) static inline void preinit(void);
ATTRIBUTES(constructor(2)) static inline void init(void);
ATTRIBUTES(always_inline, used) static inline int check_linked_library(struct dl_phdr_info *,
                                                                    ATTRIBUTES(unused) size_t, void *);
ATTRIBUTES(always_inline, overloadable, used) int perform(so_info_t *, Elf_Word, Elf_Word);
ATTRIBUTES(always_inline, overloadable, used) int perform(so_info_t *, Elf_Word, Elf_Word, uint8_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void load(JNIEnv *, void *);
ATTRIBUTES(always_inline, section(".text_ext"), overloadable, used) static inline ssize_t get_package_name(char *);
ATTRIBUTES(always_inline, section(".text_ext"), overloadable, used) static inline ssize_t get_package_name(char *, const char *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline int process_new_dex(JNIEnv *env);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline int load_dex_files(JNIEnv *env);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline ssize_t make_data_path(char *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline jobject get_jni_context(JNIEnv *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline jobject set_list_dex(JNIEnv *, const char *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline ssize_t update_pathlist(JNIEnv *, jobject, jobject);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline jobject get_field_object(JNIEnv *, jobject, const char *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline jobject get_method_object(JNIEnv *, jobject, const char *, jobjectArray);
ATTRIBUTES(always_inline, used) static inline int get_library_info(const char *, struct dl_phdr_info *, Dl_info *);

#endif /* UNPACK_H */