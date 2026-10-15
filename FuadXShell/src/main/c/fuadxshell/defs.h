#ifndef DEFS_H
#define DEFS_H

/* Default includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <limits.h>
#include <ctype.h>

/* Unix includes */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/random.h>

/* Network manipulation includes */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Android includes */
#include <android/log.h>
#include <android/asset_manager_jni.h>
#include <android/asset_manager.h>

/* JNI includes */
#include <jni.h>

/* Zip includes */
#include <zlib.h>
#include <../minizip/mz_zip.h>
#include <../minizip/mz.h>
#include <../minizip/mz_os.h>
#include <../minizip/mz_strm_split.h>
#include <../minizip/mz_strm_buf.h>

/* ELF includes */
#include <elf.h>

/* Principal syscall include */
#include <fuadxshell_syscall.h>

#ifndef NDEBUG
    #define FUADXSHELL_LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, ##__VA_ARGS__)
#else
    #define FUADXSHELL_LOG_D(...)
#endif
#define FUADXSHELL_LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, TAG, ##__VA_ARGS__)
#define FUADXSHELL_LOG_I(...) __android_log_print(ANDROID_LOG_INFO, TAG, ##__VA_ARGS__)
#define FUADXSHELL_LOG_W(...) __android_log_print(ANDROID_LOG_WARN, TAG, ##__VA_ARGS__)

/* ELF headers */
#if INTPTR_MAX == INT64_MAX
    typedef Elf64_Ehdr Elf_Ehdr;
	typedef Elf64_Shdr Elf_Shdr;
    typedef Elf64_Word Elf_Word;
#elif INTPTR_MAX == INT32_MAX
    typedef Elf32_Ehdr Elf_Ehdr;
	typedef Elf32_Shdr Elf_Shdr;
    typedef Elf32_Word Elf_Word;
#else
    #error "Unsupported ABI"
#endif

/* Stringify / Concatenate macros */
#define STRINGIFY(x) #x
#define CONCATENATE(x, y) x##y

/* Define likely/unlikely */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* Define attributes */
#define ATTRIBUTES(...) __attribute__((__VA_ARGS__))

/* Android Properties */
#define PROP_DEVICE_NAME "ro.product.device"
#define PROP_DEVICE_MODEL "ro.product.model"
#define PROP_DEVICE_MANUFACTURER "ro.product.manufacturer"
#define PROP_BUILD_VERSION "ro.build.version.release"
#define PROP_BUILD_ID "ro.build.id"
#define PROP_BUILD_FPRINT "ro.build.fingerprint"
#define PROP_CPU_ABI "ro.product.cpu.abi"
#define PROP_VERSION_SDK "ro.build.version.sdk"
#define PROP_KERNEL_VERSION "ro.kernel.version"
#define PROP_KERNEL_RELEASE "ro.build.version.security_patch"

/* Logger Event Lists */
#define LOG_EVENT_FRIDA "FridaEvent"
#define LOG_EVENT_DEBUG "DebugEvent"
#define LOG_EVENT_HOOK "HookEvent"
#define LOG_EVENT_SIGNATURE "SignatureEvent"
#define LOG_EVENT_ROOT "RootEvent"
#define LOG_EVENT_PINNING "PinningEvent"

/* Custom errors */
#define ENOREADBYTES 35
#define ENOSECT 36
#define ENODECR 37
#define EPTRACED 38
#define ENOPIPELOG 39
#define ENOMTXLOG 40
#define ELOGNTHRD 41
#define ENOLOGGER 42
#define ELOGWRITE 43
#define EPRTLWRTLOG 44
#define ENOPROP 45
#define ENOADDR 46
#define ENOWBC 47
#define EWBCOMPUTED 48
#define ENOJVM 49
#define ENOJNIENV 50
#define ENOTHRD 51
#define ENOJNIDTCH 52
#define ENOCONTEXT 53
#define ENOJNIMTHD 54
#define ENOJNICLASS 55
#define ENOJNIOBJECT 56
#define ENOJNIFIELD 57
#define EXPOSED 58
#define EFRIDA 59
#define EHOOK 60 /* Both frida and xposed was found */
#define ENOKDF 61
#define EBADKDF 62

/* Custom error messages (TODO: Create custom errno) */
#define ERR_ENOREADBYTES "ERROR: Unable to read bytes properly from file or memory"
#define ERR_ENOSECT "ERROR: Section not found in linked object"
#define ERR_ENODECR "FATAL: Error while performing runtime decryption"

/* Initialization | macros */
#define NOT_INITIALIZED ~0ULL
#define INITIALIZED_CHECK_APK_STATE 1 << 15
#define INITIALIZED_SO_FOUND 1 << 16
#define INITIALIZED_FOUND_RX 1 << 17
#define INITIALIZED_ENC_SECTION_FOUND 1 << 18
#define INITIALIZED_DEC_SECTION 1 << 19
#define ARE_ROUTINES_INITIALIZED (INITIALIZED_CHECK_APK_STATE | INITIALIZED_SO_FOUND | INITIALIZED_FOUND_RX | INITIALIZED_ENC_SECTION_FOUND | INITIALIZED_DEC_SECTION)

/* Define size macros */
#define MAX_LOG_MESSAGE_SIZE 4096 /* Maximum size of a log message */

/* Define LOG macro */
#define TAG "FuadXShell"

/* Enum for logging */
typedef enum log_level_t
{
    LOG_LEVEL_DEBUG = ANDROID_LOG_DEBUG,
    LOG_LEVEL_ERROR = ANDROID_LOG_ERROR,
    LOG_LEVEL_INFO = ANDROID_LOG_INFO,
    LOG_LEVEL_WARN = ANDROID_LOG_WARN,
    LOG_LEVEL_FATAL = ANDROID_LOG_FATAL
} log_level_t;

/* Enum for cleanup */
typedef enum cleanup_type_t
{
    CT_NONE,
    CT_MALLOC,
    CT_MMAP,
    CT_FD,
    CT_SOCKET,
    CT_ZEROD, /* Zeroed memory value, to avoid potential analysis */
    CT_NULLD /* Null pointer value, to avoid potential analysis */
} cleanup_type_t;

/* Typedef structs */
typedef struct log_entry_t log_entry_t;
typedef struct apk_info_t apk_info_t;
typedef struct
{
    cleanup_type_t type;
    ssize_t size; /* Size of the resource */
    union
    {
        void *ptr; /* Pointer to the resource */
        int fd;   /* File descriptor for the resource */
        int sockfd; /* Socket file descriptor for the resource */
    };
} resource_t;
typedef struct
{
    int count;
    resource_t resources[4];
} resource_handler_t;

typedef struct so_info_t
{
    char *path;
    char *loadedMem;
    void *loadedAddr;
    size_t loadedMemSize;
    resource_handler_t resource;
} so_info_t;

#endif /* DEFS_H */