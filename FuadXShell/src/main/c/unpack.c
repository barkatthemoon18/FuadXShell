#include <unpack.h>
#include <sys/statfs.h>

struct apk_info_t
{
    char *basePath; /* Base path of the APK */
    uint32_t apkLookup; /* Lookup value for the APK */
};

/* Preload definitions */
ssize_t precon = 0;
static JavaVM *vmGlobal = NULL;
static void *jniThrowClassGlobal = NULL;
static apk_info_t apkInfo = { 0 };
static unsigned long long initialized = NOT_INITIALIZED;

/* Constants (.rodata_ext). These will be patched when running the obfuscation process. Randomness is provided on each build
ATTRIBUTES(section(".rodata_ext"), used) const char DEFAULT_KEY[65] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\0";
ATTRIBUTES(section(".rodata_ext"), used) const char DEFAULT_IV[33] = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\0";
ATTRIBUTES(section(".rodata_ext"), used) const char DEFAULT_SO_INTEGRITY_VALUE[65] = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\0"; */
ATTRIBUTES(section(".rodata_ext"), used) const char MASTER_KEY[65] = "d78e0d61464cacdafd0b1da7661c5e0f634030db576a3156959b97ee36cb3a4d\0";

/* JNI Method */
static JNINativeMethod method[] =
{
    { "load", "()V", load }
};

/**
ATTRIBUTES(constructor(0))
static inline void ini0(void)
{
    uint8_t cipher[256] = { 0 };
    uint8_t plain[256] = { 0 };
    uint8_t hexcipher[256] = { 0 };
    int retEncryption = 0;
    int retDecryption = 0;

    /* retEncryption = wb_encrypt((const uint8_t *)"Hola mundo\0", strlen("Hola mundo\0"), cipher);
    retDecryption = wb_decrypt(cipher, strlen((char *)cipher), plain);
    bin_to_hex((char *)cipher, (char *)hexcipher, strlen((char *)cipher));

    FUADXSHELL_LOG_D("Cipher: %s", retEncryption == 0 ? hexcipher : NULL);
    FUADXSHELL_LOG_D("Plain: %s", retDecryption == 0 ? plain : NULL);

    ARGON2ID

    kdf(KDF_ARGON2ID, (uint8_t *)output, 32, (uint8_t *)pwd, strlen(pwd), (uint8_t *)salt, 16, NULL, 0);
} */

#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xE0F5E1E2
#endif

static inline const char *parse_ftype(unsigned long ftype)
{
    switch (ftype)
    {
        case OVERLAYFS_SUPER_MAGIC:
            return "overlayfs";
        case EROFS_SUPER_MAGIC:
            return "erofs";
        case EXT4_SUPER_MAGIC:
            return "ext4";
        case TMPFS_MAGIC:
            return "tmpfs";
        case PROC_SUPER_MAGIC:
            return "proc";
        case SYSFS_MAGIC:
            return "sysfs";
        case SELINUX_MAGIC:
            return "selinuxfs";
        case FUSE_SUPER_MAGIC:
            return "fuse";
        case BINDERFS_SUPER_MAGIC:
            return "binderfs";
        default:
            return "unknown";
    }
}

static void rstrip(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r' || isspace((unsigned char)s[n-1]))) {
        s[--n] = '\0';
    }
}

static int ci_strstr(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; ++p) {
        if (strncasecmp(p, needle, nlen) == 0)
            return 1;
    }
    return 0;
}

static int whitelisted_token(const char *name) {
    static const char *WL[] = {
            "jit", "zygote", "dalvik", "code-cache", "dex", "vdex",
            "linearalloc", "compiler", "malloc", "scudo", "heapprofd",
            "libdexfile", "dex2oat", "jit-cache", "jit-zygote",
            "vdso", "vvar"
    };
    for (size_t i = 0; i < sizeof(WL)/sizeof(WL[0]); ++i)
        if (ci_strstr(name, WL[i]))
            return 1;
    return 0;
}

static int looks_like_suspicious_exec(const char *perms,
                                      const char *path_or_tag) {
    if (!perms || strchr(perms, 'x') == NULL)
        return 0;

    if (!path_or_tag || path_or_tag[0] == '\0') {
        return 1;
    }

    if (path_or_tag[0] == '[') {
        if (whitelisted_token(path_or_tag))
            return 0;
        return 1;
    }

    if (ci_strstr(path_or_tag, "memfd:")) {
        if (!whitelisted_token(path_or_tag))
            return 1;
        return 0;
    }

    if (ci_strstr(path_or_tag, "(deleted)") && !whitelisted_token(path_or_tag)) {
        return 1;
    }

    // Ruta normal con x: probablemente ok.
    return 0;
}

static void print_suspicious_line(const char *line,
                                  unsigned long start, unsigned long end,
                                  const char *perms, const char *name) {
    (void)line;
    FUADXSHELL_LOG_E("[SUS] %lx-%lx %s %s", start, end, perms, (name && *name) ? name : "(no-name)");
}

int scan_exec_anonymous_vmas(void) {
    int fd = sys_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        FUADXSHELL_LOG_E("No pude abrir /proc/self/maps: %s", strerror(errno));
        return -1;
    }

    char buf[64 * 1024];   // suficiente: maps suele ser << 64KB en apps típicas
    char line[2048];
    size_t line_len = 0;
    int suspicious = 0;

    for (;;) {
        ssize_t r = sys_read(fd, buf, sizeof(buf));
        if (r < 0) {
            FUADXSHELL_LOG_E("Error leyendo maps: %s", strerror(errno));
            break;
        }
        if (r == 0) { // EOF
            // Procesar línea residual si la hay
            if (line_len) {
                line[line_len] = '\0';
                // Parse final
                unsigned long start=0, end=0, offset=0;
                char perms[8]={0}, dev[16]={0};
                unsigned long inode=0;
                int n = 0;
                if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                           &start, &end, perms, &offset, dev, &inode, &n) >= 6) {
                    const char *name = (line[n] ? line + n : "");
                    char tmp[PATH_MAX];
                    strncpy(tmp, name, sizeof(tmp)-1);
                    tmp[sizeof(tmp)-1] = 0;
                    rstrip(tmp);
                    if (looks_like_suspicious_exec(perms, tmp)) {
                        print_suspicious_line(line, start, end, perms, tmp);
                        suspicious++;
                    }
                }
            }
            break;
        }

        // Procesar buffer por líneas
        size_t off = 0;
        while (off < (size_t)r) {
            char c = buf[off++];
            if (c == '\n') {
                line[line_len] = '\0';
                // Parsear la línea completa
                unsigned long start=0, end=0, offset=0;
                char perms[8]={0}, dev[16]={0};
                unsigned long inode=0;
                int n = 0;

                if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                           &start, &end, perms, &offset, dev, &inode, &n) >= 6) {
                    const char *name = (line[n] ? line + n : "");
                    char tmp[PATH_MAX];
                    strncpy(tmp, name, sizeof(tmp)-1);
                    tmp[sizeof(tmp)-1] = 0;
                    rstrip(tmp);
                    if (looks_like_suspicious_exec(perms, tmp)) {
                        print_suspicious_line(line, start, end, perms, tmp);
                        suspicious++;
                    }
                }
                line_len = 0;
            } else if (line_len + 1 < sizeof(line)) {
                line[line_len++] = c;
            } else {
                // Línea demasiado larga (inusual). Truncamos de forma segura.
                line[sizeof(line)-1] = '\0';
                line_len = 0;
            }
        }
    }
    sys_close(fd);
    return suspicious;
}

ATTRIBUTES(constructor(0), used)
static inline void ini0(void)
{
    int n = scan_exec_anonymous_vmas();
    if (n >= 0) {
        FUADXSHELL_LOG_E("Total sospechosos: %d", n);
    }

}

ATTRIBUTES(constructor(1), used)
static inline void ini(void)
{
    const char *paths[] = { "/", "/system/bin", "/vendor", "/data", "/debug_ramdisk" };
    struct kernel_statfs statfs;
    struct kernel_statfs statfsfd;
    int fd;

    for (int i = 0; i < 5; i++)
    {
        if (!sys_statfs(paths[i], &statfs))
        {
            FUADXSHELL_LOG_D("Filesystem type is: %s", parse_ftype(statfs.f_type));
        }
        if ((fd = sys_openat(AT_FDCWD, paths[i], O_PATH | O_CLOEXEC | O_DIRECTORY, 0)) < 0)
        {
            FUADXSHELL_LOG_E("Error while opening directory %s: %s", paths[i], strerror(errno));
            continue; /* Skip directories that cannot be opened */
        }
        sys_fstatfs(fd, &statfsfd);
        FUADXSHELL_LOG_D("Filesystem type using fd is: %s - %s", parse_ftype(statfsfd.f_type), strerror(errno));
        sys_close(fd);
    }

    logger_init(getprogname());
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Initializing FuadXShell\0");
    precon = check_precon();
    FUADXSHELL_LOG_D("Return value from detect_debug: %zu", precon);

}

ATTRIBUTES(constructor(2), used)
static inline void init(void)
{
    struct dirent *entry = NULL;
    DIR *dirStrct = NULL;
    Dl_info _dlinfo;
    size_t _apkLen = 0;
    size_t printfLen = 0;
    char _dir[512] = { 0 };
    char _test[512] = { 0 };
    char *_apkBreak = NULL;
    char *_dot = NULL;
    int bytesWritten = 0;

    FUADXSHELL_LOG_D("Inside init");
    /* Default verification */
    if (unlikely(!dladdr(init, &_dlinfo)))
    {
        FUADXSHELL_LOG_E("Error while retrieving dladdr: %s", strerror(errno));
        return;
    }
    /* Check for extractNativeLibs=false */
    if ((_apkBreak = strstr(_dlinfo.dli_fname, ".apk!")) != NULL)
    {
        FUADXSHELL_LOG_D("ExtractNativeLibs is set to false");
        _apkLen = (size_t)(_apkBreak - _dlinfo.dli_fname + 4);
        apkInfo = (apk_info_t)
        {
            .basePath = strndup(_dlinfo.dli_fname, _apkLen),
            .apkLookup = APK_INFO_EXTRACT_NATIVE_LIBS_FALSE /* Placeholder for APK lookup value */
        };
        FUADXSHELL_LOG_D("Apk path where extractNativeLibs is false: %s", apkInfo.basePath);
        initialized &= INITIALIZED_CHECK_APK_STATE;
        FUADXSHELL_LOG_D("Returning from init (1) with initialized = %lld", initialized);
        (void) dl_iterate_phdr(check_linked_library, &_dlinfo);
        free(apkInfo.basePath);
        apkInfo.basePath = NULL;
        return;
    }
    else
    {
        /* Default case (extractNativeLibs=true) */
        bytesWritten = snprintf(_dir, sizeof(_dir), "%s", _dlinfo.dli_fname);
        if (unlikely(bytesWritten < 0) || bytesWritten >= sizeof(_dir))
        {
            FUADXSHELL_LOG_E("Error while formatting directory path");
            return;
        }
        for (int i = 0; i < 3; i++)
        {
            _apkBreak = strrchr(_dir, '/');
            if (unlikely(!_apkBreak))
            {
                FUADXSHELL_LOG_E("Error while parsing apk path");
                return;
            }
            (*_apkBreak) = '\0';
        }
        printfLen = snprintf(_test, sizeof(_test), "%s/base.apk", _dir);
        if (unlikely(printfLen < 0) || printfLen >= sizeof(_test))
        {
            FUADXSHELL_LOG_E("Error while formatting apk path");
            return;
        }
        if (!access(_test, F_OK))
        {
            apkInfo = (apk_info_t)
            {
                .basePath = strdup(_test),
                .apkLookup = APK_INFO_EXTRACT_NATIVE_LIBS_TRUE /* Placeholder for APK lookup value */
            };
            FUADXSHELL_LOG_D("Apk path where extractNativeLibs is true: %s", apkInfo.basePath);
            initialized &= INITIALIZED_CHECK_APK_STATE;
            FUADXSHELL_LOG_D("Returning from init (2) with initialized = %lld", initialized);
            (void) dl_iterate_phdr(check_linked_library, &_dlinfo);
            free(apkInfo.basePath);
            apkInfo.basePath = NULL;
            return;
        }
        /* Fallback */
        else
        {
            dirStrct = opendir(_dir);
            if (!dirStrct)
            {
                FUADXSHELL_LOG_E("Error while opening directory: %s", strerror(errno));
                return;
            }
            while ((entry = readdir(dirStrct)) != NULL)
            {
                _dot = strrchr(entry->d_name, '.');
                if (_dot && !strcmp(_dot, ".apk"))
                {
                    snprintf(_test, sizeof(_test), "%s/%s", _dir, entry->d_name);
                    if (!access(_test, R_OK))
                    {
                        apkInfo = (apk_info_t)
                        {
                            .basePath = strdup(_test),
                            .apkLookup = APK_INFO_EXTRACT_NATIVE_LIBS_TRUE /* Placeholder for APK lookup value */
                        };
                        FUADXSHELL_LOG_D("Apk path where fallback was reached: %s", apkInfo.basePath);
                        initialized &= INITIALIZED_CHECK_APK_STATE;
                        closedir(dirStrct);
                        FUADXSHELL_LOG_D("Returning from init (3) with initialized = %lld", initialized);
                        (void) dl_iterate_phdr(check_linked_library, &_dlinfo);
                        free(apkInfo.basePath);
                        apkInfo.basePath = NULL;
                        return;
                    }
                }
            }
            FUADXSHELL_LOG_E("Error while looking for APK file");
            closedir(dirStrct);
            free(apkInfo.basePath);
            apkInfo.basePath = NULL;
            return;
        }
    }
}

ATTRIBUTES(always_inline, used)
static inline int check_linked_library(struct dl_phdr_info *info, ATTRIBUTES(unused) size_t sz,
                                       void *data)
{
    ATTRIBUTES(unused) const ElfW(Phdr) *phdr = NULL;
    ATTRIBUTES(unused) const uint8_t *segment = NULL;
    ATTRIBUTES(unused) uint8_t *hash = NULL;
    ATTRIBUTES(unused) char hexHash[65] = { 0 };
    #if defined(__aarch64__)
        const char *abi = "arm64";
    #elif defined(__arm__)
        const char *abi = "armeabi-v7a";
    #elif defined(__i386__)
        const char *abi = "x86";
    #elif defined(__x86_64__)
        const char *abi = "x86_64";
    #else
        #error "Unsupported architecture. Try again"
    #endif

    /* TODO: Validate initial .raw_text (decrypted) checksum
    for (int i = 0; i < info->dlpi_phnum; i++)
    {
        phdr = &info->dlpi_phdr[i];
        if (phdr->p_type == PT_LOAD && (phdr->p_flags & PF_X | PF_R))
        {
            segment = (const uint8_t *)(info->dlpi_addr + phdr->p_vaddr);
            hash = (uint8_t *)malloc(33);
            if (!hash)
            {
                FUADXSHELL_LOG_E("Error while allocating memory for hash");
                return -1;
            }
            sha256(segment, phdr->p_memsz, hash);
            for (int j = 0; j < 32; j++)
                sprintf(hexHash + (j * 2), "%02x", hash[j]);
            hexHash[64] = '\0';
            #ifdef NDEBUG
                if (strcmp(DEFAULT_SO_INTEGRITY_VALUE, hexHash) != 0)
                {
                    FUADXSHELL_LOG_D("Integrity check failed: %s - %s", DEFAULT_SO_INTEGRITY_VALUE, hexHash);
                    FUADXSHELL_LOG_E("Integrity check failed");
                    free(hash);
                    hash = NULL;
                    return -1;
                }
                FUADXSHELL_LOG_D("Integrity checked passed");
            #endif
            FUADXSHELL_LOG_D("Found PT_LOAD and PF_X segment at: %p - %p - %s - %d", segment, phdr, info->dlpi_name, i);
            FUADXSHELL_LOG_D("Bypassed in debug mode: %s - %s", DEFAULT_SO_INTEGRITY_VALUE, hexHash);
            free(hash);
            hash = NULL;
            break;
        }
    } */
    /* TODO: Look for hooks or use of frida */
    /* Look for to-be-decrypted .text_end section */
    static int counter = 1;
    FUADXSHELL_LOG_D("Checking linked library: %s / %s - %d", (*(Dl_info *)data).dli_fname, info->dlpi_name, counter++);
    if (strstr(info->dlpi_name, "libfuadxshell.so"))
    {
        initialized |= INITIALIZED_SO_FOUND;
        if (get_library_info(abi, info, data) < 0)
        {
            FUADXSHELL_LOG_E("Error while getting library info");
            return -1;
        }
        return 1;
    }
    return 0; /* Continue iterating through linked libraries */
}

ATTRIBUTES(always_inline, overloadable, used)
int perform(so_info_t *output, Elf_Word sectionOffset, Elf_Word sectionSize)
{
    uint8_t *addrSection = NULL;
    uint8_t *addrSectionEnd = NULL;
    uintptr_t ptrStart = 0;
    size_t elfpagesize = 0;
    size_t pagesize = sysconf(_SC_PAGESIZE);
    int test = 0;

    if (unlikely(!output) || unlikely(!output->loadedAddr) || unlikely(sectionSize == -1)
        || unlikely(sectionOffset == -1))
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for performing operation");
        return -EINVAL;
    }
    addrSection = (uint8_t *)((output->loadedAddr) + sectionOffset);
    addrSectionEnd = addrSection + sectionSize;
    FUADXSHELL_LOG_D("Section address: %p, Section size: %x", addrSection, sectionSize);
    ptrStart = (uintptr_t)addrSection & -pagesize;
    elfpagesize = (addrSectionEnd - (uint8_t *)ptrStart);
    test = sys_mprotect((void *)ptrStart, elfpagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (test != 0)
    {
        FUADXSHELL_LOG_E("Error while setting memory protection: %s", strerror(errno));
        return -errno;
    }
    /* Perform decrpytion */
    wb_decrypt(addrSection, sectionSize);
    FUADXSHELL_LOG_D("Memory protection set successfully for section at %p with size %zu", addrSection, elfpagesize);
    FUADXSHELL_LOG_D("Restoring protections for shared library (R-X)");
    test = sys_mprotect((void *)ptrStart, elfpagesize, PROT_READ | PROT_EXEC);
    if (test != 0)
    {
        FUADXSHELL_LOG_E("Error while restoring memory protection: %s", strerror(errno));
        return -errno;
    }
    return 0;
}

ATTRIBUTES(always_inline, overloadable, used)
int perform(so_info_t *output, Elf_Word sectionOffset, Elf_Word sectionSize, uint8_t noExec)
{
    uint8_t *addrSection = NULL;
    uint8_t *addrSectionEnd = NULL;
    uintptr_t ptrStart = 0;
    size_t elfpagesize = 0;
    size_t pagesize = sysconf(_SC_PAGESIZE);
    int test = 0;

    if (unlikely(!output) || unlikely(!output->loadedAddr) || unlikely(sectionSize == -1)
        || unlikely(sectionOffset == -1))
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for performing operation");
        return -EINVAL;
    }
    addrSection = (uint8_t *)((output->loadedAddr) + sectionOffset);
    addrSectionEnd = addrSection + sectionSize;
    FUADXSHELL_LOG_D("Section address: %p, Section size: %x", addrSection, sectionSize);
    ptrStart = (uintptr_t)addrSection & -pagesize;
    elfpagesize = (addrSectionEnd - (uint8_t *)ptrStart);
    test = sys_mprotect((void *)ptrStart, elfpagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (test != 0)
    {
        FUADXSHELL_LOG_E("Error while setting memory protection: %s", strerror(errno));
        return -errno;
    }
    /* Perform decrpytion */
    wb_decrypt(addrSection, sectionSize);
    FUADXSHELL_LOG_D("Memory protection set successfully for section at %p with size %zu", addrSection, elfpagesize);
    FUADXSHELL_LOG_D("Restoring protections for shared library");
    test = noExec ? sys_mprotect((void *)ptrStart, elfpagesize, PROT_READ) : sys_mprotect((void *)ptrStart, elfpagesize, PROT_READ | PROT_EXEC);
    if (test != 0)
    {
        FUADXSHELL_LOG_E("Error while restoring memory protection: %s", strerror(errno));
        return -errno;
    }
    return 0;
}

ATTRIBUTES(visibility("default"), section(".text_ext"), used)
int JNI_OnLoad(JavaVM *_vm, ATTRIBUTES(unused) void *_reserved)
{
    int hooks;
    int emulator;
    int debug;
    int root;
    JNIEnv *env;
    void *throwExceptionClass = NULL;
#define FUADXSHELL_INCLUDES_MAIN_APPLICATION_SHELL
    #if defined(FUADXSHELL_INCLUDES_MAIN_APPLICATION_SHELL) || defined(NDEBUG)
        void *mainApplicationClass = NULL;
    #endif

    FUADXSHELL_LOG_D("Inside JNI_OnLoad");
    if (unlikely(initialized == NOT_INITIALIZED) || unlikely(initialized != ARE_ROUTINES_INITIALIZED))
    {
        FUADXSHELL_LOG_E("Error while loading application [E000]");
        return -1;
    }
    vmGlobal = _vm;
    if (unlikely((*_vm)->GetEnv(_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK))
    {
        FUADXSHELL_LOG_E("Error while running JNI_OnLoad: [E001]");
        return -1;
    }
    throwExceptionClass = getJNIClass(env, FUADXSHELL_RUNTIME_EXCEPTION_NAME);
    jniThrowClassGlobal = (*env)->NewGlobalRef(env, throwExceptionClass);
    #if defined(FUADXSHELL_INCLUDES_MAIN_APPLICATION_SHELL) || defined(NDEBUG)
        mainApplicationClass = getJNIClass(env, FUADXSHELL_MAIN_APP_NAME);
        if (unlikely(!throwExceptionClass || !mainApplicationClass))
        {
            FUADXSHELL_LOG_E("Error while loading required classes: [E001]");
            return -1;
        }
        (*env)->DeleteLocalRef(env, throwExceptionClass);
        if ((*env)->RegisterNatives(env, mainApplicationClass,
                                    method, sizeof(method) / sizeof(method[0])) < 0)
        {
            FUADXSHELL_LOG_E("Error while registering JNI methods: [E002]");
            return -1;
        }
    #endif
    #ifdef NDEBUG
    if (precon < 0)
    {
        FUADXSHELL_LOG_D("Preconditions failed");
        return JNI_ERR;
    }
    #endif
    /* Pass all initial tests (Emulator, Debugger, Frida, etc.) */

    /* Get AssetManager */
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Processing non-shell dex files");
    /* Write and decrypt the .xshell file */
    if (process_new_dex(env) < 0)
    {
        FUADXSHELL_LOG_E("Error while processing runtime loading");
        return JNI_ERR;
    }
    /* Load .xshell file and load DEX files */
    FUADXSHELL_LOG_D("Loading dex files from .xshell file");
    if (load_dex_files(env) < 0)
    {
        FUADXSHELL_LOG_E("Error while loading files at runtime");
        return JNI_ERR;
    }
    /* TODO: Starting this point, run threads to verify while running after preconditions are checked */
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "FuadXShell initialized successfully");
    root = detect_root();
    hooks = detect_hook(vmGlobal);
    emulator = detect_emulator();
    debug = detect_debug();
    if (root == -EROOT || hooks == -EHOOK || hooks == -EFRIDA || emulator == -EEMU || debug == -EPTRACED)
    {
        FUADXSHELL_LOG_D("Root: %d, Hooks: %d, Emulator: %d, Debug: %d", root, hooks, emulator, debug);
        #ifdef NDEBUG
            sys_raise(SIGSEGV);
        #endif
    }
    FUADXSHELL_LOG_E("List of values for: hooks=%d, emulator=%d, debug=%d", hooks, emulator, debug);
    return JNI_VERSION_1_6;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline int process_new_dex(JNIEnv *env)
{
    const void *xshellBuffer = NULL;
    const char *assetName = NULL;
    void *mAppClass = NULL;
    void *contextClass = NULL;
    void *contextObject = NULL;
    void *contextField = NULL;
    void *getAssetsMethodId = NULL;
    void *assetManagerObject = NULL;
    AAssetManager *assetManager = NULL;
    AAssetDir *assetDir = NULL;
    AAsset *asset = NULL;
    ssize_t bytesWritten;
    char binKey[33] = { 0 };
    char dataPath[512] = { 0 };
    char pathFileXshell[512] = { 0 };
    int fd;
    ATTRIBUTES(section(".rodata_ext")) static const char fileExtension[] = ".xshell";
    ATTRIBUTES(section(".rodata_ext")) static const char jniNames[][256] =
    {
        "com/fuad/fuadxshell/MainApplication" /*"com/fuad/fuadxapp/MainApplication"*/,
        "app",
        "Landroid/app/Application;",
        "getAssets",
        "()Landroid/content/res/AssetManager;",
    };
    rc4_ctx_t ctx;

    /* Get the Main Application */
    mAppClass = getJNIClass(env, jniNames[0]);
    if (unlikely(!mAppClass))
    {
        FUADXSHELL_LOG_E("Error while loading MainApplication class");
        return -ENOJNICLASS;
    }
    contextField = (*env)->GetStaticFieldID(env, mAppClass, jniNames[1], jniNames[2]);
    if (!contextField)
    {
        FUADXSHELL_LOG_E("Error while getting static field ID for app");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -ENOJNIFIELD;
    }

    /* Get context */
    contextObject = (*env)->GetStaticObjectField(env, mAppClass, contextField);
    if (!contextObject)
    {
        FUADXSHELL_LOG_E("Error while getting static field object for app");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -ENOJNIOBJECT;
    }
    contextClass = (*env)->GetObjectClass(env, contextObject);

    /* Context.getAssets() */
    getAssetsMethodId = getJNIMethodID(env, contextClass, jniNames[3], jniNames[4]);
    if (!getAssetsMethodId)
    {
        FUADXSHELL_LOG_E("Error while getting getAssets method ID");
        return -ENOJNIMTHD;
    }
    assetManagerObject = getJNIObject(env, contextObject, getAssetsMethodId);
    if (!assetManagerObject)
    {
        FUADXSHELL_LOG_E("Error while getting AssetManager object");
        return -ENOJNIOBJECT;
    }

    /* Get AAssetManager ptr */
    assetManager = AAssetManager_fromJava(env, assetManagerObject);
    if (!assetManager)
    {
        FUADXSHELL_LOG_E("Error while converting AssetManager from Java to native");
        return -ENOJNIOBJECT;
    }
    FUADXSHELL_LOG_D("AssetManager successfully retrieved");
    assetDir = AAssetManager_openDir(assetManager, "");
    if (!assetDir)
    {
        FUADXSHELL_LOG_E("Error while opening AssetManager directory");
        return -ENOENT;
    }
    while ((assetName = AAssetDir_getNextFileName(assetDir)) != NULL)
    {
        if (strstr(assetName, fileExtension))
        {
            FUADXSHELL_LOG_D("Found asset with .xshell extension: %s", assetName);
            asset = AAssetManager_open(assetManager, assetName, AASSET_MODE_BUFFER);
            if (!asset)
            {
                FUADXSHELL_LOG_E("Error while opening asset: %s", assetName);
                AAssetDir_close(assetDir);
                return -ENOENT;
            }
            xshellBuffer = AAsset_getBuffer(asset);
            if (!xshellBuffer)
            {
                FUADXSHELL_LOG_E("Error while getting buffer from asset: %s", assetName);
                AAsset_close(asset);
                AAssetDir_close(assetDir);
                return -ENOENT;
            }
            FUADXSHELL_LOG_D("Processing the dex's holder file: %s", assetName);
            if (make_data_path(dataPath, sizeof(dataPath)) < 0)
            {
                log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while making data path for dex injection");
                AAsset_close(asset);
                AAssetDir_close(assetDir);
                return -ENODECR;
            }
            FUADXSHELL_LOG_D("Data path for dex injection: %s", dataPath);
            bytesWritten = snprintf(pathFileXshell, sizeof(pathFileXshell), "%s/%s", dataPath, assetName);
            if (bytesWritten < 0 || bytesWritten >= sizeof(pathFileXshell))
            {
                FUADXSHELL_LOG_E("Error while formatting path for dex injection: %s", strerror(errno));
                AAsset_close(asset);
                AAssetDir_close(assetDir);
                return -ENAMETOOLONG;
            }
            FUADXSHELL_LOG_D("Final path for dex injection: %s", pathFileXshell);
            /* Write the xshell file to the data path */
            fd = sys_open(pathFileXshell, O_WRONLY | O_CREAT | O_TRUNC, 0700);
            if (fd < 0)
            {
                FUADXSHELL_LOG_E("Error while opening file %s for writing: %s", pathFileXshell, strerror(errno));
                AAsset_close(asset);
                AAssetDir_close(assetDir);
                return -errno;
            }
            /* RC4 decryption before writing down file */
            hex_to_bin(MASTER_KEY, binKey, 32);
            rc4_init(&ctx, (uint8_t *)binKey, 32);
            rc4_crypt(&ctx, (uint8_t *)xshellBuffer, AAsset_getLength(asset));
            FUADXSHELL_LOG_D("Bytes decrypted: %02x - %02x - %02x", ((uint8_t *)xshellBuffer)[0], ((uint8_t *)xshellBuffer)[1], ((uint8_t *)xshellBuffer)[2]);
            bytesWritten = sys_write(fd, xshellBuffer, AAsset_getLength(asset));
            if (bytesWritten < 0)
            {
                FUADXSHELL_LOG_E("Error while writing xshell buffer to file %s: %s", pathFileXshell, strerror(errno));
                sys_close(fd);
                AAsset_close(asset);
                AAssetDir_close(assetDir);
                return -errno;
            }
            FUADXSHELL_LOG_D("Dex file written successfully to %s", pathFileXshell);
            sys_close(fd);
            AAsset_close(asset);
            AAssetDir_close(assetDir);
            /* *.xshell written successfully, now we can proceed with the decryption for each dex file and injection */
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Processed zip which holds dex values: %s, into: %s", assetName, pathFileXshell);
            break;
        }
    }
    FUADXSHELL_LOG_E("Processed all assets successfully");
    return 0;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline int load_dex_files(JNIEnv *env)
{
    ATTRIBUTES(section(".rodata_ext")) static const char defaultPath[256] = "/data/data/%s/fuadx_files";
    ATTRIBUTES(section(".rodata_ext")) static const char defaultPathFile[512] = "/data/data/%s/fuadx_files/%s";
    ATTRIBUTES(section(".rodata_ext")) static const char needle[] = ".xshell";
    jobject appContextObject = NULL;
    jobject dexFileListObject = NULL;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char canonicalPath[512] = { 0 };
    char canonicalPathFile[512] = { 0 };
    ssize_t bytesWritten;

    /* Load .xshell and write down the dex files (should be only one for this demo) */
    bytesWritten = snprintf(canonicalPath, sizeof(defaultPath), defaultPath, getprogname());
    if (bytesWritten < 0 || bytesWritten >= (long)sizeof(canonicalPath))
    {
        FUADXSHELL_LOG_E("Error while formatting canonical path: %s", strerror(errno));
        return -ENAMETOOLONG;
    }
    FUADXSHELL_LOG_D("Canonical path for dex files: %s", canonicalPath);
    dir = opendir(canonicalPath);
    if (!dir)
    {
        FUADXSHELL_LOG_E("Error while opening directory %s: %s", canonicalPath, strerror(errno));
        return -errno;
    }
    FUADXSHELL_LOG_D("Opened directory %s successfully", canonicalPath);
    while ((entry = readdir(dir)) != NULL)
    {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        {
            FUADXSHELL_LOG_D("Skipping self or parent directory: %s", entry->d_name);
            continue;
        }
        if (strstr(entry->d_name, needle))
        {
            FUADXSHELL_LOG_D("Found .xshell file: %s", entry->d_name);
            bytesWritten = snprintf(canonicalPathFile, sizeof(canonicalPathFile), defaultPathFile, getprogname(), entry->d_name);
            if (bytesWritten < 0 || bytesWritten >= (long)sizeof(canonicalPathFile))
            {
                FUADXSHELL_LOG_E("Error while formatting canonical path: %s", strerror(errno));
                return -ENAMETOOLONG;
            }
            FUADXSHELL_LOG_D("Canonical path for dex file: %s", canonicalPathFile);
            entry = NULL;
            break;
        }
    }
    closedir(dir);
    /* Unzip files */
    if (unzip_files(canonicalPathFile) < 0)
    {
        FUADXSHELL_LOG_E("Error while unzipping files from %s", canonicalPathFile);
        return -ENODECR;
    }
    sys_unlink(canonicalPathFile); /* Delete the .xshell file after unzipping */
    FUADXSHELL_LOG_D("Unzipped files successfully from %s", canonicalPathFile);
    /* Load dex files */
    appContextObject = get_jni_context(env);
    if (!appContextObject)
    {
        FUADXSHELL_LOG_E("Error while getting JNI context object");
        return -ENOJNIOBJECT;
    }
    FUADXSHELL_LOG_D("JNI context object retrieved successfully");
    dexFileListObject = set_list_dex(env, defaultPathFile);
    if (!dexFileListObject)
    {
        FUADXSHELL_LOG_E("Error while setting list of dex files.");
        (*env)->DeleteLocalRef(env, appContextObject);
        return -ENODECR;
    }
    if (update_pathlist(env, appContextObject, dexFileListObject) < 0)
    {
        FUADXSHELL_LOG_E("Error while updating path list");
        (*env)->DeleteLocalRef(env, appContextObject);
        (*env)->DeleteLocalRef(env, dexFileListObject);
        return -ENODECR;
    }
    return 0;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline ssize_t make_data_path(char *canonicalPath, size_t size)
{
    ATTRIBUTES(section(".rodata_ext")) static const char defaultPath[] = "/data/data/%s/fuadx_files";
    char buf[4096] = { 0 };
    ssize_t bytesWritten;

    if (!get_package_name(buf))
    {
        bytesWritten = snprintf(canonicalPath, size, defaultPath, buf);
        if (bytesWritten < 0 || bytesWritten >= size)
        {
            FUADXSHELL_LOG_E("Error while formatting package name: %s", strerror(errno));
            memset(buf, 0, sizeof(buf));
            return -1;
        }
        FUADXSHELL_LOG_D("Package's data folder name: %s", canonicalPath);
        memset(buf, 0, sizeof(buf));
        /* Create directory if it does not exist */
        if (mkdir(canonicalPath, 0750) < 0)
        {
            if (errno != EEXIST)
            {
                FUADXSHELL_LOG_E("Error while creating data path %s: %s", canonicalPath, strerror(errno));
                return -1;
            }
            FUADXSHELL_LOG_D("Data path already exists: %s", canonicalPath);
            return 0;
        }
    }
    else
    {
        FUADXSHELL_LOG_E("Error while getting package name");
        return -1; /* Failed to get package name */
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline jobject get_jni_context(JNIEnv *env)
{
    jclass contextClass = NULL;
    jfieldID appFieldId = NULL;
    jobject contextObject = NULL;

    if (unlikely(!env))
    {
        FUADXSHELL_LOG_E("JNI environment is NULL");
        return NULL;
    }
    #if defined(FUADXSHELL_INCLUDES_MAIN_APPLICATION_SHELL) || defined(NDEBUG)
        contextClass = (*env)->FindClass(env, "com/fuad/fuadxshell/MainApplication");
    #else
        contextClass = (*env)->FindClass(env, "com/fuad/fuadxapp/MainApplication");
    #endif
    if (unlikely(!contextClass))
    {
        FUADXSHELL_LOG_E("Error while finding MainApplication class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return NULL;
    }
    appFieldId = (*env)->GetStaticFieldID(env, contextClass, "app", "Landroid/app/Application;");
    if (unlikely(!appFieldId))
    {
        FUADXSHELL_LOG_E("Error while getting static field ID for app");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, contextClass);
        return NULL;
    }
    contextObject = (*env)->GetStaticObjectField(env, contextClass, appFieldId);
    if (unlikely(!contextObject))
    {
        FUADXSHELL_LOG_E("Error while getting static field object for app");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, contextClass);
    }
    return contextObject;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline jobject set_list_dex(JNIEnv *env, const char *defaultPath)
{
    ATTRIBUTES(section(".rodata_ext")) static const char dexFileName[] = "classes%d.dex";
    ATTRIBUTES(section(".rodata_ext")) static const char classesNeedle[] = "classes";
    ATTRIBUTES(section(".rodata_ext")) static const char dexNeedle[] = ".dex";
    ATTRIBUTES(section(".rodata_ext")) static const char jniNames[][256] =
    {
        "java/util/ArrayList",
        "<init>",
        "()V",
        "add",
        "(Ljava/lang/Object;)Z",
        "java/io/File",
        "<init>",
        "(Ljava/lang/String;)V",
    };
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char *parentDir = NULL;
    char dexFile[256] = { 0 };
    char dexPath[512] = { 0 }; /* Iterate through all classes%d.dex files */
    char progname[4096] = { 0 };
    int counter = 1;
    struct kernel_stat stat;
    ssize_t bytesWritten;
    jclass arrayListClass = NULL;
    jclass classFile = NULL;
    jmethodID arrayListCtorMethodId = NULL;
    jmethodID addMethodId = NULL;
    jmethodID ctorFileMethodId = NULL;
    jmethodID setWritableMethodId = NULL;
    jobject dexFileObject = NULL;
    jobject dexFileListObject = NULL;
    jstring jniFilePath = NULL;

    bytesWritten = snprintf(dexFile, sizeof(dexFile), dexFileName, counter);
    if (bytesWritten < 0 || bytesWritten >= (long)sizeof(dexFile))
    {
        FUADXSHELL_LOG_E("Error while formatting dex file name: %s", strerror(errno));
        return NULL;
    }
    FUADXSHELL_LOG_D("Dex file name: %s", dexFile);
    get_package_name(progname);
    bytesWritten = snprintf(dexPath, sizeof(dexPath), defaultPath, progname, dexFile);
    if (bytesWritten < 0 || bytesWritten >= (long)sizeof(dexPath))
    {
        FUADXSHELL_LOG_E("Error while formatting dex path: %s", strerror(errno));
        return NULL;
    }
    parentDir = dirname(dexPath);
    FUADXSHELL_LOG_D("Dex path: %s", dexPath);
    FUADXSHELL_LOG_D("Parent directory: %s", parentDir);
    memset(dexPath, 0, sizeof(dexPath));
    /* Setting up JNI Array List */
    arrayListClass = (*env)->FindClass(env, jniNames[0]);
    if (unlikely(!arrayListClass))
    {
        FUADXSHELL_LOG_E("Error while finding ArrayList class");
        (*env)->ExceptionCheck(env);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return NULL;
    }
    arrayListCtorMethodId = (*env)->GetMethodID(env, arrayListClass, jniNames[1], jniNames[2]);
    if (unlikely(!arrayListCtorMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting ArrayList constructor method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    addMethodId = (*env)->GetMethodID(env, arrayListClass, jniNames[3], jniNames[4]);
    if (unlikely(!addMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting add method ID for ArrayList");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    classFile = (*env)->FindClass(env, jniNames[5]);
    if (unlikely(!classFile))
    {
        FUADXSHELL_LOG_E("Error while finding File class");
        (*env)->ExceptionCheck(env);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    ctorFileMethodId = (*env)->GetMethodID(env, classFile, jniNames[6], jniNames[7]);
    if (unlikely(!ctorFileMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting File constructor method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, classFile);
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    dexFileListObject = (*env)->NewObject(env, arrayListClass, arrayListCtorMethodId);
    if (unlikely(!dexFileListObject))
    {
        FUADXSHELL_LOG_E("Error while creating new ArrayList object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, classFile);
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    /* It should be at least one dex file with classes1.dex */
    dir = opendir(parentDir);
    if (!dir)
    {
        FUADXSHELL_LOG_E("Error while opening directory %s: %s", parentDir, strerror(errno));
        (*env)->DeleteLocalRef(env, dexFileListObject);
        (*env)->DeleteLocalRef(env, classFile);
        (*env)->DeleteLocalRef(env, arrayListClass);
        return NULL;
    }
    FUADXSHELL_LOG_D("Opened directory %s successfully", parentDir);
    while ((entry = readdir(dir)) != NULL)
    {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        {
            FUADXSHELL_LOG_D("Skipping self or parent directory: %s", entry->d_name);
            continue;
        }
        if (!strncmp(entry->d_name, classesNeedle, 7) && strstr(entry->d_name, dexNeedle))
        {
            /* Found dex file. Adding to list */
            FUADXSHELL_LOG_D("Found dex file at %s/%s", parentDir, entry->d_name);
            bytesWritten = snprintf(dexPath, sizeof(dexPath), "%s/%s", parentDir, entry->d_name);
            if (bytesWritten < 0 || bytesWritten >= (long)sizeof(dexPath))
            {
                FUADXSHELL_LOG_E("Error while formatting dex path: %s", strerror(errno));
                closedir(dir);
                (*env)->DeleteLocalRef(env, dexFileListObject);
                (*env)->DeleteLocalRef(env, classFile);
                (*env)->DeleteLocalRef(env, arrayListClass);
                return NULL;
            }
            if (sys_stat(dexPath, &stat) != 0 || !S_ISREG(stat.st_mode))
            {
                FUADXSHELL_LOG_D("File didn't meet criteria, moving to next: %s", dexPath);
                continue;
            }
            jniFilePath = (*env)->NewStringUTF(env, dexPath);
            if (unlikely(!jniFilePath))
            {
                FUADXSHELL_LOG_E("Error while creating jniFilePath string");
                if ((*env)->ExceptionCheck(env))
                {
                    (*env)->ExceptionDescribe(env);
                    (*env)->ExceptionClear(env);
                }
                closedir(dir);
                (*env)->DeleteLocalRef(env, dexFileListObject);
                (*env)->DeleteLocalRef(env, classFile);
                (*env)->DeleteLocalRef(env, arrayListClass);
                return NULL;
            }
            dexFileObject = (*env)->NewObject(env, classFile, ctorFileMethodId, jniFilePath);
            if (unlikely(!dexFileObject))
            {
                FUADXSHELL_LOG_E("Error while creating new File object for dex file");
                if ((*env)->ExceptionCheck(env))
                {
                    (*env)->ExceptionDescribe(env);
                    (*env)->ExceptionClear(env);
                }
                (*env)->DeleteLocalRef(env, jniFilePath);
                closedir(dir);
                (*env)->DeleteLocalRef(env, dexFileListObject);
                (*env)->DeleteLocalRef(env, classFile);
                (*env)->DeleteLocalRef(env, arrayListClass);
                return NULL;
            }
            setWritableMethodId = (*env)->GetMethodID(env, classFile, "setWritable", "(Z)Z");
            if (unlikely(!setWritableMethodId))
            {
                FUADXSHELL_LOG_E("Error while getting setWritable method ID for File class");
                if ((*env)->ExceptionCheck(env))
                {
                    (*env)->ExceptionDescribe(env);
                    (*env)->ExceptionClear(env);
                }
                (*env)->DeleteLocalRef(env, jniFilePath);
                (*env)->DeleteLocalRef(env, dexFileObject);
                closedir(dir);
                (*env)->DeleteLocalRef(env, dexFileListObject);
                (*env)->DeleteLocalRef(env, classFile);
                (*env)->DeleteLocalRef(env, arrayListClass);
                return NULL;
            }
            (*env)->CallBooleanMethod(env, dexFileObject, setWritableMethodId, JNI_FALSE); /* Set file non-writable */
            (*env)->CallBooleanMethod(env, dexFileListObject, addMethodId, dexFileObject);
            if ((*env)->ExceptionCheck(env))
            {
                FUADXSHELL_LOG_E("Error while adding dex file to ArrayList");
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, jniFilePath);
                (*env)->DeleteLocalRef(env, dexFileObject);
                closedir(dir);
                (*env)->DeleteLocalRef(env, dexFileListObject);
                (*env)->DeleteLocalRef(env, classFile);
                (*env)->DeleteLocalRef(env, arrayListClass);
                return NULL;
            }
            FUADXSHELL_LOG_D("Dex file %s added to ArrayList", dexPath);
            (*env)->DeleteLocalRef(env, jniFilePath);
            (*env)->DeleteLocalRef(env, dexFileObject);
        }
    }
    closedir(dir);
    FUADXSHELL_LOG_D("All dex files processed successfully");
    return dexFileListObject;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline ssize_t update_pathlist(JNIEnv *env, jobject contextObject, jobject fileArrayListObject)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char deletableDir[] = "/data/data";
    ATTRIBUTES(section(".rodata_ext"), used) static const char dexOptDir[] = "fuadx_files";
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char progname[4096] = { 0 };
    char fullDir[512] = { 0 };
    char deleteFilePath[512] = { 0 };
    ssize_t bytesWritten;
    jclass methodClass = NULL;
    jclass objectClass = NULL;
    jclass classLoaderClass = NULL;
    jclass contextClass = NULL;
    jclass pathListClass = NULL;
    jclass arrayListClass = NULL;
    jclass listClass = NULL;
    jclass fileClass = NULL;
    jclass elementType = NULL;
    jclass dexElementsClass = NULL;
    jmethodID getClassLoaderMethodId = NULL;
    jmethodID getMethodId = NULL;
    jmethodID getDexelementsMethodId = NULL;
    jmethodID arrayListCtorMethodId = NULL;
    jmethodID getDirMethodId = NULL;
    jmethodID invokeMethodId = NULL;
    jmethodID setMethodId = NULL;
    jobject classLoaderObject = NULL;
    jobject pathListField = NULL;
    jobject pathListObject = NULL;
    jobject dexElementsField = NULL;
    jobject arrayListObject = NULL;
    jobject makeDexMethod = NULL;
    jobject outdirObject = NULL;
    jobject element = NULL;
    jstring outdirPath = NULL;
    jobjectArray dexElementsArray = NULL;
    jobjectArray newElementsArray = NULL;
    jobjectArray tmpArray = NULL;
    jobjectArray mergedArray = NULL;
    jobjectArray params = NULL;
    jsize addCounter;
    jsize oldCounter;

    contextClass = (*env)->GetObjectClass(env, contextObject);
    classLoaderClass = (*env)->FindClass(env, "java/lang/ClassLoader");
    if (unlikely(!classLoaderClass))
    {
        FUADXSHELL_LOG_E("Error while finding ClassLoader class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    getClassLoaderMethodId = (*env)->GetMethodID(env, contextClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (unlikely(!getClassLoaderMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getClassLoader method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, classLoaderClass);
        return -1;
    }
    classLoaderObject = (*env)->CallObjectMethod(env, contextObject, getClassLoaderMethodId);
    if (unlikely(!classLoaderObject))
    {
        FUADXSHELL_LOG_E("Error while getting ClassLoader object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, classLoaderClass);
        return -1;
    }
    pathListField = get_field_object(env, classLoaderObject, "pathList");
    if (unlikely(!pathListField))
    {
        FUADXSHELL_LOG_E("Error while getting pathList object from ClassLoader");
        (*env)->DeleteLocalRef(env, classLoaderObject);
        (*env)->DeleteLocalRef(env, classLoaderClass);
        return -1;
    }
    pathListClass = (*env)->GetObjectClass(env, pathListField);
    getMethodId = (*env)->GetMethodID(env, pathListClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    if (unlikely(!getMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting get method ID from pathList");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    pathListObject = (*env)->CallObjectMethod(env, pathListField, getMethodId, classLoaderObject);
    if (unlikely(!pathListObject))
    {
        FUADXSHELL_LOG_E("Error while getting pathList object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    /* pathList retrieved / Build new dex elements */
    dexElementsField = get_field_object(env, pathListObject, "dexElements");
    if (unlikely(!dexElementsField))
    {
        FUADXSHELL_LOG_E("Error while getting dexElements field from pathList");
        return -1;
    }
    dexElementsClass = (*env)->GetObjectClass(env, dexElementsField);
    getDexelementsMethodId = (*env)->GetMethodID(env, dexElementsClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    if (unlikely(!getDexelementsMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getDexelements method ID from dexElements");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    dexElementsArray = (jobjectArray)(*env)->CallObjectMethod(env, dexElementsField, getDexelementsMethodId, pathListObject);
    if (unlikely(!dexElementsArray))
    {
        FUADXSHELL_LOG_E("Error while getting dexElements array");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    oldCounter = (*env)->GetArrayLength(env, dexElementsArray);
    /* makeDexElements method */
    listClass = (*env)->FindClass(env, "java/util/List");
    if (unlikely(!listClass))
    {
        FUADXSHELL_LOG_E("Error while finding List class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        return -1;
    }
    fileClass = (*env)->FindClass(env, "java/io/File");
    if (unlikely(!fileClass))
    {
        FUADXSHELL_LOG_E("Error while finding File class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    arrayListClass = (*env)->FindClass(env, "java/util/ArrayList");
    if (unlikely(!arrayListClass))
    {
        FUADXSHELL_LOG_E("Error while finding ArrayList class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    arrayListCtorMethodId = (*env)->GetMethodID(env, arrayListClass, "<init>", "()V");
    if (unlikely(!arrayListCtorMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting ArrayList constructor method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    arrayListObject = (*env)->NewObject(env, arrayListClass, arrayListCtorMethodId);
    if (unlikely(!arrayListObject))
    {
        FUADXSHELL_LOG_E("Error while creating new ArrayList object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    objectClass = (*env)->FindClass(env, "java/lang/Object");
    if (unlikely(!objectClass))
    {
        FUADXSHELL_LOG_E("Error while finding Object class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    if (android_get_application_target_sdk_version() < 26)
    {
        FUADXSHELL_LOG_D("Working makeDexElements with three parameters");
        params = (*env)->NewObjectArray(env, 3, (*env)->FindClass(env, "java/lang/Class"), NULL);
        if (unlikely(!params))
        {
            FUADXSHELL_LOG_E("Error while creating new ObjectArray for params");
            if ((*env)->ExceptionCheck(env))
            {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
            }
            (*env)->DeleteLocalRef(env, arrayListObject);
            (*env)->DeleteLocalRef(env, arrayListClass);
            (*env)->DeleteLocalRef(env, fileClass);
            (*env)->DeleteLocalRef(env, listClass);
            return -1;
        }
        (*env)->SetObjectArrayElement(env, params, 0, listClass);
        (*env)->SetObjectArrayElement(env, params, 1, fileClass);
        (*env)->SetObjectArrayElement(env, params, 2, listClass);
    }
    else
    {
        FUADXSHELL_LOG_D("Working makeDexElements with four parameters");
        params = (*env)->NewObjectArray(env, 4, (*env)->FindClass(env, "java/lang/Class"), NULL);
        if (unlikely(!params))
        {
            FUADXSHELL_LOG_E("Error while creating new ObjectArray for params");
            if ((*env)->ExceptionCheck(env))
            {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
            }
            (*env)->DeleteLocalRef(env, arrayListObject);
            (*env)->DeleteLocalRef(env, arrayListClass);
            (*env)->DeleteLocalRef(env, fileClass);
            (*env)->DeleteLocalRef(env, listClass);
            return -1;
        }
        (*env)->SetObjectArrayElement(env, params, 0, listClass);
        (*env)->SetObjectArrayElement(env, params, 1, fileClass);
        (*env)->SetObjectArrayElement(env, params, 2, listClass);
        (*env)->SetObjectArrayElement(env, params, 3, classLoaderClass);
    }
    makeDexMethod = get_method_object(env, pathListObject, "makeDexElements", params);
    if (unlikely(!makeDexMethod))
    {
        FUADXSHELL_LOG_E("Error while getting makeDexElements method object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    getDirMethodId = (*env)->GetMethodID(env, contextClass, "getDir", "(Ljava/lang/String;I)Ljava/io/File;");
    outdirPath = (*env)->NewStringUTF(env, "outdex");
    if (unlikely(!getDirMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getDir method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    outdirObject = (*env)->CallObjectMethod(env, contextObject, getDirMethodId, outdirPath, 0);
    if (unlikely(!outdirObject))
    {
        FUADXSHELL_LOG_E("Error while getting outdir object");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    methodClass = (*env)->FindClass(env, "java/lang/reflect/Method");
    if (unlikely(!methodClass))
    {
        FUADXSHELL_LOG_E("Error while finding Method class");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    invokeMethodId = (*env)->GetMethodID(env, methodClass, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (unlikely(!invokeMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting invoke method ID");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    tmpArray = (*env)->NewObjectArray(env, 4, objectClass, NULL);
    if (unlikely(!tmpArray))
    {
        FUADXSHELL_LOG_E("Error while creating new ObjectArray for tmpArray");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    (*env)->SetObjectArrayElement(env, tmpArray, 0, fileArrayListObject);
    (*env)->SetObjectArrayElement(env, tmpArray, 1, outdirObject);
    (*env)->SetObjectArrayElement(env, tmpArray, 2, (*env)->NewObject(env, (*env)->FindClass(env, "java/util/ArrayList"), arrayListCtorMethodId));
    (*env)->SetObjectArrayElement(env, tmpArray, 3, classLoaderObject);
    newElementsArray = (jobjectArray) (*env)->CallObjectMethod(env, makeDexMethod, invokeMethodId, pathListObject, (jobjectArray)tmpArray);
    if (unlikely(!newElementsArray))
    {
        FUADXSHELL_LOG_E("Error while getting newElements array");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, tmpArray);
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    addCounter = (*env)->GetArrayLength(env, newElementsArray);
    /* Merge old and new arrays */
    elementType = (*env)->GetObjectClass(env, (*env)->GetObjectArrayElement(env, dexElementsArray, 0));
    if (unlikely(!elementType))
    {
        FUADXSHELL_LOG_E("Error while getting element type from dexElementsArray");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, newElementsArray);
        (*env)->DeleteLocalRef(env, tmpArray);
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    mergedArray = (*env)->NewObjectArray(env, oldCounter + addCounter, elementType, NULL);
    if (unlikely(!mergedArray))
    {
        FUADXSHELL_LOG_E("Error while creating new ObjectArray for mergedArray");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, elementType);
        (*env)->DeleteLocalRef(env, newElementsArray);
        (*env)->DeleteLocalRef(env, tmpArray);
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    for (jsize i = 0; i < oldCounter; i++)
    {
        element = (*env)->GetObjectArrayElement(env, dexElementsArray, i);
        (*env)->SetObjectArrayElement(env, mergedArray, i, element);
        (*env)->DeleteLocalRef(env, element);
    }
    for (jsize i = 0; i < addCounter; i++)
    {
        element = (*env)->GetObjectArrayElement(env, newElementsArray, i);
        (*env)->SetObjectArrayElement(env, mergedArray, oldCounter + i, element);
        (*env)->DeleteLocalRef(env, element);
    }
    /* Replace pathList.dexElements with mergedArray */
    setMethodId = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, dexElementsField), "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");
    if (unlikely(!setMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting set method ID from dexElements");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, mergedArray);
        (*env)->DeleteLocalRef(env, elementType);
        (*env)->DeleteLocalRef(env, newElementsArray);
        (*env)->DeleteLocalRef(env, tmpArray);
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    (*env)->CallVoidMethod(env, dexElementsField, setMethodId, pathListObject, mergedArray);
    if ((*env)->ExceptionCheck(env))
    {
        FUADXSHELL_LOG_E("Error while setting new dexElements array to pathList");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, mergedArray);
        (*env)->DeleteLocalRef(env, elementType);
        (*env)->DeleteLocalRef(env, newElementsArray);
        (*env)->DeleteLocalRef(env, tmpArray);
        (*env)->DeleteLocalRef(env, methodClass);
        (*env)->DeleteLocalRef(env, outdirObject);
        (*env)->DeleteLocalRef(env, outdirPath);
        (*env)->DeleteLocalRef(env, makeDexMethod);
        (*env)->DeleteLocalRef(env, params);
        (*env)->DeleteLocalRef(env, arrayListObject);
        (*env)->DeleteLocalRef(env, arrayListClass);
        (*env)->DeleteLocalRef(env, fileClass);
        (*env)->DeleteLocalRef(env, listClass);
        return -1;
    }
    FUADXSHELL_LOG_D("Dex elements updated successfully, total elements: %d", oldCounter + addCounter);
    if (get_package_name(progname) < 0)
    {
        FUADXSHELL_LOG_E("Error while getting package name");
        return -1;
    }
    bytesWritten = snprintf(fullDir, sizeof(fullDir), "%s/%s/%s", deletableDir, progname, dexOptDir);
    if (bytesWritten < 0 || bytesWritten >= (long)sizeof(fullDir))
    {
        FUADXSHELL_LOG_E("Error while formatting fullDir path");
        return -1;
    }
    FUADXSHELL_LOG_D("Deleting everything under %s", fullDir);
    dir = opendir(fullDir);
    if (!dir)
    {
        FUADXSHELL_LOG_E("Error while opening directory %s: %s", fullDir, strerror(errno));
        return -1;
    }
    while ((entry = readdir(dir)) != NULL)
    {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        {
            FUADXSHELL_LOG_D("Skipping self or parent directory: %s", entry->d_name);
            continue;
        }
        bytesWritten = snprintf(deleteFilePath, sizeof(fullDir), "%s/%s", fullDir, entry->d_name);
        if (bytesWritten < 0 || bytesWritten >= (long)sizeof(fullDir))
        {
            FUADXSHELL_LOG_E("Error while formatting filePath path: %s", deleteFilePath);
            closedir(dir);
            return -1;
        }
        if (sys_unlink(deleteFilePath) < 0)
        {
            FUADXSHELL_LOG_E("Error while deleting file at path %s: %s", deleteFilePath, strerror(errno));
            closedir(dir);
            return -1;
        }
        FUADXSHELL_LOG_D("Deleted file %s successfully", fullDir);
        if (__builtin_available(android 34, *))
            memset_explicit(deleteFilePath, 0, sizeof(deleteFilePath));
        else
            OPENSSL_cleanse(deleteFilePath, sizeof(deleteFilePath));
    }
    if (rmdir(fullDir) < 0)
    {
        FUADXSHELL_LOG_E("Error while deleting directory %s: %s", fullDir, strerror(errno));
        closedir(dir);
        return -1;
    }
    if (__builtin_available(android 34, *))
        memset_explicit(fullDir, 0, sizeof(fullDir));
    else
        OPENSSL_cleanse(fullDir, sizeof(fullDir));
    return 0;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline jobject get_field_object(JNIEnv *env, jobject instance, const char *name)
{
    ATTRIBUTES(section(".rodata_ext")) static const char jniNames[][256] =
    {
        "java/lang/Class",
        "java/lang/reflect/Field",
        "getSuperclass",
        "()Ljava/lang/Class;",
        "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
        "setAccessible",
        "(Z)V"
    };
    jclass classClass = NULL;
    jclass fieldClass = NULL;
    jclass currentClass = NULL;
    jclass upperClass = NULL;
    jmethodID getSuperclassMethodId = NULL;
    jmethodID getDeclaredFieldMethodId = NULL;
    jmethodID setAccessibleMethodId = NULL;
    jstring jniName = NULL;
    jobject fieldObject = NULL;

    classClass = (*env)->FindClass(env, jniNames[0]);
    if (unlikely(!classClass))
    {
        FUADXSHELL_LOG_E("Error while finding Class class");
        return NULL;
    }
    fieldClass = (*env)->FindClass(env, jniNames[1]);
    if (unlikely(!fieldClass))
    {
        FUADXSHELL_LOG_E("Error while finding Field class");
        (*env)->DeleteLocalRef(env, classClass);
        return NULL;
    }
    getSuperclassMethodId = (*env)->GetMethodID(env, classClass, jniNames[2], jniNames[3]);
    if (unlikely(!getSuperclassMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getSuperclass method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, fieldClass);
        return NULL;
    }
    getDeclaredFieldMethodId = (*env)->GetMethodID(env, classClass, jniNames[4], jniNames[5]);
    if (unlikely(!getDeclaredFieldMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getDeclaredField method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, fieldClass);
        return NULL;
    }
    setAccessibleMethodId = (*env)->GetMethodID(env, fieldClass, jniNames[6], jniNames[7]);
    if (unlikely(!setAccessibleMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting setAccessible method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, fieldClass);
        return NULL;
    }
    currentClass = (*env)->GetObjectClass(env, instance);
    if (unlikely(!currentClass))
    {
        FUADXSHELL_LOG_E("Error while getting class of instance");
        return NULL;
    }
    jniName = (*env)->NewStringUTF(env, name);
    if (unlikely(!jniName))
    {
        FUADXSHELL_LOG_E("Error while creating jniName string");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, fieldClass);
        (*env)->DeleteLocalRef(env, currentClass);
        return NULL;
    }
    while (currentClass != NULL)
    {
        fieldObject = (*env)->CallObjectMethod(env, currentClass, getDeclaredFieldMethodId, jniName);
        if (!(*env)->ExceptionCheck(env))
        {
            /* Found */
            (*env)->CallVoidMethod(env, fieldObject, setAccessibleMethodId, JNI_TRUE);
            if ((*env)->ExceptionCheck(env))
            {
                FUADXSHELL_LOG_E("Error while setting field accessible");
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, jniName);
                (*env)->DeleteLocalRef(env, currentClass);
                (*env)->DeleteLocalRef(env, fieldClass);
                (*env)->DeleteLocalRef(env, classClass);
                return NULL;
            }
            (*env)->DeleteLocalRef(env, jniName);
            (*env)->DeleteLocalRef(env, currentClass);
            return fieldObject;
        }
        (*env)->ExceptionClear(env);
        /* Not found, try superclass */
        upperClass = (*env)->CallObjectMethod(env, currentClass, getSuperclassMethodId);
        if ((*env)->ExceptionCheck(env))
        {
            FUADXSHELL_LOG_E("Error while getting superclass of current class");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, jniName);
            (*env)->DeleteLocalRef(env, currentClass);
            (*env)->DeleteLocalRef(env, fieldClass);
            (*env)->DeleteLocalRef(env, classClass);
            return NULL;
        }
        (*env)->DeleteLocalRef(env, currentClass);
        currentClass = upperClass;
    }
    (*env)->DeleteLocalRef(env, jniName);
    FUADXSHELL_LOG_D("Error: Field %s not found in class hierarchy", name);
    return NULL;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline jobject get_method_object(JNIEnv *env, jobject instance, const char *name, jobjectArray params)
{
    ATTRIBUTES(section(".rodata_ext")) static const char jniNames[][256] =
    {
        "java/lang/Class",
        "java/lang/reflect/Method",
        "getSuperclass",
        "()Ljava/lang/Class;",
        "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        "setAccessible",
        "(Z)V"
    };
    jclass classClass = NULL;
    jclass methodClass = NULL;
    jclass classArray = NULL;
    jclass currentClass = NULL;
    jclass upperClass = NULL;
    jmethodID getSuperclassMethodId = NULL;
    jmethodID getDeclaredMethodMethodId = NULL;
    jmethodID setAccessibleMethodId = NULL;
    jstring jniName = NULL;
    jobject methodObject = NULL;

    classClass = (*env)->FindClass(env, jniNames[0]);
    methodClass = (*env)->FindClass(env, jniNames[1]);
    if (unlikely(!classClass || !methodClass))
    {
        FUADXSHELL_LOG_E("Error while finding Class or Method class");
        return NULL;
    }
    getSuperclassMethodId = (*env)->GetMethodID(env, classClass, jniNames[2], jniNames[3]);
    if (unlikely(!getSuperclassMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getSuperclass method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, methodClass);
        return NULL;
    }
    getDeclaredMethodMethodId = (*env)->GetMethodID(env, classClass, jniNames[4], jniNames[5]);
    if (unlikely(!getDeclaredMethodMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting getDeclaredMethod method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, methodClass);
        return NULL;
    }
    setAccessibleMethodId = (*env)->GetMethodID(env, methodClass, jniNames[6], jniNames[7]);
    if (unlikely(!setAccessibleMethodId))
    {
        FUADXSHELL_LOG_E("Error while getting setAccessible method ID");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, methodClass);
        return NULL;
    }
    /* Check array values */
    if (!params)
    {
        classArray = classClass; /* Class.class */
        params = (*env)->NewObjectArray(env, 0, classArray, NULL);
        if ((*env)->ExceptionCheck(env))
        {
            FUADXSHELL_LOG_E("Error while creating empty object array for parameters");
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, classClass);
            (*env)->DeleteLocalRef(env, methodClass);
            return NULL;
        }
    }
    /* Look for method */
    currentClass = (*env)->GetObjectClass(env, instance);
    jniName = (*env)->NewStringUTF(env, name);
    if (unlikely(!jniName))
    {
        FUADXSHELL_LOG_E("Error while creating jniName string");
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classClass);
        (*env)->DeleteLocalRef(env, methodClass);
        return NULL;
    }
    while (currentClass)
    {
        methodObject = (*env)->CallObjectMethod(env, currentClass, getDeclaredMethodMethodId, jniName, params);
        if (!(*env)->ExceptionCheck(env))
        {
            /* Found */
            (*env)->CallVoidMethod(env, methodObject, setAccessibleMethodId, JNI_TRUE);
            if ((*env)->ExceptionCheck(env))
                (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, jniName);
            (*env)->DeleteLocalRef(env, currentClass);
            (*env)->DeleteLocalRef(env, methodClass);
            (*env)->DeleteLocalRef(env, classClass);
            return methodObject;
        }
        (*env)->ExceptionClear(env);
        /* Not found, try superclass */
        upperClass = (*env)->CallObjectMethod(env, currentClass, getSuperclassMethodId);
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, currentClass);
        currentClass = upperClass;
    }
    (*env)->DeleteLocalRef(env, jniName);
    FUADXSHELL_LOG_D("Error: Method %s not found in class hierarchy", name);
    (*env)->DeleteLocalRef(env, methodClass);
    (*env)->DeleteLocalRef(env, classClass);
    return NULL;
}

ATTRIBUTES(always_inline, section(".text_ext"), overloadable, used)
static inline ssize_t get_package_name(char *buf)
{
    ssize_t readBytes;
    ATTRIBUTES(cleanup(raii_fd)) int fd = 0;

    fd = sys_open(PROC_CMDLINE, O_RDONLY | O_CLOEXEC, 0);
    if (fd > 0)
    {
        if ((readBytes = sys_read(fd, buf, 4095)) > 0)
        {
            buf[readBytes] = '\0'; /* Ensure null-termination */
            FUADXSHELL_LOG_D("Package name retrieved from cmdline: %s", buf);
            return 0;
        }
        else
        {
            FUADXSHELL_LOG_E("Error while reading cmdline file: %s", strerror(errno));
            return -1;
        }
    }
    else
    {
        FUADXSHELL_LOG_E("Error while opening cmdline file: %s", strerror(errno));
        /* Using progname */
        if (getprogname() && strlen(getprogname()) < 4095)
        {
            snprintf(buf, 4095, "%s", getprogname());
            FUADXSHELL_LOG_D("Package name retrieved from getprogname: %s", buf);
            return 0;
        }
    }
    return -1;
}

ATTRIBUTES(always_inline, section(".text_ext"), overloadable, used)
static inline ssize_t get_package_name(char *buf, const char *mAppCls)
{
    ssize_t n;
    size_t need;
    ATTRIBUTES(cleanup(raii_fd)) int fd = 0;

    fd = sys_open(PROC_CMDLINE, O_RDONLY | O_CLOEXEC, 0);
    if (fd > 0)
    {
        n = sys_read(fd, buf, 4095);
        if (n < 0 )
        {
            FUADXSHELL_LOG_E("Error while reading cmdline file: %s", strerror(errno));
            return -1;
        }
        buf[n] = '\0';
        need = strlen(buf) + strlen(mAppCls) + 1;
        if (need > 4095)
        {
            FUADXSHELL_LOG_E("Buffer too small for package name and MainApplication class: %zu bytes needed", need);
            return -ENOMEM;
        }
        strlcat(buf, mAppCls, 4095);
        FUADXSHELL_LOG_D("Package name with MainApplication class updated: %s", buf);
        return 0;
    }
    FUADXSHELL_LOG_E("Error while opening cmdline file: %s", strerror(errno));
    return -1;
}

ATTRIBUTES(always_inline, used)
static inline int get_library_info(const char *abi, struct dl_phdr_info *info, Dl_info *dlInfo)
{
    /* Strings */
    static const char suffix[] = "/base.apk";
    char basePath[512] = { 0 };
    char concatenatedPath[512] = { 0 };
    const char *separator = "/";
    /* Memory addresses / Pointers */
    void *paddr = NULL;
    /* ELF-related structs */
    Elf_Word sectionOffset = -1;
    Elf_Word sectionSize = -1;
    /* Sizes */
    size_t written;
    size_t dirBaseLength;
    /* Test errno or custom errors */
    int testError = 0;
    /* Kernel stat structures */
    struct kernel_stat statBase;
    /* So info struct */
    ATTRIBUTES(cleanup(raii_so_info_t)) so_info_t output =
    {
        .path = NULL,
        .loadedMem = NULL,
        .loadedAddr = NULL,
        .loadedMemSize = 0,
        .resource = { 0, { 0 } }
    };

    FUADXSHELL_LOG_D("ApkInfo: basePath=%s, apkLookup=%u", apkInfo.basePath, apkInfo.apkLookup);
    if (apkInfo.apkLookup & APK_INFO_EXTRACT_NATIVE_LIBS_TRUE)
    {
        /* Extracted shared libraries */
        if (!apkInfo.basePath || !abi || !info)
        {
            FUADXSHELL_LOG_E("Invalid parameters provided to get_library_info: %p - %p - %p", apkInfo.basePath, abi, info);
            return -EACCES;
        }
        dirBaseLength = strlen(apkInfo.basePath) - strlen(suffix);
        if (dirBaseLength + 1 < sizeof(basePath))
        {
            memcpy(basePath, apkInfo.basePath, dirBaseLength);
            basePath[dirBaseLength] = '\0';
        }
        else
        {
            FUADXSHELL_LOG_E("Base path too long: %zu bytes", dirBaseLength + 1);
            return -EINVAL;
        }
        if (sys_stat(basePath,  &statBase) == -1 || !S_ISDIR(statBase.st_mode))
        {
            FUADXSHELL_LOG_E("Base path is not a directory or does not exist: %s", basePath);
            return -ENOENT;
        }
        written = snprintf(concatenatedPath, sizeof(concatenatedPath), "%s%slib%s%s%slibfuadxshell.so",
                           basePath, separator, separator, abi, separator);
        if (unlikely(written < 0) || written >= sizeof(concatenatedPath))
        {
            FUADXSHELL_LOG_E("Error while concatenating path with %zu bytes written", written);
            return -EINVAL;
        }
        if (sys_stat(concatenatedPath, &statBase) == -1 || !S_ISREG(statBase.st_mode)
            || statBase.st_size == 0)
        {
            FUADXSHELL_LOG_E("Shared library does not exist or is empty: %s", concatenatedPath);
            return -ENOENT;
        }
        if (lookup_library_info(info, dlInfo, &output, concatenatedPath, true) != 0)
        {
            FUADXSHELL_LOG_E("Error while looking up library info for %s", concatenatedPath);
            return -ENODECR;
        }
        initialized |= INITIALIZED_FOUND_RX;
        paddr = sys_mmap(0, output.loadedMemSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (unlikely(paddr == MAP_FAILED))
        {
            FUADXSHELL_LOG_E("Error while mapping memory for shared library: %s", strerror(errno));
            return -ENOMEM;
        }
        else
        {
            (void)memcpy(paddr, output.loadedMem, output.loadedMemSize);
            FUADXSHELL_LOG_D("Shared library loaded from: %s", output.path);
        }
    }
    else
    {
        /* Fallback when shared libraries are not extracted */
        if (lookup_library_info(info, dlInfo, &output, apkInfo.basePath, false) != 0)
        {
            FUADXSHELL_LOG_E("Error while looking up library info for %s", apkInfo.basePath);
            return -ENODECR;
        }
        initialized |= INITIALIZED_FOUND_RX;
        paddr = sys_mmap(0, output.loadedMemSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        if (unlikely(paddr == MAP_FAILED))
        {
            FUADXSHELL_LOG_E("Error while mapping memory for shared library: %s", strerror(errno));
            return -ENOMEM;
        }
        else
        {
            (void)memcpy(paddr, output.loadedMem, output.loadedMemSize);
            FUADXSHELL_LOG_D("Shared library loaded from: %s", output.path);
        }
    }
    /* Parse ELF header and segments */
    testError = lookup_section(&sectionOffset, &sectionSize, paddr, ".text_ext");
    if (testError != 0 && unlikely(sectionOffset == -1 || sectionSize == -1))
        FUADXSHELL_LOG_E("Error while finding .text_ext section in shared library: %d", testError);
    /* Perform runtime decryption */
    if (perform(&output, sectionOffset, sectionSize) < 0)
        FUADXSHELL_LOG_E("Error while performing operation on shared library: %d", testError);
    /* Parse ELF Header and segments for rodata_ext */
    testError = lookup_section(&sectionOffset, &sectionSize, paddr, ".rodata_ext");
    if (testError != 0 && unlikely(sectionOffset == (unsigned int)-1 || sectionSize == (unsigned int)-1))
        FUADXSHELL_LOG_E("Error while finding .rodata_ext section in shared library: %d", testError);
    initialized |= INITIALIZED_ENC_SECTION_FOUND;
    /* Perform runtime decryption */
    if (perform(&output, sectionOffset, sectionSize) < 0)
        FUADXSHELL_LOG_E("Error while performing operation on shared library: %d", testError);
    initialized |= INITIALIZED_DEC_SECTION;
    FUADXSHELL_LOG_D("Shared library %s loaded successfully with address %p", output.path, output.loadedAddr);
    sys_munmap(paddr, output.loadedMemSize);
    return testError != 0 ? -ENODECR : 0;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static void load(JNIEnv *env, ATTRIBUTES(unused) void *this)
{
    void *activityThreadCls = NULL;
    void *currentActivityThreadMethodId = NULL;
    void *activityThreadObj = NULL;
    void *mBoundApplicationFieldId = NULL;
    void *mBoundApplicationObj = NULL;
    void *infoFieldId = NULL;
    void *infoObj = NULL;
    void *mApplicationFieldId = NULL;
    void *mInitialApplicationFieldId = NULL;
    void *mInitialApplicationObj = NULL;
    void *mAllApplicationsFieldId = NULL;
    void *mAllApplicationsObj = NULL;
    void *appInfoFieldId = NULL;
    void *removeMethodId = NULL;
    void *appInfoObj = NULL;
    void *mApplicationInfoFieldId = NULL;
    void *classNameFieldId = NULL;
    void *mApplicationInfoObj = NULL;
    void *newString = NULL;
    void *makeApplicationMethodId = NULL;
    void *originalAppObj = NULL;
    void *mProviderMapFieldId = NULL;
    void *mProviderMapObj = NULL;
    void *valuesMethodId = NULL;
    void *valuesObj = NULL;
    void *iteratorMethodId = NULL;
    void *iteratorObj = NULL;
    void *hasNextMethodId = NULL;
    void *nextMethodId = NULL;
    void *providerClientRecordObj = NULL;
    void *providerClientRecordCls = NULL;
    void *mLocalProviderFieldId = NULL;
    void *mLocalProviderObj = NULL;
    void *mContextFieldId = NULL;
    void *onCreateMethodId = NULL;
    ATTRIBUTES(section(".rodata_ext"), used) static const char stringsJni[][256] =
    {
        "android/app/ActivityThread",
        "ActivityThread class not found",
        "currentActivityThread",
        "()Landroid/app/ActivityThread;",
        "currentActivityThread method not found",
        "ActivityThread object not found",
        "mBoundApplication",
        "Landroid/app/ActivityThread$AppBindData;",
        "mBoundApplication field not found",
        "mBoundApplication object not found",
        "info",
        "Landroid/app/LoadedApk;",
        "info field not found",
        "LoadedApk object not found",
        "mApplication",
        "Landroid/app/Application;",
        "mApplication field not found",
        "mInitialApplication",
        "Landroid/app/Application;",
        "mInitialApplication field not found",
        "mInitialApplication object not found",
        "mAllApplications",
        "Ljava/util/ArrayList;",
        "mAllApplications field not found",
        "mAllApplications object not found",
        "remove",
        "(Ljava/lang/Object;)Z",
        "remove method ID not found",
        "Exception while removing mInitialApplication from mAllApplications",
        "appInfo",
        "Landroid/content/pm/ApplicationInfo;",
        "appInfo field id not found",
        "appInfo object not found",
        "mApplicationInfo",
        "Landroid/content/pm/ApplicationInfo;",
        "mApplicationInfo field id not found",
        "mApplicationInfo object not found",
        "className",
        "Ljava/lang/String;",
        "className field id not found",
        "Exception while creating a new string",
        "makeApplication",
        "(ZLandroid/app/Instrumentation;)Landroid/app/Application;",
        "mApplicationInfo field id not found",
        "Exception while creating new application",
        "mProviderMap",
        "Landroid/util/ArrayMap;",
        "mProviderMap field id not found",
        "mProviderMap object not found",
        "values",
        "()Ljava/util/Collection;",
        "values method id not found",
        "values object not found",
        "iterator",
        "()Ljava/util/Iterator;",
        "iterator method id not found",
        "Exception while creating iterator object",
        "hasNext",
        "()Z",
        "hasNext method id not found",
        "next",
        "()Ljava/lang/Object;",
        "next method id not found",
        "android/app/ActivityThread$ProviderClientRecord",
        "ProviderClientRecord class not found",
        "mLocalProvider",
        "Landroid/content/ContentProvider;",
        "mLocalProvider field id not found",
        "mLocalProvider object not found",
        "mContext",
        "Landroid/content/Context;",
        "mContext field id not found",
        "onCreate",
        "()V",
        "onCreate method id not found",
        "Exception while calling onCreate method"
    };
    char buf[4096] = { 0 };

    FUADXSHELL_LOG_D("Inside load function which will overlay MainApplication class");
    /* Get ActivityThread */
    activityThreadCls = getJNIClass(env, stringsJni[0]);
    if (!activityThreadCls)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[1]);

    /* Get currentActivityThread method */
    currentActivityThreadMethodId = getJNIStaticMethodID(env, activityThreadCls,
                                                         stringsJni[2], stringsJni[3]);
    if (!currentActivityThreadMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[4]);

    /* Get ActivityThread object */
    activityThreadObj = getJNIObject(env, activityThreadCls, currentActivityThreadMethodId);
    if (!activityThreadObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[5]);

    /* Get Application field ID */
    mBoundApplicationFieldId = getJNIFieldID(env, activityThreadCls, stringsJni[6], stringsJni[7]);
    if (!mBoundApplicationFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[8]);

    /* Get mBoundApplication object */
    mBoundApplicationObj = getJNIField(env, activityThreadObj, mBoundApplicationFieldId);
    if (!mBoundApplicationObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[9]);

    /* Get info field ID */
    infoFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, mBoundApplicationObj),
                                stringsJni[10], stringsJni[11]);
    if (!infoFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[12]);

    /* Get LoadedApk object */
    infoObj = getJNIField(env, mBoundApplicationObj, infoFieldId);
    if (!infoObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[13]);

    /* Get mApplication field ID */
    mApplicationFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, infoObj),
                                            stringsJni[14], stringsJni[15]);
    if (!mApplicationFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[16]);

    /* Set mApplication object to NULL */
    (*env)->SetObjectField(env, infoObj, mApplicationFieldId, NULL);

    /* Get mInitialApplication field ID */
    mInitialApplicationFieldId = getJNIFieldID(env, activityThreadCls,
                                               stringsJni[17], stringsJni[18]);
    if (!mInitialApplicationFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[19]);

    /* Get mInitialApplication object */
    mInitialApplicationObj = getJNIField(env, activityThreadObj, mInitialApplicationFieldId);
    if (!mInitialApplicationObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[20]);

    /* Get mAllApplications field ID */
    mAllApplicationsFieldId = getJNIFieldID(env, activityThreadCls,
                                                stringsJni[21], stringsJni[22]);
    if (!mAllApplicationsFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[23]);

    /* Get mAllApplications object */
    mAllApplicationsObj = getJNIField(env, activityThreadObj, mAllApplicationsFieldId);
    if (!mAllApplicationsObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[24]);

    /* Get remove method ID */
    removeMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, mAllApplicationsObj),
                                        stringsJni[25], stringsJni[26]);
    if (!removeMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[27]);

    /* Remove mInitialApplication from mAllApplications */
    (*env)->CallBooleanMethod(env, mAllApplicationsObj, removeMethodId, mInitialApplicationObj);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_D("Exception while removing mInitialApplication from mAllApplications");
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[28]);
    }

    /* Get appInfo field ID */
    appInfoFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, mBoundApplicationObj),
                                   stringsJni[29], stringsJni[30]);
    if (!appInfoFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[31]);

    /* Get appInfo object */
    appInfoObj = getJNIField(env, mBoundApplicationObj, appInfoFieldId);
    if (!appInfoObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[32]);

    /* Get mApplicationInfo field ID */
    mApplicationInfoFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, infoObj),
                                                stringsJni[33], stringsJni[34]);
    if (!mApplicationInfoFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[35]);

    /* Get mApplicationInfo object */
    mApplicationInfoObj = getJNIField(env, infoObj, mApplicationInfoFieldId);
    if (!mApplicationInfoObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[36]);

    /* Get className field ID */
    classNameFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, appInfoObj),
                                        stringsJni[37], stringsJni[38]);
    if (!classNameFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[39]);

    /* Set className field to original's name */
    if (get_package_name(buf, MAIN_APPLICATION_NAME) < 0)
    {
        FUADXSHELL_LOG_E("Error while getting package name");
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[40]);
    }
    else
        newString = (*env)->NewStringUTF(env, buf);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_D("Exception while creating a new string for: %s", MAIN_APPLICATION_NAME);
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[40]);
    }

    (*env)->SetObjectField(env, appInfoObj, classNameFieldId, newString);
    (*env)->SetObjectField(env, mApplicationInfoObj, classNameFieldId, newString);

    /* Get makeApplication method ID */
    makeApplicationMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, infoObj),
                                                stringsJni[41], stringsJni[42]);
    if (!makeApplicationMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[43]);

    /* Create new application */
    originalAppObj = (*env)->CallObjectMethod(env, infoObj, makeApplicationMethodId, 0, NULL);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_D("Exception while creating new application");
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[44]);
    }

    /* Set mInitialApplication to original application */
    (*env)->SetObjectField(env, activityThreadObj, mInitialApplicationFieldId, originalAppObj);

    /* Get mProviderMap field ID */
    mProviderMapFieldId = getJNIFieldID(env, activityThreadCls,
                                            stringsJni[45], stringsJni[46]);
    if (!mProviderMapFieldId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[47]);

    /* Get mProviderMap object */
    mProviderMapObj = getJNIField(env, activityThreadObj, mProviderMapFieldId);
    if (!mProviderMapObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[48]);

    /* Get values method ID */
    valuesMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, mProviderMapObj),
                                        stringsJni[49], stringsJni[50]);
    if (!valuesMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[51]);

    /* Get values object */
    valuesObj = (*env)->CallObjectMethod(env, mProviderMapObj, valuesMethodId);
    if (!valuesObj)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[52]);

    /* Get iterator method ID */
    iteratorMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, valuesObj),
                                            stringsJni[53], stringsJni[54]);
    if (!iteratorMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[55]);

    /* Get iterator object */
    iteratorObj = (*env)->CallObjectMethod(env, valuesObj, iteratorMethodId);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_D("Exception while creating iterator object");
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[56]);
    }

    /* Get hasNext method ID */
    hasNextMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, iteratorObj),
                                        stringsJni[57], stringsJni[58]);
    if (!hasNextMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[59]);

    /* Get next method ID */
    nextMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, iteratorObj),
                                  stringsJni[60], stringsJni[61]);
    if (!nextMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[62]);

    /* Iterate through all ContentProviders */
    while ((*env)->CallBooleanMethod(env, iteratorObj, hasNextMethodId))
    {
        providerClientRecordObj = (*env)->CallObjectMethod(env, iteratorObj, nextMethodId);
        if (!providerClientRecordObj)
        {
            FUADXSHELL_LOG_D("providerClientRecord is null");
            continue;
        }
        providerClientRecordCls = getJNIClass(env, stringsJni[63]);
        if (!providerClientRecordCls)
            (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[64]);

        /* Get mLocalProvider field ID */
        mLocalProviderFieldId = getJNIFieldID(env, providerClientRecordCls,
                                                stringsJni[65], stringsJni[66]);
        if (!mLocalProviderFieldId)
            (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[67]);

        /* Get mLocalProvider object */
        mLocalProviderObj = getJNIField(env, providerClientRecordObj, mLocalProviderFieldId);
        if (!mLocalProviderObj)
            (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[68]);

        /* Get mContext field ID */
        mContextFieldId = getJNIFieldID(env, (*env)->GetObjectClass(env, mLocalProviderObj),
                                            stringsJni[69], stringsJni[70]);
        if (!mContextFieldId)
            (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[71]);

        /* Set mContext field to original application */
        (*env)->SetObjectField(env, mLocalProviderObj, mContextFieldId, originalAppObj);
    }

    /* Get onCreate method ID */
    onCreateMethodId = getJNIMethodID(env, (*env)->GetObjectClass(env, originalAppObj),
                                        stringsJni[72], stringsJni[73]);
    if (!onCreateMethodId)
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[74]);

    /* Call onCreate method */
    (*env)->CallVoidMethod(env, originalAppObj, onCreateMethodId);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_D("Exception while calling onCreate method");
        (*env)->ThrowNew(env, jniThrowClassGlobal, stringsJni[75]);
    }
    (*env)->DeleteGlobalRef(env, jniThrowClassGlobal);
    FUADXSHELL_LOG_I("Application loaded successfully");
}