#include <debug.h>

typedef struct trap_event_t {
    void *addr;
    int signalNumber;
    int signalCode;
    ucontext_t *context;
} ATTRIBUTES(packed) trap_event_t;

volatile sig_atomic_t trapCtr = 0;
int pipefd[2];

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void get_random(uint32_t *buf, size_t size)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char urandomPath[] = "/dev/urandom";
    int fd;

    fd = sys_open(urandomPath, O_RDONLY, 0);
    if (unlikely(fd == -1))
    {
        FUADXSHELL_LOG_E("Error while opening /dev/urandom: %s", strerror(errno));
        return;
    }
    if (sys_read(fd, buf, size) == -1)
    {
        FUADXSHELL_LOG_E("Error while reading from /dev/urandom: %s", strerror(errno));
        sys_close(fd);
        return;
    }
    sys_close(fd);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void trap_handler(int signo, siginfo_t *info, void *ctx)
{
    trap_event_t event = { 0 };
    ucontext_t *context = NULL;

    event.context = context = (ucontext_t *)ctx;
    event.addr = info->si_addr;
    event.signalNumber = signo;
    event.signalCode = info->si_code;
    /* Write to pipe */
    sys_write(pipefd[1], &event, sizeof(event)); /* Doesn't matter if it fails, we just want to log it */
    #if defined(__arm__)
        uintptr_t instructionAddr = 0;
        uint16_t halfWord = 0;
        bool isThumb = false;
    #elif defined(__i386__)
        uint8_t *eip = NULL;
    #elif defined(__x86_64__)
        uint8_t *rip = NULL;
    #endif

    /* TODO: PENDIENTE CORRECCION EN ARMEABI-V7A */
    #if defined(__aarch64__)
        trapCtr++;
        uint32_t *pc = (uint32_t *)context->uc_mcontext.pc;
        if ((*pc) == 0xD4200000) /* BKPT */
            (*pc) = 0xD503201F; /* NOP */
    #elif defined(__arm__)
        trapCtr++;
        isThumb = context->uc_mcontext.arm_cpsr & (1u << 5);
        if (!isThumb)
            context->uc_mcontext.arm_pc += 4;
        else
        {
            instructionAddr = context->uc_mcontext.arm_pc & ~1u;
            halfWord = *(uint16_t *)instructionAddr;
            if ((halfWord & 0xF800) >= 0xE800)
                context->uc_mcontext.arm_pc = instructionAddr + 4 | 1;
            else
                context->uc_mcontext.arm_pc = instructionAddr + 2 | 1;
        }
    #elif defined (__i386__)
        trapCtr++;
        eip = (uint8_t *)context->uc_mcontext.gregs[REG_EIP];
        if ((*eip) == 0xCC) /* SIGTRAP */
            (*eip) = 0xC3; /* RET */
    #elif defined(__x86_64__)
        trapCtr++;
        rip = (uint8_t *)context->uc_mcontext.gregs[REG_RIP];
        if ((*rip) == 0xCC) /* TRAP */
            (*rip) = 0xC3; /* RET */
    #else
        #error "Unsupported architecture for trap handler"
    #endif
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline int set_handlers(void)
{
    struct sigaction sa_sigaction = { 0 };

    sa_sigaction.sa_sigaction = trap_handler;
    sa_sigaction.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;
    if (sigaction(SIGTRAP, &sa_sigaction, NULL) == -1)
    {
        FUADXSHELL_LOG_E("Error while setting SIGTRAP handler: %s", strerror(errno));
        return errno;
    }
    if (sigaction(SIGILL, &sa_sigaction, NULL) == -1)
    {
        FUADXSHELL_LOG_E("Error while setting SIGILL handler: %s", strerror(errno));
        return errno;
    }
    return 0;
}

_Noreturn ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *monitor_signal_handler(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char signals[][25] = { "SIGTRAP", "SIGILL" };
    ssize_t bytesRead;
    ssize_t bytesWritten;
    trap_event_t handler;
    char buffer[512] = { 0 };
    char signalName[32] = { 0 };

    sys_prctl(PR_SET_NAME, (unsigned long)"SignalHandlerMonitor\0", 0, 0, 0);
    FUADXSHELL_LOG_D("Starting signal handler monitoring");
    while (1)
    {
        bytesRead = sys_read(pipefd[0], &handler, sizeof(handler));
        if (bytesRead < 0)
            FUADXSHELL_LOG_E("Error while reading from pipe: %s", strerror(errno));
        else if (bytesRead == 0)
            FUADXSHELL_LOG_D("Pipe closed, exiting signal handler monitoring");
        else
        {
            switch (handler.signalNumber)
            {
                case SIGTRAP:
                    bytesWritten = snprintf(signalName, sizeof(signalName), "%s", signals[0]);
                    break;
                case SIGILL:
                    bytesWritten = snprintf(signalName, sizeof(signalName), "%s", signals[1]);
                    break;
                default:
                    bytesWritten = snprintf(signalName, sizeof(signalName), "Unknown Signal (%d)", handler.signalNumber);
                    break;
            }
            if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(signalName))
                FUADXSHELL_LOG_E("Error while formatting signal name: %s", strerror(errno));
            else
            {
                bytesWritten = snprintf(buffer, sizeof(buffer), "Signal: %d (%s), Code: %d, Address: %p, Context at: %p",
                handler.signalNumber, signalName, handler.signalCode, handler.addr, handler.context);
                if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(buffer))
                    FUADXSHELL_LOG_E("Error while formatting signal info: %s", strerror(errno));
                else
                    FUADXSHELL_LOG_D("SIGNAL HANDLER: %s", buffer);
            }
        }
    }
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_ptrace_traceme(ATTRIBUTES(unused) void *arg)
{
    if (sys_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        FUADXSHELL_LOG_D("Ptrace was found. Unable to attach: %s", strerror(errno));
        return (void *)(intptr_t)(-DEBUG_PTRACE_TRACEME_ACTIVE);
    }
    // int ret = sys_ptrace(PTRACE_DETACH, 0, 0, 0);
    // FUADXSHELL_LOG_D("Detaching from PTRACE_TRACEME: %d - %s", ret, ret < 0 ? strerror(errno) : "Success");
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_debug_property(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char prop[] = "ro.debuggable";
    char props[PROP_VALUE_MAX] = { 0 };

    FUADXSHELL_LOG_D("Checking ro.debuggable property");
    if (likely(get_android_prop(prop, props) > 0))
    {
        if (!strcmp(props, "1"))
        {
            FUADXSHELL_LOG_D("Debuggable property is set to 1");
            return (void *)(intptr_t)(-DEBUG_JDWP_ALLOWED);
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get ro.debuggable property");
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_brk(ATTRIBUTES(unused) void *arg)
{
    void *mem = NULL;
    pthread_t monitorThread;
    sigset_t sigset;
    size_t pagesize = sysconf(_SC_PAGESIZE);
    #if defined(__aarch64__) || defined(__arm__)
        size_t size = pagesize / sizeof(uint32_t);
    #elif defined(__i386__) || defined(__x86_64__)
        size_t size = pagesize / sizeof(uint8_t);
    #else
        #error "Unsupported architecture for breakpoint instruction"
    #endif
    int32_t bkptCounter = 0;
    uint32_t randomBkpt;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTRAP);
    sigaddset(&sigset, SIGILL);
    pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
    mem = sys_mmap(NULL, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (unlikely(mem == MAP_FAILED))
    {
        FUADXSHELL_LOG_E("Error while allocating memory: %s", strerror(errno));
        return (void *)((intptr_t)0);
    }
    for (size_t i = 0; i < size; i++)
    {
        #if defined(__aarch64__)
            ((uint32_t *)mem)[i] = 0xD503201F;
        #elif defined(__arm__)
            ((uint32_t *)mem)[i] = 0xE1A00000;
        #elif defined(__i386__) || defined(__x86_64__)
            ((uint8_t *)mem)[i] = 0x90;
        #else
            #error "Unsupported architecture for NOP instruction"
        #endif
    }
    randomBkpt = arc4random_uniform(10) + 1;
    FUADXSHELL_LOG_D("Random breakpoint quantity: %u", randomBkpt);
    while (bkptCounter < randomBkpt)
    {
        size_t idx = arc4random_uniform(size - 1);
        #if defined(__aarch64__)
            if (((uint32_t *)mem)[idx] == 0xD503201F)
                ((uint32_t *)mem)[idx] = 0xD4200000;
            else
                continue;
            FUADXSHELL_LOG_D("Breakpoint instruction set at: %zu - %p", idx, &((uint32_t *)mem)[idx]);
        #elif defined(__arm__)
            if (((uint32_t *)mem)[idx] == 0xE1A00000)
                ((uint32_t *)mem)[idx] = 0xE1200070;
            else
                continue;
            FUADXSHELL_LOG_D("Breakpoint instruction set at: %zu - %p", idx, &((uint32_t *)mem)[idx]);
        #elif defined(__i386__) || defined(__x86_64__)
            if (((uint8_t *)mem)[idx] == 0x90)
                ((uint8_t *)mem)[idx] = 0xCC; /* INT3 */
            else
                continue;
            FUADXSHELL_LOG_D("Breakpoint instruction set at: %zu - %p", idx, &((uint8_t *)mem)[idx]);
        #else
            #error "Unsupported architecture for breakpoint instruction"
        #endif
        bkptCounter++;
    }
    if (set_handlers() != 0)
    {
        sys_munmap(mem, pagesize);
        return (void *)((intptr_t)0);
    }
    #if defined(__aarch64__)
        ((uint32_t *)mem)[size - 1] = 0xD65F03C0; /* RET */
    #elif defined(__i386__) || defined(__x86_64__)
        ((uint8_t *)mem)[size - 1] = 0xC3; /* RET */
    #endif
    /* USAR: process handle -p true -s false SIGTRAP */
    __builtin___clear_cache((char*)mem, (char*)mem + pagesize);
    /* Run the monitor after setting the handlers and clear cache */
    if (sys_pipe(pipefd) == -1)
    {
        FUADXSHELL_LOG_E("Error while creating pipe: %s", strerror(errno));
        sys_munmap(mem, pagesize);
        return (void *)(intptr_t)(-1);
    }
    if (pthread_create(&monitorThread, NULL, (void *(*)(void *))monitor_signal_handler, mem) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread: %s", strerror(errno));
        sys_munmap(mem, pagesize);
        return (void *)(intptr_t)(-1);
    }
    /* TODO: Make this only R-X and switch from signal handler by using self-pipe */
    ((void(*)())mem)();
    if (unlikely(trapCtr == 0) || (unlikely(trapCtr > 0) && unlikely(trapCtr < bkptCounter)))
    {
        FUADXSHELL_LOG_D("Brk instruction was hit %d times which is less than expected. So, it's likely that the process is being debugged", trapCtr);
        sys_munmap(mem, pagesize);
        return (void *)(intptr_t)(-DEBUG_BRKT_HIT);
    }
    sys_munmap(mem, pagesize);
    FUADXSHELL_LOG_D("Brk instruction was not hit by a debugger");
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
int detect_debug(void)
{
    char bufferEvent[512] = { 0 };
    void *resultTmpPtraceTraceme = NULL;
    void *resultTmpDebugProperty = NULL;
    void *resultTmpRunRandomDebug = NULL;
    intptr_t resultPtraceTraceme;
    intptr_t resultDebugProperty;
    intptr_t resultRunRandomDebug;
    pthread_t threadPtraceTraceme;
    pthread_t threadDebugProperty;
    pthread_t threadRunRandomDebug;
    sigset_t sigset;

    /* TODO: Add handler loop for an interval of X seconds to check for ptrace and debug property */

    /* Block SIGTRAP and SIGILL */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTRAP);
    sigaddset(&sigset, SIGILL);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    if (pthread_create(&threadDebugProperty, NULL, (void *(*)(void *))check_debug_property, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread: %s", strerror(errno));
        return 0;
    }
    if (pthread_create(&threadRunRandomDebug, NULL, (void *(*)(void *))check_brk, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread. Deferring to debug property: %s", strerror(errno));
        pthread_join(threadDebugProperty, (void **)&resultTmpDebugProperty);
        return ((intptr_t)resultTmpDebugProperty) > 0 ? -EPTRACED : 0;
    }
    pthread_join(threadDebugProperty, (void **)&resultTmpDebugProperty);
    pthread_join(threadRunRandomDebug, (void **)&resultTmpRunRandomDebug);
    FUADXSHELL_LOG_D("Debug property result: %p - %p", resultTmpDebugProperty, resultTmpRunRandomDebug);
    resultDebugProperty = (intptr_t)resultTmpDebugProperty;
    resultRunRandomDebug = (intptr_t)resultTmpRunRandomDebug;
    if (pthread_create(&threadPtraceTraceme, NULL, (void *(*)(void *))check_ptrace_traceme, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread. Deferring to both debug property and check brk: %s", strerror(errno));
        if (resultDebugProperty || resultRunRandomDebug)
        {
            FUADXSHELL_LOG_D("Suspicious activity detected: debug_property: %" PRIdPTR ", run_random_debug: %" PRIdPTR "",
                             resultDebugProperty, resultRunRandomDebug);
            set_heuristic(bufferEvent, sizeof(bufferEvent), "debug_property: %" PRIdPTR ", run_random_debug: %" PRIdPTR "",
                          resultDebugProperty, resultRunRandomDebug);
            log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferEvent, "Found some suspicious activity while checking for active debugging: %d", -EPTRACED);
            return -EPTRACED;
        }
    }
    pthread_join(threadPtraceTraceme, (void **)&resultTmpPtraceTraceme);
    resultPtraceTraceme = (intptr_t)resultTmpPtraceTraceme;
    FUADXSHELL_LOG_D("Result: ptrace_traceme: %p - %" PRIdPTR ", debug_property: %p - %" PRIdPTR ", run_random_debug: %p - %" PRIdPTR "",
                     resultTmpPtraceTraceme, resultPtraceTraceme, resultTmpDebugProperty, resultDebugProperty, resultTmpRunRandomDebug, resultRunRandomDebug);
    if (resultDebugProperty || resultRunRandomDebug)
    {
        FUADXSHELL_LOG_D("Suspicious activity detected: ptrace_traceme: %" PRIdPTR ", debug_property: %" PRIdPTR ", run_random_debug: %" PRIdPTR "",
                         resultPtraceTraceme, resultDebugProperty, resultRunRandomDebug);

        set_heuristic(bufferEvent, sizeof(bufferEvent), "ptrace_traceme: %" PRIdPTR ", debug_property: %" PRIdPTR ", run_random_debug: %" PRIdPTR "",
                      resultPtraceTraceme, resultDebugProperty, resultRunRandomDebug);
        log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferEvent, "Found some suspicious activity while checking for active debugging: %d", -EPTRACED);
        return -EPTRACED;
    }
    FUADXSHELL_LOG_D("No suspicious activity detected");
    return 0;
}

ATTRIBUTES(always_inline, used)
static inline bool check_port(int port, int ms)
{
    const char *localhost = "127.0.0.1";
    int socket;
    int flags;
    int err;
    struct sockaddr_in address;
    struct timeval tv;
    socklen_t length;
    fd_set wfds;

    socket = sys_socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(socket < 0))
    {
        FUADXSHELL_LOG_E("Error while creating socket: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating socket: %s", strerror(errno));
        return false;
    }
    flags = sys_fcntl(socket, F_GETFL, 0);
    sys_fcntl(socket, F_SETFL, flags | O_NONBLOCK);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, localhost, &address.sin_addr);
    if (connect(socket, (struct sockaddr *)&address, sizeof(address)) == 0)
    {
        FUADXSHELL_LOG_D("Port %d is open on %s", port, localhost);
        log_msg(LOG_LEVEL_INFO, NULL, NULL, "Port %d is open on %s", port, localhost);
        sys_fcntl(socket, F_SETFL, flags);
        sys_close(socket);
        return true; /* Port is open */
    }
    else if (errno != EINPROGRESS)
    {
        FUADXSHELL_LOG_E("Error while connecting to port %d: %s", port, strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while connecting to port %d: %s", port, strerror(errno));
        sys_close(socket);
        return false; /* Port is closed or error occurred */
    }
    FD_ZERO(&wfds);
    FD_SET(socket, &wfds);
    tv.tv_sec = ms / 1000; /* Convert milliseconds to seconds */
    tv.tv_usec = (ms % 1000) * 1000; /* Convert milliseconds to microseconds */
    if (select(socket + 1, NULL, &wfds, NULL, &tv) > 0 && FD_ISSET(socket, &wfds))
    {
        length = sizeof(err);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &err, &length) == 0 && err == 0)
        {
            sys_fcntl(socket, F_SETFL, flags); /* Restore original flags */
            FUADXSHELL_LOG_D("Port %d is open on %s", port, localhost);
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Port %d is open on %s", port, localhost);
            sys_close(socket);
            return true; /* Port is open */
        }
    }
    FUADXSHELL_LOG_D("Port %d is closed on %s", port, localhost);
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Port %d is closed on %s", port, localhost);
    sys_close(socket);
    return false; /* Port is closed */
}

/** ATTRIBUTES(always_inline, used)
static inline void *check_traceme(ATTRIBUTES(unused) void *arg)
{
    return (void *)(intptr_t)(0);
    pid_t tracerTid = *(pid_t *)arg;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellPtrace\0", 0, 0, 0);
    if (sys_ptrace(PTRACE_TRACEME, tracerTid, 0, 0) < 0)
    {
        FUADXSHELL_LOG_D("Ptrace was found. Unable to attach: %s", strerror(errno));
        return (void *)(intptr_t)(-DEBUG_PTRACE_TRACEME_ACTIVE);
    }
    if (sys_ptrace(PTRACE_DETACH, tracerTid, 0, 0) < 0)
    {
        FUADXSHELL_LOG_E("Error while detaching from PTRACE_TRACEME (1): %s with pid: %d", strerror(errno), getpid());
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while detaching from PTRACE_TRACEME: %s", strerror(errno));
    }
    /* Write down the detection of ptrace
    return (void *)(intptr_t)(0);
} */

ATTRIBUTES(always_inline, used)
static inline void *check_jdwp(ATTRIBUTES(unused) void *arg)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    const char comm[] = "/proc/self/task/%s/comm";
    const char task[] = "/proc/self/task";
    char bufferLog[512] = { 0 };
    char buffer[512] = { 0 };
    char taskCommPath[512] = { 0 };
    int bytesRead;
    int bytesWritten;
    int fd;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellJdwp\0", 0, 0, 0);
    dir = opendir(task);
    if (unlikely(!dir))
    {
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening directory %s: %s", task, strerror(errno));
        FUADXSHELL_LOG_E("Error while opening directory %s: %s", task, strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when directory is not accessible */
    }
    while ((entry = readdir(dir)))
    {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        {
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Pointing to self or parent. Nothing to do: %s", entry->d_name);
            FUADXSHELL_LOG_D("Pointing to self or parent. Nothing to do");
            continue;
        }
        bytesWritten = snprintf(taskCommPath, sizeof(taskCommPath), comm, entry->d_name);
        if (bytesWritten < 0 && (size_t)bytesWritten > sizeof(taskCommPath))
        {
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while formatting path: %s", strerror(errno));
            FUADXSHELL_LOG_E("Error while formatting path: %s", strerror(errno));
            continue;
        }
        fd = sys_openat(AT_FDCWD, taskCommPath, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0)
        {
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening file %s: %s", taskCommPath, strerror(errno));
            FUADXSHELL_LOG_E("Error while opening file %s: %s", taskCommPath, strerror(errno));
            continue;
        }
        bytesRead = readline(fd, buffer, sizeof(buffer));
        if (bytesRead < 0)
        {
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while reading file %s: %s", taskCommPath, strerror(bytesRead)); /* TODO: Validar cuando ocurran errores custom */
            FUADXSHELL_LOG_E("Error while reading file %s: %s", taskCommPath, strerror(bytesRead));
            sys_close(fd);
            continue;
        }
        if (strstr(buffer, "jdwp"))
        {
            set_heuristic(bufferLog, sizeof(bufferLog), "check_jdwp found potential communication with java debugger: %s", buffer);
            log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "JDWP detected in %s", taskCommPath);
            FUADXSHELL_LOG_D("JDWP detected in %s: %s", taskCommPath, buffer);
            sys_close(fd);
            closedir(dir);
            memset(bufferLog, 0, sizeof(bufferLog));
            memset(buffer, 0, sizeof(buffer));
            memset(taskCommPath, 0, sizeof(taskCommPath));
            return (void *)(intptr_t)(-DEBUG_JDWP_ALLOWED);
        }
        sys_close(fd);
        memset(buffer, 0, sizeof(buffer));
        memset(taskCommPath, 0, sizeof(taskCommPath));
    }
    /* If we reach here, it means no JDWP was found */
    closedir(dir);
    FUADXSHELL_LOG_D("No JDWP detected in any task");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "No JDWP detected in any task");
    return (void *)(intptr_t)(0); /* Defaulting when no JDWP is found */
}

ATTRIBUTES(always_inline, used)
static inline void *check_jdwp_so(ATTRIBUTES(unused) void *arg)
{
    map_entry_t *entries = NULL;
    size_t entriesCount = 0;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellJdwpSo\0", 0, 0, 0);
    if (parse_maps(getpid(), &entries, &entriesCount))
    {
        FUADXSHELL_LOG_E("Error while parsing maps for JDWP shared object: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while parsing maps for JDWP shared object");
        return (void *)(intptr_t)(0); /* Defaulting when maps cannot be parsed */
    }
    for (size_t i = 0; i < entriesCount; i++)
    {
        if (!entries[i].pathname || entries[i].pathname[0] == '\0')
        {
            FUADXSHELL_LOG_D("Skipping entry with no pathname");
            continue; /* Skip entries with no pathname */
        }
        if (strstr(entries[i].pathname, "jdwp"))
        {
            FUADXSHELL_LOG_D("JDWP shared object detected: %s", entries[i].pathname);
            log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, entries[i].pathname, "JDWP shared object detected: %s", entries[i].pathname);
            release_parsed_maps(entries, entriesCount);
            return (void *)(intptr_t)(-DEBUG_JDWP_LIB);
        }
    }
    FUADXSHELL_LOG_D("No JDWP shared object detected in maps");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "No JDWP shared object detected in maps");
    release_parsed_maps(entries, entriesCount);
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(always_inline, used)
static inline void *check_tracepid(ATTRIBUTES(unused) void *arg)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char *ptrTokenConvert = NULL;
    char *tokenReturn = NULL;
    char bufferLog[512] = { 0 };
    char buffer[512] = { 0 };
    int bytesWritten;
    ATTRIBUTES(cleanup(raii_fd)) int fdSelftStatus;
    ATTRIBUTES(cleanup(raii_fd)) int fdTaskStatus;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellTPid\0", 0, 0, 0);
    fdSelftStatus = sys_openat(AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    if (fdSelftStatus < 0)
    {
        FUADXSHELL_LOG_E("Error while opening /proc/self/status: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening /proc/self/status: %s", strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when file is not accessible */
    }
    while (readline(fdSelftStatus, buffer, sizeof(buffer)) > 0)
    {
        if (strstr(buffer, "TracerPid"))
        {
            strtok_r(buffer, ":", &tokenReturn);
            if (strtol(tokenReturn, NULL, 10) != 0)
            {
                FUADXSHELL_LOG_D("TracerPid is not zero, indicating process is being traced");
                set_heuristic(bufferLog, sizeof(bufferLog), "check_tracepid found TracerPid: %d", strtol(tokenReturn, NULL, 10));
                log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "TracerPid is not zero. Process is traced");
                memset(buffer, 0, sizeof(buffer));
                memset(bufferLog, 0, sizeof(bufferLog));
                return (void *)(intptr_t)(-DEBUG_TRACER_PID);
            }
            else
            {
                FUADXSHELL_LOG_D("TracerPid is zero, indicating no active tracing");
                log_msg(LOG_LEVEL_INFO, NULL, NULL, "TracerPid is zero. Process is not being traced");
                memset(buffer, 0, sizeof(buffer));
                ptrTokenConvert = NULL; /* Reset pointer for next use */
            }
        }
    }
    sys_close(fdSelftStatus);
    FUADXSHELL_LOG_D("No TracerPid found in /proc/self/status");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "No TracerPid found in /proc/self/status");
    if (android_get_device_api_level() >= 24)
    {
        dir = opendir("/proc/self/task");
        if (!dir)
        {
            FUADXSHELL_LOG_E("Error while opening /proc/self/task: %s", strerror(errno));
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening /proc/self/task: %s", strerror(errno));
            return (void *)(intptr_t)(0); /* Defaulting when directory is not accessible */
        }
        (void) memset(buffer, 0, sizeof(buffer));
        while ((entry = readdir(dir)) != NULL)
        {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            {
                log_msg(LOG_LEVEL_INFO, NULL, NULL, "Pointing to self or parent. Nothing to do: %s", entry->d_name);
                FUADXSHELL_LOG_D("Pointing to self or parent. Nothing to do");
                continue;
            }
            bytesWritten = snprintf(buffer, sizeof(buffer), "/proc/self/task/%s/status", entry->d_name);
            if (bytesWritten < 0)
            {
                FUADXSHELL_LOG_E("Error while formatting path: %s", strerror(errno));
                log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while formatting path: %s", strerror(errno));
                continue;
            }
            fdTaskStatus = sys_openat(AT_FDCWD, buffer, O_RDONLY | O_CLOEXEC, 0);
            if (fdTaskStatus < 0)
            {
                FUADXSHELL_LOG_E("Error while opening %s: %s", buffer, strerror(errno));
                log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening %s: %s", buffer, strerror(errno));
                continue;
            }
            FUADXSHELL_LOG_D("Checking task status for %s", buffer);
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Checking task status for %s", buffer);
            (void) memset(buffer, 0, sizeof(buffer));
            while (readline(fdTaskStatus, buffer, sizeof(buffer)) > 0)
            {
                if (strstr(buffer, "TracerPid"))
                {
                    strtok_r(buffer, ":", &tokenReturn);
                    if (strtol(tokenReturn, NULL, 10) != 0)
                    {
                        FUADXSHELL_LOG_D("TracerPid is not zero in task (%s) %s, indicating process is being traced", "/proc/self/task/tid/status", entry->d_name);
                        set_heuristic(bufferLog, sizeof(bufferLog), "check_tracepid found TracerPid in task %s: %d", entry->d_name, strtol(tokenReturn, NULL, 10));
                        log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "TracerPid is not zero in task %s. Process is traced", entry->d_name);
                        memset(buffer, 0, sizeof(buffer));
                        memset(bufferLog, 0, sizeof(bufferLog));
                        sys_close(fdTaskStatus);
                        closedir(dir);
                        return (void *)(intptr_t)(-DEBUG_TRACER_PID);
                    }
                    else
                    {
                        FUADXSHELL_LOG_D("TracerPid is zero in task %s, indicating no active tracing", entry->d_name);
                        log_msg(LOG_LEVEL_INFO, NULL, NULL, "TracerPid is zero in task %s. Process is not being traced", entry->d_name);
                        memset(buffer, 0, sizeof(buffer));
                        ptrTokenConvert = NULL; /* Reset pointer for next use */
                        continue; /* Continue to check other tasks */
                    }
                }
            }
            sys_close(fdTaskStatus);
        }
    }
    FUADXSHELL_LOG_D("No TracerPid found in any task");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "No TracerPid found in any task");
    closedir(dir);
    return (void *)(intptr_t)(0); /* Defaulting when no TracerPid is found */
}

ATTRIBUTES(always_inline, used)
static inline void *check_trace_stop(ATTRIBUTES(unused) void *arg)
{
    FILE *file = NULL;
    char buffer[512] = { 0 };
    char bufferLog[512] = { 0 };
    int bytesRead;
    int bytesWritten;
    pid_t pid;
    pid_t pidNoUse;
    uint8_t state;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellTStop\0", 0, 0, 0);
    bytesWritten = snprintf(buffer, sizeof(buffer), "/proc/%d/task/%d/stat", getpid(), getpid());
    if (bytesWritten < 0)
    {
        FUADXSHELL_LOG_E("Error while formatting path: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while formatting path: %s", strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when path is not accessible */
    }
    file = fopen(buffer, "r");
    if (unlikely(!file))
    {
        FUADXSHELL_LOG_E("Error while opening file %s: %s", buffer, strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening file %s: %s", buffer, strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when file is not accessible */
    }
    (void) memset(buffer, 0, sizeof(buffer));
    bytesRead = fscanf(file, "%d (%255[^)]) %c %d %d", &pid, buffer, &state, &pidNoUse, &pidNoUse);
    if (bytesRead != EOF && bytesRead > 0)
    {
        if (state == 't' || state == 'T')
        {
            FUADXSHELL_LOG_D("Process is in stopped state (trace stop): %s with PID: %d", buffer, pid);
            set_heuristic(bufferLog, sizeof(bufferLog), "check_trace_stop found process in stopped state: %s with PID: %d", buffer, pid);
            log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "Process is in stopped state (trace stop)");
            fclose(file);
            file = NULL;
            memset(buffer, 0, sizeof(buffer));
            memset(bufferLog, 0, sizeof(bufferLog));
            return (void *)(intptr_t)(-DEBUG_TRACE_STOP);
        }
    }
    fclose(file);
    file = NULL;
    FUADXSHELL_LOG_D("Process is not in stopped state (trace stop)");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Process is not in stopped state (trace stop)");
    memset(buffer, 0, sizeof(buffer));
    return (void *)(intptr_t)(0); /* Defaulting when process is not in stopped state */
}

ATTRIBUTES(always_inline, used)
static inline void *check_ptrace_stop(ATTRIBUTES(unused) void *arg)
{
    char buffer[512] = { 0 };
    char bufferLog[512] = { 0 };
    ATTRIBUTES(cleanup(raii_fd)) int fd;
    int bytesWritten;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellWchan\0", 0, 0, 0);
    bytesWritten = snprintf(buffer, sizeof(buffer), "/proc/%d/task/%d/wchan", getpid(), getpid());
    if (bytesWritten < 0)
    {
        FUADXSHELL_LOG_E("Error while formatting path: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while formatting path: %s", strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when path is not accessible */
    }
    fd = sys_openat(AT_FDCWD, buffer, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
    {
        FUADXSHELL_LOG_E("Error while opening file %s: %s", buffer, strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while opening file %s: %s", buffer, strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when file is not accessible */
    }
    (void) memset(buffer, 0, sizeof(buffer));
    if (readline(fd, buffer, sizeof(buffer)) < 0)
    {
        FUADXSHELL_LOG_E("Error while reading file %s: %s", buffer, strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while reading file %s: %s", buffer, strerror(errno));
        return (void *)(intptr_t)(0); /* Defaulting when read fails */
    }
    if (strstr(buffer, "ptrace_stop"))
    {
        FUADXSHELL_LOG_D("Process is in ptrace stop state: %s", buffer);
        set_heuristic(bufferLog, sizeof(bufferLog), "check_ptrace_stop found process in ptrace_stop state: %s", buffer);
        log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "Process is in ptrace_stop state");
        memset(buffer, 0, sizeof(buffer));
        memset(bufferLog, 0, sizeof(bufferLog));
        return (void *)(intptr_t)(-DEBUG_TRACE_EVENT_WCHAN);
    }
    FUADXSHELL_LOG_D("Process is not in ptrace stop state");
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Process is not in ptrace stop state");
    memset(buffer, 0, sizeof(buffer));
    return (void *)(intptr_t)(0); /* Defaulting when process is not in ptrace stop state */
}

ATTRIBUTES(always_inline, used)
static inline void *check_ida(ATTRIBUTES(unused) void *arg)
{
    char bufferLog[512] = { 0 };

    for (int i = 23940; i <= 23960; i++)
    {
        if (check_port(i, 200))
        {
            FUADXSHELL_LOG_D("IDA Pro detected on port %d", i);
            set_heuristic(bufferLog, sizeof(bufferLog), "check_ida found IDA Pro on port %d", i);
            log_msg(LOG_LEVEL_ERROR, LOG_EVENT_DEBUG, bufferLog, "IDA Pro detected");
            return (void *)(intptr_t)(-DEBUG_IDA_SOCKET);
        }
        FUADXSHELL_LOG_D("No IDA Pro detected on port %d", i);
        log_msg(LOG_LEVEL_INFO, NULL, NULL, "No IDA Pro detected on port %d", i);
    }
    return (void *)(intptr_t)(0);
}

/* Run just once. Just a precondition check to avoid initial tracing */
ATTRIBUTES(always_inline, used)
int check_precon(void)
{
    ATTRIBUTES(unused) intptr_t preconPtraceTraceme; /* Precondition for PTRACE_TRACEME */
    intptr_t preconTracerPid;
    intptr_t preconJdwpAllowed;
    intptr_t preconJdwpLib; /* Precondition for JDWP library found in maps */
    intptr_t preconTracedStatus;
    intptr_t preconTraceStopWchan;
    intptr_t preconIdaTracing;
    ATTRIBUTES(unused) pthread_t threadPtraceTraceme; /* Thread for PTRACE_TRACEME */
    pthread_t threadTracerPid;
    pthread_t threadJdwpAllowed;
    pthread_t threadJdwpLib; /* Thread for JDWP library check */
    pthread_t threadTracedStatus;
    pthread_t threadTraceStopWchan;
    pthread_t threadIdaTracing;

    FUADXSHELL_LOG_D("Checking preconditions for debugging detection");
    if (pthread_create(&threadTracerPid, NULL, (void *(*)(void *))check_tracepid, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for tracer pid: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for tracer pid: %s", strerror(errno));
        return (intptr_t)(void *)(-1);
    }
    if (pthread_create(&threadJdwpAllowed, NULL, (void *(*)(void *))check_jdwp, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for JDWP check: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for JDWP check: %s", strerror(errno));
        pthread_join(threadTracerPid, (void **)&preconTracerPid);
        return ((intptr_t)preconTracerPid) < 0 ? -EPTRACED : 0;
    }
    if (pthread_create(&threadJdwpLib, NULL, (void *(*)(void *))check_jdwp_so, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for JDWP library check: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for JDWP library check: %s", strerror(errno));
        pthread_join(threadTracerPid, (void **)&preconTracerPid);
        pthread_join(threadJdwpAllowed, (void **)&preconJdwpAllowed);
        return ((intptr_t)preconTracerPid || (intptr_t)preconJdwpAllowed) > 0 ? -EPTRACED : 0;
    }
    if (pthread_create(&threadTracedStatus, NULL, (void *(*)(void *)) check_trace_stop, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for traced status: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for traced status: %s", strerror(errno));
        pthread_join(threadTracerPid, (void **)&preconTracerPid);
        pthread_join(threadJdwpLib, (void **)&preconJdwpLib);
        pthread_join(threadJdwpAllowed, (void **)&preconJdwpAllowed);
        return ((intptr_t)preconTracerPid || (intptr_t)preconJdwpAllowed) > 0 ? -EPTRACED : 0;
    }
    if (pthread_create(&threadTraceStopWchan, NULL, (void *(*)(void *)) check_ptrace_stop, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for trace stop wchan: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for trace stop wchan: %s", strerror(errno));
        pthread_join(threadTracerPid, (void **)&preconTracerPid);
        pthread_join(threadJdwpAllowed, (void **)&preconJdwpAllowed);
        pthread_join(threadJdwpLib, (void **)&preconJdwpLib);
        pthread_join(threadTracedStatus, (void **)&preconTracedStatus);
        return ((intptr_t)preconTracerPid || (intptr_t)preconJdwpAllowed
            || (intptr_t)preconTracedStatus) > 0 ? -EPTRACED : 0;
    }
    if (pthread_create(&threadIdaTracing, NULL, (void *(*)(void *))check_ida, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for IDA tracing: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating thread for IDA tracing: %s", strerror(errno));
        pthread_join(threadTracerPid, (void **)&preconTracerPid);
        pthread_join(threadJdwpAllowed, (void **)&preconJdwpAllowed);
        pthread_join(threadJdwpLib, (void **)&preconJdwpLib);
        pthread_join(threadTracedStatus, (void **)&preconTracedStatus);
        pthread_join(threadTraceStopWchan, (void **)&preconTraceStopWchan);
        return ((intptr_t)preconTracerPid || (intptr_t)preconJdwpAllowed
            || (intptr_t)preconTracedStatus || (intptr_t)preconTraceStopWchan) > 0 ? -EPTRACED : 0;
    }
    pthread_join(threadTracerPid, (void **)&preconTracerPid);
    pthread_join(threadJdwpAllowed, (void **)&preconJdwpAllowed);
    pthread_join(threadJdwpLib, (void **)&preconJdwpLib);
    pthread_join(threadTracedStatus, (void **)&preconTracedStatus);
    pthread_join(threadTraceStopWchan, (void **)&preconTraceStopWchan);
    pthread_join(threadIdaTracing, (void **)&preconIdaTracing);
    FUADXSHELL_LOG_D("Preconditions check results: tracer_pid: %" PRIdPTR ", "
                     "jdwp_allowed: %" PRIdPTR ", jdwp_library: %" PRIdPTR ", traced_status: %" PRIdPTR ", trace_stop_wchan: %" PRIdPTR ", ida_tracing: %" PRIdPTR "",
                     preconTracerPid,
                     preconJdwpAllowed,
                     preconJdwpLib,
                     preconTracedStatus,
                     preconTraceStopWchan,
                     preconIdaTracing);
    log_msg(LOG_LEVEL_INFO, NULL, NULL, "Preconditions check results: "
                                        "tracer_pid: %" PRIdPTR ", jdwp_allowed: %" PRIdPTR ", jdwp_library: %" PRIdPTR ", traced_status: %" PRIdPTR ", "
                                        "trace_stop_wchan: %" PRIdPTR ", ida_tracing: %" PRIdPTR "",
                     preconTracerPid,
                     preconJdwpAllowed,
                     preconJdwpLib,
                     preconTracedStatus,
                     preconTraceStopWchan,
                     preconIdaTracing);
    return ((intptr_t)preconTracerPid || (intptr_t)preconJdwpAllowed || (intptr_t)preconJdwpLib
        || (intptr_t)preconTracedStatus || (intptr_t)preconTraceStopWchan
        || (intptr_t)preconIdaTracing) > 0 ? -EPTRACED : 0;
}