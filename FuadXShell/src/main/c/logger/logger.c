#include <logger.h>

typedef struct log_entry_t
{
    struct kernel_timeval timestamp; /* Timestamp of the log entry */
    log_level_t level;
    char message[MAX_LOG_MESSAGE_SIZE]; /* Log message */
    struct
    {
        char idDevice[64]; /* UUID of the device */
        char deviceName[PROP_VALUE_MAX]; /* Device name */
        char deviceModel[PROP_VALUE_MAX]; /* Device model */
        char deviceManufacturer[PROP_VALUE_MAX]; /* Device manufacturer */
        char androidVersion[PROP_VALUE_MAX]; /* Android version */
        char buildId[PROP_VALUE_MAX]; /* Build ID */
        char buildFingerprint[PROP_VALUE_MAX]; /* Build fingerprint */
        char cpuArch[PROP_VALUE_MAX]; /* CPU architecture */
        char kernelVersion[PROP_VALUE_MAX]; /* Kernel version */
        char kernelRelease[PROP_VALUE_MAX]; /* Kernel release */
    } device_data_t;
    struct
    {
        char appName[64]; /* Application name */
        char appVersion[32]; /* Application version */
        char packageName[64]; /* Package name */
    } app_data_t;
    struct
    {
        char eventName[64]; /* Name of the event */
        char eventDescription[512]; /* Description of the event */
    } event_t;
    struct
    {
        char processName[64]; /* Name of the running process via prctl() */
        uid_t userId;
        pid_t parentId; /* Process ID */
        pid_t threadId; /* Thread ID */
    } running_process_t;
} log_entry_t;

static char logPath[512] = { 0 };
static int pipefd[2] = { -1, -1 };
static _Atomic int loggerRunning = 0;
static pthread_t loggerThreadId;
static pthread_mutex_t loggerMutex;

ATTRIBUTES(always_inline, used)
static inline void *logger(ATTRIBUTES(unused) void *arg)
{
    json_object *obj = NULL;
    json_object *processObj = NULL;
    json_object *eventObj = NULL;
    const char *serialized;
    const char *level;
    char timestamp[64] = { 0 };
    struct tm *timeInfo;
    ssize_t bytesRead;
    log_entry_t entry;
    FILE *logFile = NULL;
    struct pollfd pollFd;
    int ret;

    sys_prctl(PR_SET_NAME, (unsigned long)"FuadXShellLogger\0", 0, 0, 0);
    logFile = fopen(logPath, "a");
    if (!logFile)
        FUADXSHELL_LOG_E("Error while opening log file: %s", strerror(errno));
    else
    {
        if (setvbuf(logFile, NULL, _IOLBF, 0) != 0)
        {
            FUADXSHELL_LOG_E("Error while setting line buffering for log file: %s", strerror(errno));
            fclose(logFile);
            logFile = NULL;
        }
    }
    pollFd.fd = pipefd[0];
    pollFd.events = POLLIN;

    while (loggerRunning)
    {
        ret = poll(&pollFd, 1, 1000); /* Wait for up to 1000 ms */
        if (unlikely(ret == -1))
        {
            if (errno == EINTR)
            {
                FUADXSHELL_LOG_W("Poll interrupted. Retry");
                continue; /* Retry on interrupt */
            }
            FUADXSHELL_LOG_E("Error while polling pipe: %s", strerror(errno));
            break; /* Exit on other errors */
        }
        if (likely(ret == 0))
        {
            FUADXSHELL_LOG_D("No data available in pipe, continuing to wait");
            continue; /* No data available, continue waiting */
        }
        if (likely(pollFd.revents & POLLIN))
        {
            bytesRead = sys_read(pipefd[0], &entry, sizeof(log_entry_t));
            if (bytesRead == -1)
            {
                if (errno == EINTR)
                {
                    FUADXSHELL_LOG_W("Read interrupted. Retry");
                    continue; /* Retry on interrupt */
                }
                FUADXSHELL_LOG_E("Error while reading from pipe: %s", strerror(errno));
                break; /* Exit on other errors */
            }
            if (bytesRead == 0)
            {
                FUADXSHELL_LOG_D("Pipe closed, exiting logger thread");
                loggerRunning = 0;
                break; /* Exit if pipe is closed */
            }
            timeInfo = localtime(&entry.timestamp.tv_sec);
            strftime(timestamp, sizeof(timestamp), "%d-%m-%Y %H:%M:%S", timeInfo);
            if (!timeInfo)
            {
                FUADXSHELL_LOG_E("Error while converting timestamp to local time: %s", strerror(errno));
                continue; /* Skip this entry on error */
            }
            switch (entry.level)
            {
                case LOG_LEVEL_DEBUG:
                    level = "DEBUG";
                    break;
                case LOG_LEVEL_INFO:
                    level = "INFO";
                    break;
                case LOG_LEVEL_WARN:
                    level = "WARN";
                    break;
                case LOG_LEVEL_ERROR:
                    level = "ERROR";
                    break;
                case LOG_LEVEL_FATAL:
                    level = "FATAL";
                    break;
                default:
                    level = "UNKNOWN";
                    break;
            }
            if (logFile)
            {
                obj = json_object_new_object();
                processObj = json_object_new_object();
                if (obj)
                {
                    /* Adding default data */
                    json_object_object_add(obj, "timestamp", json_object_new_string(timestamp));
                    json_object_object_add(obj, "level", json_object_new_string(level));
                    json_object_object_add(obj, "message", json_object_new_string(entry.message));
                    /* Setting event data, if exists */
                    if (strlen(entry.event_t.eventName) > 0 && strlen(entry.event_t.eventDescription) > 0)
                    {
                        eventObj = json_object_new_object();
                        json_object_object_add(eventObj, "eventName", json_object_new_string(entry.event_t.eventName));
                        json_object_object_add(eventObj, "eventDescription", json_object_new_string(entry.event_t.eventDescription));
                        json_object_object_add(obj, "event", eventObj);
                    }
                    /* Setting running_process_t */
                    json_object_object_add(processObj, "processName", json_object_new_string(entry.running_process_t.processName));
                    json_object_object_add(processObj, "uid", json_object_new_uint64(entry.running_process_t.userId));
                    json_object_object_add(processObj, "pid", json_object_new_int(entry.running_process_t.parentId));
                    json_object_object_add(processObj, "tid", json_object_new_int(entry.running_process_t.threadId));
                    json_object_object_add(obj, "runningProcess", processObj);
                    collect_data(&entry, obj);
                    serialized = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
                    if (serialized)
                    {
                        fprintf(logFile, "%s\n", serialized);
                        fflush(logFile);
                    }
                    else
                        FUADXSHELL_LOG_E("Error while serializing log entry to JSON");
                    json_object_put(obj); /* Free the JSON object */
                }
                else
                    FUADXSHELL_LOG_E("Error while creating JSON object for log entry");
            }
            else
                FUADXSHELL_LOG_E("Log file is not open, cannot write log entry");
        }
    }
    if (logFile)
    {
        fclose(logFile);
        logFile = NULL;
    }
    FUADXSHELL_LOG_I("Logger thread exiting");
    return 0;
}

ATTRIBUTES(always_inline, used)
static inline void collect_data(log_entry_t *entry, json_object *obj)
{
    /* Device data */
    ATTRIBUTES(unused) char idDevice[64] = { 0 };
    char deviceName[PROP_VALUE_MAX] = { 0 };
    char deviceModel[PROP_VALUE_MAX] = { 0 };
    char deviceManufacturer[PROP_VALUE_MAX] = { 0 };
    char androidVersion[PROP_VALUE_MAX] = { 0 };
    char buildId[PROP_VALUE_MAX] = { 0 };
    char buildFingerprint[PROP_VALUE_MAX] = { 0 };
    char cpuArch[PROP_VALUE_MAX] = { 0 };
    char versionSdk[PROP_VALUE_MAX] = { 0 };
    char kernelVersion[PROP_VALUE_MAX] = { 0 };
    char kernelRelease[PROP_VALUE_MAX] = { 0 };
    /* JSON object for device data */
    json_object *deviceData = json_object_new_object();

    /* Acquiring device data */
    /* deviceName */
    if (get_android_prop(PROP_DEVICE_NAME, deviceName) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.product.device");
        snprintf(deviceName, sizeof(deviceName), "Unknown Device");
    }

    /* deviceModel */
    if (get_android_prop(PROP_DEVICE_MODEL, deviceModel) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.product.model");
        snprintf(deviceModel, sizeof(deviceModel), "Unknown Model");
    }

    /* deviceManufacturer */
    if (get_android_prop(PROP_DEVICE_MANUFACTURER, deviceManufacturer) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.product.manufacturer");
        snprintf(deviceManufacturer, sizeof(deviceManufacturer), "Unknown Manufacturer");
    }

    /* androidVersion */
    if (get_android_prop(PROP_BUILD_VERSION, androidVersion) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.build.version.release");
        snprintf(androidVersion, sizeof(androidVersion), "Unknown Version");
    }

    /* buildId */
    if (get_android_prop(PROP_BUILD_ID, buildId) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.build.id");
        snprintf(buildId, sizeof(buildId), "Unknown Build ID");
    }

    /* buildFingerprint */
    if (get_android_prop(PROP_BUILD_FPRINT, buildFingerprint) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.build.fingerprint");
        snprintf(buildFingerprint, sizeof(buildFingerprint), "Unknown Fingerprint");
    }

    /* CPU Architecture */
    if (get_android_prop(PROP_CPU_ABI, cpuArch) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.product.cpu.abi");
        snprintf(cpuArch, sizeof(cpuArch), "Unknown CPU Arch");
    }

    /* SDK Version */
    if (get_android_prop(PROP_VERSION_SDK, versionSdk) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.build.version.sdk");
        snprintf(versionSdk, sizeof(versionSdk), "Unknown SDK Version");
    }

    /* Kernel Version */
    if (get_android_prop(PROP_KERNEL_VERSION, kernelRelease) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.kernel.version");
        snprintf(kernelRelease, sizeof(kernelRelease), "Unknown Kernel Version");
    }

    /* Kernel Release */
    if (get_android_prop(PROP_KERNEL_RELEASE, kernelVersion) < 0)
    {
        FUADXSHELL_LOG_E("Unable to get property ro.kernel.release");
        snprintf(kernelVersion, sizeof(kernelVersion), "Unknown Kernel Release");
    }

    FUADXSHELL_LOG_D("Device data has been acquired");

    /* Write collected device data to log entry */
    snprintf(entry->device_data_t.deviceName, sizeof(entry->device_data_t.deviceName), "%s", deviceName);
    snprintf(entry->device_data_t.deviceModel, sizeof(entry->device_data_t.deviceModel), "%s", deviceModel);
    snprintf(entry->device_data_t.deviceManufacturer, sizeof(entry->device_data_t.deviceManufacturer), "%s", deviceManufacturer);
    snprintf(entry->device_data_t.androidVersion, sizeof(entry->device_data_t.androidVersion), "%s", androidVersion);
    snprintf(entry->device_data_t.buildId, sizeof(entry->device_data_t.buildId), "%s", buildId);
    snprintf(entry->device_data_t.buildFingerprint, sizeof(entry->device_data_t.buildFingerprint), "%s", buildFingerprint);
    snprintf(entry->device_data_t.cpuArch, sizeof(entry->device_data_t.cpuArch), "%s", cpuArch);
    snprintf(entry->device_data_t.kernelVersion, sizeof(entry->device_data_t.kernelVersion), "%s", kernelVersion);
    snprintf(entry->device_data_t.kernelRelease, sizeof(entry->device_data_t.kernelRelease), "%s", kernelRelease);
    FUADXSHELL_LOG_D("Device data written to log entry");

    /* Create JSON object for device data */
    json_object_object_add(deviceData, "deviceName", json_object_new_string(entry->device_data_t.deviceName));
    json_object_object_add(deviceData, "deviceModel", json_object_new_string(entry->device_data_t.deviceModel));
    json_object_object_add(deviceData, "deviceManufacturer", json_object_new_string(entry->device_data_t.deviceManufacturer));
    json_object_object_add(deviceData, "androidVersion", json_object_new_string(entry->device_data_t.androidVersion));
    json_object_object_add(deviceData, "buildId", json_object_new_string(entry->device_data_t.buildId));
    json_object_object_add(deviceData, "buildFingerprint", json_object_new_string(entry->device_data_t.buildFingerprint));
    json_object_object_add(deviceData, "cpuArch", json_object_new_string(entry->device_data_t.cpuArch));
    json_object_object_add(deviceData, "kernelVersion", json_object_new_string(entry->device_data_t.kernelVersion));
    json_object_object_add(deviceData, "kernelRelease", json_object_new_string(entry->device_data_t.kernelRelease));
    json_object_object_add(obj, "deviceData", deviceData);
}

ATTRIBUTES(always_inline, used)
void set_heuristic(char *buffer, size_t buflen, const char *__restrict__ format, ...)
{
    char heuristic[256] = "Heuristics found: \0";
    va_list ap;
    ssize_t bytesWritten;

    FUADXSHELL_LOG_D("Buffer: %s", buffer);
    FUADXSHELL_LOG_D("Format: %s", format);
    bytesWritten = snprintf(buffer, buflen, "%s", heuristic);
    if (bytesWritten < 0)
    {
        FUADXSHELL_LOG_E("Error while formatting heuristic string: %s", strerror(errno));
        return;
    }
    bytesWritten += snprintf(buffer + bytesWritten, buflen - bytesWritten, "%s", format);
    if (bytesWritten < 0 || (size_t)bytesWritten >= buflen)
    {
        FUADXSHELL_LOG_E("Error while formatting heuristic string: %s", strerror(errno));
        return;
    }
    va_start(ap, format);
    vsnprintf(&buffer[strlen(heuristic)], buflen - strlen(heuristic), format, ap);
    va_end(ap);
    FUADXSHELL_LOG_D("Heuristic set: %s", buffer);
}

ATTRIBUTES(always_inline, used)
int log_msg(log_level_t level, const char *event, const char *eventDescription, const char *__restrict__ format, ...)
{
    ssize_t bytesWritten;
    log_entry_t entry;
    va_list va_args;

    if (unlikely(pipefd[1] == -1) || unlikely(!loggerRunning))
    {
        FUADXSHELL_LOG_E("Logger thread started but pipe is not initialized or logger is not running");
        return -ENOLOGGER;
    }
    entry.level = level;
    /* Process info */
    if (sys_prctl(PR_GET_NAME, (unsigned long)entry.running_process_t.processName, 0, 0, 0) != 0)
    {
        FUADXSHELL_LOG_E("Error while getting process name: %s", strerror(errno));
        snprintf(entry.running_process_t.processName, sizeof(entry.running_process_t.processName), "");
    }
    entry.running_process_t.userId = getuid();
    entry.running_process_t.parentId = getpid();
    entry.running_process_t.threadId = gettid();
    /* Timestamp */
    sys_gettimeofday(&entry.timestamp, NULL);
    /* Setting message */
    va_start(va_args, format);
    vsnprintf(entry.message, sizeof(entry.message), format, va_args);
    va_end(va_args);
    /* Check event and eventDescription */
    if (event && eventDescription)
    {
        snprintf(entry.event_t.eventName, sizeof(entry.event_t.eventName), "%s", event);
        snprintf(entry.event_t.eventDescription, sizeof(entry.event_t.eventDescription), "%s", eventDescription);
    }
    else
    {
        FUADXSHELL_LOG_D("Event or event description is NULL, skipping event data");
        entry.event_t.eventName[0] = '\0';
        entry.event_t.eventDescription[0] = '\0';
    }
    pthread_mutex_lock(&loggerMutex);
    bytesWritten = sys_write(pipefd[1], &entry, sizeof(entry));
    if (bytesWritten < 0)
    {
        FUADXSHELL_LOG_E("Error while writing to pipe: %s", strerror(errno));
        pthread_mutex_unlock(&loggerMutex);
        return -ELOGWRITE;
    }
    else if ((size_t)bytesWritten < sizeof(entry))
    {
        FUADXSHELL_LOG_E("Partial write to pipe, expected %zu bytes, wrote %zd bytes", sizeof(entry), bytesWritten);
        pthread_mutex_unlock(&loggerMutex);
        return -EPRTLWRTLOG;
    }
    else
    {
        FUADXSHELL_LOG_D("Log entry written to pipe: Level: %d, Thread ID: %d, Message: %s",
                         level, entry.running_process_t.threadId, entry.message);
    }
    pthread_mutex_unlock(&loggerMutex);
    return 0;
}

ATTRIBUTES(always_inline, used)
int logger_init(const char *pkgName)
{
    ssize_t bytesWritten;
    time_t rawTime;
    struct tm *timeInfo;
    char dirPath[512] = { 0 };
    char date[64] = { 0 };
    int fd = -1;

    if (unlikely(!pkgName))
    {
        FUADXSHELL_LOG_E("Package name is NULL, cannot initialize logger");
        return -EINVAL;
    }
    time(&rawTime);
    timeInfo = localtime(&rawTime);
    if (strftime(date, sizeof(date), "%d%m%Y", timeInfo) == 0)
    {
        FUADXSHELL_LOG_E("Error while formatting date: %s", strerror(errno));
        return -errno;
    }
    bytesWritten = snprintf(dirPath, sizeof(dirPath), "/data/data/%s/fuadx_logs/", pkgName);
    if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(dirPath))
    {
        FUADXSHELL_LOG_E("Error while formatting directory path: %s", strerror(errno));
        return -errno;
    }
    bytesWritten = snprintf(logPath, sizeof(logPath), "/data/data/%s/fuadx_logs/fuadx_log_%s.log", pkgName, date);
    if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(logPath))
    {
        FUADXSHELL_LOG_E("Error while formatting log path: %s", strerror(errno));
        return -errno;
    }
    if (!access(dirPath, F_OK | W_OK))
        FUADXSHELL_LOG_I("Log directory %s already exists, skipping creation", dirPath);
    else
    {
        if (mkdir(dirPath, 0755) < 0)
        {
            FUADXSHELL_LOG_E("Error while creating log directory %s: %s", dirPath, strerror(errno));
            return -errno;
        }
        FUADXSHELL_LOG_I("Log directory %s created successfully", dirPath);
    }
    if (!access(logPath, F_OK))
        FUADXSHELL_LOG_I("Log file %s already exists, skipping creation", logPath);
    else
    {
        fd = sys_open(logPath, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
        if (fd < 0)
        {
            FUADXSHELL_LOG_E("Error while creating log file %s: %s", logPath, strerror(errno));
            return -errno;
        }
        sys_close(fd);
    }
    if (pipefd[0] != -1)
    {
        FUADXSHELL_LOG_I("Logger already initialized, skipping initialization");
        return 0;
    }
    if (sys_pipe2(pipefd, O_CLOEXEC) == -1)
    {
        FUADXSHELL_LOG_E("Error while creating pipe: %s", strerror(errno));
        return -ENOPIPELOG;
    }
    if (pthread_mutex_init(&loggerMutex, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while initializing mutex: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        pipefd[0] = pipefd[1] = -1;
        return -ENOMTXLOG;
    }
    if (pthread_create(&loggerThreadId, NULL, (void *(*)(void *))logger, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating logger thread: %s", strerror(errno));
        pthread_mutex_destroy(&loggerMutex);
        sys_close(pipefd[0]);
        sys_close(pipefd[1]);
        pipefd[0] = pipefd[1] = -1;
        return -ELOGNTHRD;
    }
    loggerRunning = 1;
    FUADXSHELL_LOG_I("Logger initialized successfully");
    return 0;
}

ATTRIBUTES(always_inline, used)
void logger_shutdown(void)
{
    if (unlikely(!loggerRunning))
    {
        FUADXSHELL_LOG_I("Logger is not running, skipping shutdown");
        return;
    }
    FUADXSHELL_LOG_I("Shutting down logger");
    loggerRunning = 0;
    if (pipefd[1] != -1)
    {
        sys_close(pipefd[1]);
        pipefd[1] = -1;
    }
    if (loggerThreadId != 0)
    {
        pthread_join(loggerThreadId, NULL);
        loggerThreadId = 0;
    }
    if (pipefd[0] != -1)
    {
        sys_close(pipefd[0]);
        pipefd[0] = -1;
    }
    pthread_mutex_destroy(&loggerMutex);
    FUADXSHELL_LOG_I("Logger shutdown complete");
}