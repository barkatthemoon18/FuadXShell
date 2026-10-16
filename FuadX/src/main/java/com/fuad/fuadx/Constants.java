package com.fuad.fuadx;

public class Constants {
    /* Integrity Control */
    public static final String PATH_PROC_CMDLINE = "/proc/self/cmdline";
    public static final String ANDROID_DEBUG = "Android Debug";
    public static final String APPLICATION_CONSTANT = "application";
    public static final String DEBUGGABLE_CONSTANT = "debuggable";
    public static final String APK_SIGNATURE = "4D537B4AD37917A22352133B43D381539678957CB66A77D192AAC76FFAD3872B";

    /* Paths Detection */
    public static final String PATH_PROC_MAPS = "/proc/self/maps";
    public static final String PATH_PROC_SELF_FD = "/proc/self/fd";
    public static final String PATH_PROC_SELF_TASK = "/proc/self/task";
    public static final String PATH_PROC_SELF_STATUS = "/proc/self/status";
    public static final String PATH_PROC_SELF_MEM = "/proc/self/mem";
    public static final String PATH_PROC_SELF_PAGEMAP = "/proc/self/pagemap";
    public static final String PATH_PROC_SELF_TASK_STATUS = "/proc/self/task/%s/status";
    public static final String PATH_PROC_SELF_TASK_COMM = "/proc/self/task/%s/comm";
    public static final String PATH_PROC_SELF_TASK_MEM = "/proc/self/task/%s/mem";
    public static final String PATH_PROC_SELF_TASK_PAGEMAP = "/proc/self/task/%s/pagemap";
    public static final String PATH_PROC_SELF_FD_FORMAT = "/proc/self/fd/%s";
    public static final String PATH_PROC_PID_TASK_PID_STAT = "/proc/%d/task/%d/stat";
    public static final String PATH_PROC_PID_TASK_PID_WCHAN = "/proc/%d/task/%d/wchan";

    /* Frida Detection */
    public static final String GUM_JS_LOOP = "gum-js-loop";
    public static final String GMAIN = "gmain";
    public static final String LINJECTOR = "linjector";
    public static final String FRIDA_SERVER = "re.frida.server";
    public static final String FRIDA_AGENT = "frida-agent";
    public static final String FRIDA_GADGET = "frida-gadget";

    /* Debug Detection */
    public static final String JDWP = "JDWP";
    public static final String TRACER_PID = "TracerPid";
    public static final String LIBJDWP = "libjdwp";
    public static final String PTRACE_STOP = "ptrace_stop";

    /* SSL Pinning */
    public static final String PINNING_URL = "https://api.stackexchange.com";

    /* General Purpose */
    public static final String LSOF_PID = "lsof -p %d";
    public static final String LSOF = "lsof";

    /* Logger / Tombstone */
    public static final String TOMBSTONE_DIRECTORY = "fuadx_tombstone";
    public static final String TOMBSTONE_FILE_NAME = "tombstone_";
    public static final String TOMBSTONE_FILE_EXTENSION = ".json";
    public static final String LOG_DIRECTORY = "fuadx_logs";
    public static final String LOG_FILE_NAME = "fuadx_log_";
    public static final String LOG_FILE_EXTENSION = ".log";
    public static final String LOG_DATE_PATTERN = "ddMMyyyy";

    /* Modules */
    public static final String DEFAULT_MODULE_NAME = "FuadX";
    public static final String ROOT_MODULE_NAME = "RootModule";
    public static final String DEBUG_MODULE_NAME = "DebugModule";
    public static final String FRIDA_MODULE_NAME = "FridaModule";
    public static final String SSL_PINNING_MODULE_NAME = "SSLPinningModule";
    public static final String INTEGRITY_CONTROL_MODULE_NAME = "IntegrityControlModule";
}
