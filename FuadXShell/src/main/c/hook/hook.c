#include <hook.h>

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline ssize_t read_line(int fd, char *buffer, size_t size)
{
    ssize_t i = 0;
    char c;
    ssize_t bytesRead;

    while (i < (int)size - 1)
    {
        bytesRead = sys_read(fd, &c, 1);
        if (bytesRead == 1)
        {
            buffer[i++] = c;
            if (c == '\n')
                break;
        }
        else if (bytesRead == 0)
            break;
        else
            return -1;
    }
    buffer[i] = '\0';
    return i;
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline int traverse_file(const char *filename, const char needles[][64])
{
    FILE *fp = NULL;
    char buffer[512] = { 0 };

    fp = fopen(filename, "r");
    if (!fp)
    {
        FUADXSHELL_LOG_E("Error while opening file: %s", strerror(errno));
        return -EACCES;
    }
    while (fgets(buffer, sizeof(buffer), fp))
    {
        for (const char (*iterator)[64] = needles; (*iterator)[0] != '\0'; iterator++)
        {
            if (strstr(buffer, (*iterator)))
            {
                fclose(fp);
                memset(buffer, 0, sizeof(buffer));
                FUADXSHELL_LOG_D("Either Frida or a Hook was detected");
                return -1;
            }
        }
    }
    FUADXSHELL_LOG_D("No detection. It went through");
    fclose(fp);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline int traverse_injected_directories(const char needles[][64])
{
    ATTRIBUTES(section(".rodata_ext")) static const char selfFd[] = "/proc/self/fd";
    ATTRIBUTES(section(".rodata_ext")) static const char selfTask[] = "/proc/self/task";
    ATTRIBUTES(section(".rodata_ext")) static const char fdFormat[] = "/proc/self/fd/%s";
    ATTRIBUTES(section(".rodata_ext")) static const char selfTaskFormat[] = "/proc/self/task/%s/status";
    DIR *dirLinjector = NULL;
    DIR *dirThreads = NULL;
    struct dirent *entryLinjector = NULL;
    struct dirent *entryThreads = NULL;
    struct stat stat;
    char buffer[512] = { 0 };
    char path[512] = { 0 };
    int fd = -1;

    dirLinjector = opendir(selfFd);
    dirThreads = opendir(selfTask);
    if (!dirLinjector || !dirThreads)
    {
        FUADXSHELL_LOG_E("Error while opening directory: %s", strerror(errno));
        return -EACCES;
    }
    /* First case */
    while ((entryLinjector = readdir(dirLinjector)) != NULL)
    {
        snprintf(path, sizeof(path), fdFormat, entryLinjector->d_name);
        if (lstat(path, &stat) == -1)
        {
            FUADXSHELL_LOG_E("Error while lstat'ing: %s", strerror(errno));
            continue;
        }
        if ((stat.st_mode & S_IFMT) == S_IFLNK)
        {
            readlinkat(AT_FDCWD, path, buffer, sizeof(buffer));
            if (strstr(buffer, needles[0]))
            {
                closedir(dirLinjector);
                memset(buffer, 0, sizeof(buffer));
                memset(path, 0, sizeof(path));
                FUADXSHELL_LOG_D("Frida detected");
                return -1;
            }
        }
    }
    closedir(dirLinjector);
    memset(buffer, 0, sizeof(buffer));
    memset(path, 0, sizeof(path));
    /* Second case */
    while ((entryThreads = readdir(dirThreads)) != NULL)
    {
        if (!strcmp(entryThreads->d_name, ".") || !strcmp(entryThreads->d_name, ".."))
        {
            FUADXSHELL_LOG_D("Pointing to self or parent. Nothing to do");
            continue;
        }
        snprintf(path, sizeof(path), selfTaskFormat, entryThreads->d_name);
        fd = sys_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd > 0)
        {
            (void)read_line(fd, buffer, sizeof(buffer));
            if (strstr(buffer, needles[1]) || strstr(buffer, needles[2]))
            {
                sys_close(fd);
                closedir(dirThreads);
                memset(buffer, 0, sizeof(buffer));
                memset(path, 0, sizeof(path));
                FUADXSHELL_LOG_D("Frida detected");
                return -1;
            }
            FUADXSHELL_LOG_D("No detection. It went through: %s", buffer);
        }
        else
        {
            FUADXSHELL_LOG_E("Error while opening file: %s", strerror(errno));
            continue;
        }
    }
    closedir(dirThreads);
    memset(buffer, 0, sizeof(buffer));
    memset(path, 0, sizeof(path));
    return 0;
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline int traverse_agent_port(const char needles[][64], const int needlesPort[])
{
    ATTRIBUTES(section(".rodata_ext")) static const char procNetTcp[] = "/proc/net/tcp";
    ATTRIBUTES(section(".rodata_ext")) static const char localhost[] = "127.0.0.1";
    FILE *fp = NULL;
    char buffer[512] = { 0 };
    struct sockaddr_in server_addr = { 0 };
    int sock = -1;

    if (android_get_device_api_level() < 29)
    {
        fp = fopen(procNetTcp, "r");
        if (!fp)
        {
            FUADXSHELL_LOG_E("Error while opening file: %s", strerror(errno));
            return -EACCES;
        }
        while (fgets(buffer, sizeof(buffer), fp))
        {
            for (const char (*iterator)[64] = needles; (*iterator)[0] != '\0'; iterator++)
            {
                if (strstr(buffer, (*iterator)))
                {
                    fclose(fp);
                    memset(buffer, 0, sizeof(buffer));
                    FUADXSHELL_LOG_D("Frida detected");
                    return -1;
                }
            }
        }
        fclose(fp);
        memset(buffer, 0, sizeof(buffer));
        return 0;
    }
    else
    {
        if (needlesPort[0] == 0)
        {
            FUADXSHELL_LOG_E("No ports have been provided");
            return -EPERM;
        }
        for (const int *iterator = needlesPort; (*iterator) != 0; iterator++)
        {
            sock = sys_socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                FUADXSHELL_LOG_E("Error while creating socket: %s", strerror(errno));
                return -EACCES;
            }
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(*iterator);
            server_addr.sin_addr.s_addr = inet_addr(localhost);
            if (!connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)))
            {
                close(sock);
                FUADXSHELL_LOG_D("Frida detected");
                return -1;
            }
            close(sock);
            FUADXSHELL_LOG_D("No detection. It went through. Checked: %d", (*iterator));
        }
        return 0;
    }
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *detect_frida(ATTRIBUTES(unused) void *arg)
{
    /* FIX THIS */
    ATTRIBUTES(section(".rodata_ext"), used) static const char maps[] = "/proc/self/maps";
    ATTRIBUTES(section(".rodata_ext"), used) static const char needlesMemfd[][64] = { "memfd:frida", "\0" };
    ATTRIBUTES(section(".rodata_ext"), used) static const char needlesFridaAgents[][64] = { "frida-agent", "frida-server", "frida-gadget", "\0" };
    ATTRIBUTES(section(".rodata_ext"), used) static const char needlesInjects[][64] = { "injector", "gum-js-loop", "gmain", "\0" };
    ATTRIBUTES(section(".rodata_ext"), used) static const char needlesFridaNet[][64] = { "0100007F:6982", "\0'" };
    ATTRIBUTES(section(".rodata_ext"), used) static const int needlesFridaPorts[] = { 27042, 27043, 0 };

    /* Look for frida files or injects */
    if (traverse_file(maps, needlesMemfd) == -1)
        return (void *)(intptr_t)-ERROR_FRIDA_MEMFD;
    if (traverse_file(maps, needlesFridaAgents) == -1)
        return (void *)(intptr_t)-ERROR_FRIDA_AGENT;
    if (traverse_injected_directories(needlesInjects) == -1)
        return (void *)(intptr_t)-ERROR_FRIDA_INJECTS;
    /* Look for frida active port */
    if (traverse_agent_port(needlesFridaNet, needlesFridaPorts) == -1)
        return (void *)(intptr_t)-ERROR_FRIDA_NET;
    return 0;
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *get_app_ctx(JNIEnv *env)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char jniStrings[][64] =
    {
        "android/app/ActivityThread",
        "currentActivityThread",
        "()Landroid/app/ActivityThread;",
        "android/content/Context",
        "getSystemContext",
        "()Landroid/content/Context;"
    };
    void *activityThreadClass = NULL;
    void *contextClass = NULL;
    void *currentActivityThreadMethodId = NULL;
    void *getSystemContextMethodId = NULL;
    void *activityThreadObject = NULL;
    void *contextObject = NULL;

    if (!env)
    {
        FUADXSHELL_LOG_E("JNI environment is NULL, can't perform JNI calls");
        return NULL;
    }
    activityThreadClass = getJNIClass(env, jniStrings[0]);
    if (!activityThreadClass)
    {
        FUADXSHELL_LOG_E("ActivityThread class not found");
        return NULL;
    }
    currentActivityThreadMethodId = getJNIStaticMethodID(env, activityThreadClass,
                                                         jniStrings[1],
                                                         jniStrings[2]);
    if (!currentActivityThreadMethodId)
    {
        FUADXSHELL_LOG_E("currentActivityThread method not found");
        return NULL;
    }
    activityThreadObject = getJNIObject(env, activityThreadClass, currentActivityThreadMethodId);
    if (!activityThreadObject)
    {
        FUADXSHELL_LOG_E("ActivityThread object not found");
        return NULL;
    }
    contextClass = getJNIClass(env, jniStrings[3]);
    if (!contextClass)
    {
        FUADXSHELL_LOG_E("Context class not found");
        return NULL;
    }
    getSystemContextMethodId = getJNIMethodID(env, activityThreadClass, jniStrings[4],
                                              jniStrings[5]);
    if (!getSystemContextMethodId)
    {
        FUADXSHELL_LOG_E("getSystemContext method ID not found");
        return NULL;
    }
    contextObject = getJNIObject(env, activityThreadObject, getSystemContextMethodId);
    if (!contextObject)
    {
        FUADXSHELL_LOG_E("Context object not found");
        return NULL;
    }
    return contextObject;
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_app_installed(void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char jniStrings[][64] =
    {
        "getPackageManager",
        "()Landroid/content/pm/PackageManager;",
        "getInstalledPackages",
        "(I)Ljava/util/List;",
        "size",
        "()I",
        "get",
        "(I)Ljava/lang/Object;",
        "android/content/pm/PackageInfo",
        "packageName",
        "Ljava/lang/String;",
    };
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    void *listClass = NULL;
    void *packageInfoClass = NULL;
    void *packageManagerClass = NULL;
    void *contextClass = NULL;
    void *packageNameFieldId = NULL;
    void *getPackageManagerMethodId = NULL;
    void *getInstalledPackagesMethodId = NULL;
    void *sizeMethodId = NULL;
    void *getMethodId = NULL;
    void *packageManagerObject = NULL;
    void *packageInfoObject = NULL;
    void *contextObject = NULL;
    void *installedPackagesListObject = NULL;
    void *packageNameObject = NULL;
    const char *packageNameStr = NULL;
    /* TODO: FIX THIS */const char *xposedAppsList[] =
    {
        "de.robv.android.xposed.installer",
        "io.va.edxposed",
        "org.meowcat.edxposed.manager",
        "com.topjohnwu.magisk",
        "com.soft.apk008v",
        "com.soft.controllers",
        "biz.bokhorst.xprivacy"
    };
    int32_t size;

    vm = (JavaVM *)arg;
    if (!vm)
    {
        FUADXSHELL_LOG_E("JavaVM is NULL, can't perform JNI calls");
        /* -ENOJVM */
        return (void *)(intptr_t)(0);
    }
    (*vm)->AttachCurrentThread(vm, &env, NULL);
    if (!env)
    {
        FUADXSHELL_LOG_E("JNI environment is NULL, can't perform JNI calls");
        /* -ENOJNIENV */
        return (void *)(intptr_t)(0);
    }
    /* Check if Xposed apps are installed */
    contextObject = get_app_ctx(env);
    if (!contextObject)
    {
        FUADXSHELL_LOG_E("Failed to get application context");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOCONTEXT */
        return (void *)(intptr_t)(0);
    }
    contextClass = (*env)->GetObjectClass(env, contextObject);
    getPackageManagerMethodId = getJNIMethodID(env, contextClass, jniStrings[0],
                                                  jniStrings[1]);
    if (!getPackageManagerMethodId)
    {
        FUADXSHELL_LOG_E("getPackageManager method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    packageManagerObject = getJNIObject(env, contextObject, getPackageManagerMethodId);
    if (!packageManagerObject)
    {
        FUADXSHELL_LOG_E("PackageManager object not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    packageManagerClass = (*env)->GetObjectClass(env, packageManagerObject);
    getInstalledPackagesMethodId = getJNIMethodID(env, packageManagerClass,
                                                  jniStrings[2],
                                                  jniStrings[3]);
    if (!getInstalledPackagesMethodId)
    {
        FUADXSHELL_LOG_E("getInstalledPackages method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    installedPackagesListObject = (*env)->CallObjectMethod(env, packageManagerObject,
                                                               getInstalledPackagesMethodId, 0);
    if (!installedPackagesListObject)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        FUADXSHELL_LOG_E("Exception while getting installed packages list");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    listClass = (*env)->GetObjectClass(env, installedPackagesListObject);
    sizeMethodId = getJNIMethodID(env, listClass, jniStrings[4], jniStrings[5]);
    if (!sizeMethodId)
    {
        FUADXSHELL_LOG_E("size method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    size = (*env)->CallIntMethod(env, installedPackagesListObject, sizeMethodId);
    getMethodId = getJNIMethodID(env, listClass, jniStrings[6], jniStrings[7]);
    if (!getMethodId)
    {
        FUADXSHELL_LOG_E("get method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    packageInfoClass = getJNIClass(env, jniStrings[8]);
    if (!packageInfoClass)
    {
        FUADXSHELL_LOG_E("PackageInfo class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    packageNameFieldId = getJNIFieldID(env, packageInfoClass, jniStrings[9], jniStrings[10]);
    if (!packageNameFieldId)
    {
        FUADXSHELL_LOG_E("packageName field ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIFIELD */
        return (void *)(intptr_t)(0);
    }
    for (int i = 0; i < size; i++)
    {
        packageInfoObject = (*env)->CallObjectMethod(env, installedPackagesListObject, getMethodId, i);
        if (!packageInfoObject)
        {
            if ((*env)->ExceptionCheck(env))
            {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
            }
            FUADXSHELL_LOG_E("Exception while getting package info object");
            (*vm)->DetachCurrentThread(vm);
            /* -ENOJNIOBJECT */
            return (void *)(intptr_t)(0);
        }
        packageNameObject = getJNIField(env, packageInfoObject, packageNameFieldId);
        if (!packageNameObject)
        {
            FUADXSHELL_LOG_E("packageName object not found");
            (*vm)->DetachCurrentThread(vm);
            /* -ENOJNIOBJECT */
            return (void *)(intptr_t)(0);
        }
        packageNameStr = (*env)->GetStringUTFChars(env, packageNameObject, NULL);
        if (!packageNameStr)
        {
            FUADXSHELL_LOG_W("Failed to get package name string");
            continue;
        }
        FUADXSHELL_LOG_D("Checking package: %s", packageNameStr);
        for (int j = 0; (size_t)j < sizeof(xposedAppsList) / sizeof(xposedAppsList[0]); j++)
        {
            if (!strcmp(packageNameStr, xposedAppsList[j]))
            {
                FUADXSHELL_LOG_D("Xposed app detected: %s", packageNameStr);
                (*env)->ReleaseStringUTFChars(env, packageNameObject, packageNameStr);
                (*vm)->DetachCurrentThread(vm);
                return (void *)(intptr_t)(-ERROR_XPOSED_APP_INSTALLED); /* Xposed app detected */
            }
        }
        (*env)->ReleaseStringUTFChars(env, packageNameObject, packageNameStr);
        (*env)->DeleteLocalRef(env, packageNameObject);
        (*env)->DeleteLocalRef(env, packageInfoObject);
    }
    if ((*vm)->DetachCurrentThread(vm) != JNI_OK)
    {
        FUADXSHELL_LOG_E("Error while detaching current thread from JavaVM");
        /* -ENOJNIDTCH */
        return (void *)(intptr_t)(0);
    }
    return (void *)(intptr_t)(0); /* No Xposed apps detected */
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_test_classes(void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char jniStrings[][64] =
    {
        "java/lang/Class",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        "de.robv.android.xposed.XposedHelpers",
        "java/lang/ClassLoader",
        "getSystemClassLoader",
        "()Ljava/lang/ClassLoader;",
        "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;"
    };
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    void *classClass = NULL;
    void *classLoaderClass = NULL;
    void *xposedClass = NULL;
    void *forNameMethodId = NULL;
    void *getSystemClassLoaderMethodId = NULL;
    void *loadClassMethodId = NULL;
    void *classNameStringObject = NULL;
    void *classLoaderObject = NULL;

    vm = (JavaVM *)arg;
    if (!vm)
    {
        FUADXSHELL_LOG_E("JavaVM is NULL, can't perform JNI calls");
        /* -ENOJVM */
        return (void *)(intptr_t)(0);
    }
    (*vm)->AttachCurrentThread(vm, &env, NULL);
    if (!env)
    {
        FUADXSHELL_LOG_E("JNI environment is NULL, can't perform JNI calls");
        /* -ENOJNIENV */
        return (void *)(intptr_t)(0);
    }
    /* Check for test classes */
    classClass = getJNIClass(env, jniStrings[0]);
    if (!classClass)
    {
        FUADXSHELL_LOG_E("Class class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    forNameMethodId = getJNIStaticMethodID(env, classClass, jniStrings[1], jniStrings[2]);
    if (!forNameMethodId)
    {
        FUADXSHELL_LOG_E("forName method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    classNameStringObject = (*env)->NewStringUTF(env, jniStrings[3]);
    if (!classNameStringObject)
    {
        FUADXSHELL_LOG_E("Failed to create class name string object");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    /* Testing Class.forName */
    xposedClass = (*env)->CallStaticObjectMethod(env, classClass, forNameMethodId, classNameStringObject);
    if (!xposedClass)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        FUADXSHELL_LOG_E("Exception while checking for XposedHelpers class");
        (*vm)->DetachCurrentThread(vm);
        return (void *)(intptr_t)(0);
    }
    /* Testing from ClassLoader */
    classLoaderClass = getJNIClass(env, jniStrings[4]);
    if (!classLoaderClass)
    {
        FUADXSHELL_LOG_E("ClassLoader class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    getSystemClassLoaderMethodId = getJNIStaticMethodID(env, classLoaderClass, jniStrings[5], jniStrings[6]);
    if (!getSystemClassLoaderMethodId)
    {
        FUADXSHELL_LOG_E("getSystemClassLoader method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    classLoaderObject = (*env)->CallStaticObjectMethod(env, classLoaderClass, getSystemClassLoaderMethodId);
    if (!classLoaderObject)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        FUADXSHELL_LOG_E("Exception while getting system class loader");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    loadClassMethodId = getJNIMethodID(env, classLoaderClass, jniStrings[7], jniStrings[8]);
    if (!loadClassMethodId)
    {
        FUADXSHELL_LOG_E("loadClass method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    xposedClass = (*env)->CallObjectMethod(env, classLoaderObject, loadClassMethodId, classNameStringObject);
    if (!xposedClass)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        FUADXSHELL_LOG_E("Exception while loading XposedHelpers class");
        (*env)->DeleteLocalRef(env, classNameStringObject);
        (*vm)->DetachCurrentThread(vm);
        return (void *)(intptr_t)(0); /* No Xposed test classes detected */
    }
    FUADXSHELL_LOG_D("XposedHelpers class found, indicating Xposed is present");
    (*env)->DeleteLocalRef(env, classNameStringObject);
    (*env)->DeleteLocalRef(env, xposedClass);
    return (void *)(intptr_t)(-ERROR_XPOSED_TEST_CLASSES); /* Xposed test classes detected */
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_exception_trace(void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char needle[] = "de.robv.android.xposed.XposedBridge";
    ATTRIBUTES(section(".rodata_ext"), used) static const char jniStrings[][64] =
    {
        "java/lang/Exception",
        "<init>",
        "()V",
        "getStackTrace",
        "()[Ljava/lang/StackTraceElement;",
        "java/lang/StackTraceElement",
        "getClassName",
        "()Ljava/lang/String;"
    };
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    void *exceptionClass = NULL;
    void *stackTraceElementClass = NULL;
    void *exceptionCtorMethodId = NULL;
    void *getStackTraceMethodId = NULL;
    void *getClassName = NULL;
    void *exceptionObject = NULL;
    void *stackTraceElementObject = NULL;
    void *classNameObject = NULL;
    void *tmpObject = NULL;
    const char *classNameStr = NULL;
    size_t size;

    vm = (JavaVM *)arg;
    if (!vm)
    {
        FUADXSHELL_LOG_E("JavaVM is NULL, can't perform JNI calls");
        /* -ENOJVM */
        return (void *)(intptr_t)(0);
    }
    (*vm)->AttachCurrentThread(vm, &env, NULL);
    if (!env)
    {
        FUADXSHELL_LOG_E("JNI environment is NULL, can't perform JNI calls");
        /* -ENOJNIENV */
        return (void *)(intptr_t)(0);
    }
    /* Check for exception trace */
    exceptionClass = getJNIClass(env, jniStrings[0]);
    if (!exceptionClass)
    {
        FUADXSHELL_LOG_E("Exception class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    exceptionCtorMethodId = getJNIMethodID(env, exceptionClass, jniStrings[1], jniStrings[2]);
    if (!exceptionCtorMethodId)
    {
        FUADXSHELL_LOG_E("Exception constructor method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    exceptionObject = (*env)->NewObject(env, exceptionClass, exceptionCtorMethodId);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_E("Exception while creating Exception object");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    getStackTraceMethodId = getJNIMethodID(env, exceptionClass, jniStrings[3], jniStrings[4]);
    if (!getStackTraceMethodId)
    {
        FUADXSHELL_LOG_E("getStackTrace method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    stackTraceElementClass = getJNIClass(env, jniStrings[5]);
    if (!stackTraceElementClass)
    {
        FUADXSHELL_LOG_E("StackTraceElement class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    stackTraceElementObject = getJNIObject(env, exceptionObject, getStackTraceMethodId);
    if (!stackTraceElementObject)
    {
        FUADXSHELL_LOG_E("Exception while getting stack trace elements");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    getClassName = getJNIMethodID(env, stackTraceElementClass, jniStrings[6], jniStrings[7]);
    if (!getClassName)
    {
        FUADXSHELL_LOG_E("getClassName method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    size = (*env)->GetArrayLength(env, stackTraceElementObject);
    for (int i = 0; i < (int)size; i++)
    {
        tmpObject = (*env)->GetObjectArrayElement(env, stackTraceElementObject, i);
        if (!tmpObject)
        {
            if ((*env)->ExceptionCheck(env))
            {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                FUADXSHELL_LOG_E("Exception while getting stack trace element at index %d", i);
                (*vm)->DetachCurrentThread(vm);
                /* -ENOJNIOBJECT */
                return (void *)(intptr_t)(0);
            }
            FUADXSHELL_LOG_W("Stack trace element at index %d is null", i);
            continue;
        }
        classNameObject = getJNIObject(env, tmpObject, getClassName);
        if (!classNameObject)
        {
            FUADXSHELL_LOG_E("Exception while getting class name from stack trace element at index %d", i);
            (*vm)->DetachCurrentThread(vm);
            /* -ENOJNIOBJECT */
            return (void *)(intptr_t)(0);
        }
        classNameStr = (*env)->GetStringUTFChars(env, classNameObject, NULL);
        if (!classNameStr)
        {
            FUADXSHELL_LOG_W("Failed to get class name string at index %d", i);
            (*env)->DeleteLocalRef(env, tmpObject);
            continue;
        }
        if (!strcmp(classNameStr, needle))
        {
            FUADXSHELL_LOG_D("Xposed detected in stack trace: %s", classNameStr);
            (*env)->ReleaseStringUTFChars(env, classNameObject, classNameStr);
            (*env)->DeleteLocalRef(env, tmpObject);
            (*vm)->DetachCurrentThread(vm);
            return (void *)(intptr_t)(-ERROR_XPOSED_EXCEPTION_TRACE); /* Xposed exception trace detected */
        }
    }
    FUADXSHELL_LOG_D("No Xposed detected in exception trace");
    (*vm)->DetachCurrentThread(vm);
    return (void *)(intptr_t)(0); /* No Xposed exception trace detected */
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_property(void *arg)
{
    JavaVM *vm = NULL;
    JNIEnv *env = NULL;
    void *systemClass = NULL;
    void *getPropertyMethodId = NULL;
    void *propertyStringObject = NULL;
    ATTRIBUTES(section(".rodata_ext"), used) static const char property[] = "vxp";
    ATTRIBUTES(section(".rodata_ext"), used) static const char jniStrings[][64] =
    {
        "java/lang/System",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;"
    };
    vm = (JavaVM *)arg;
    if (!vm)
    {
        FUADXSHELL_LOG_E("JavaVM is NULL, can't perform JNI calls");
        /* -ENOJVM */
        return (void *)(intptr_t)(0);
    }
    (*vm)->AttachCurrentThread(vm, &env, NULL);
    if (!env)
    {
        FUADXSHELL_LOG_E("JNI environment is NULL, can't perform JNI calls");
        /* -ENOJNIENV */
        return (void *)(intptr_t)(0);
    }
    /* Check for Xposed property */
    systemClass = getJNIClass(env, jniStrings[0]);
    if (!systemClass)
    {
        FUADXSHELL_LOG_E("System class not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNICLASS */
        return (void *)(intptr_t)(0);
    }
    getPropertyMethodId = getJNIStaticMethodID(env, systemClass, jniStrings[1], jniStrings[2]);
    if (!getPropertyMethodId)
    {
        FUADXSHELL_LOG_E("getProperty method ID not found");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIMTHD */
        return (void *)(intptr_t)(0);
    }
    propertyStringObject = (*env)->NewStringUTF(env, property);
    if (!propertyStringObject)
    {
        FUADXSHELL_LOG_E("Failed to create property string object");
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    void *propertyValueObject = (*env)->CallStaticObjectMethod(env, systemClass, getPropertyMethodId, propertyStringObject);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        FUADXSHELL_LOG_E("Exception while getting property value");
        (*env)->DeleteLocalRef(env, propertyStringObject);
        (*vm)->DetachCurrentThread(vm);
        /* -ENOJNIOBJECT */
        return (void *)(intptr_t)(0);
    }
    (*vm)->DetachCurrentThread(vm);
    return propertyValueObject != NULL ? (void *)(intptr_t)(-ERROR_XPOSED_PROPERTY) : (void *)(intptr_t)(0); /* Xposed property detected */
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_environ(ATTRIBUTES(unused) void *arg)
{
    FILE *file = NULL;
    const char *environContent = NULL;
    const char *valueRetrieved = NULL;
    char *token = NULL;
    size_t tokenLength = 0;
    ATTRIBUTES(section(".rodata_ext"), used) static const char classpath[] = "CLASSPATH";
    ATTRIBUTES(section(".rodata_ext"), used) static const char classpathEq[] = "CLASSPATH=";
    ATTRIBUTES(section(".rodata_ext"), used) static const char xposedBridge[] = "XposedBridge";
    ATTRIBUTES(section(".rodata_ext"), used) static const char environPath[] = "/proc/self/environ";

    environContent = getenv(classpath);
    if (environContent)
    {
        FUADXSHELL_LOG_D("CLASSPATH environment variable found: %s", environContent);
        if (strstr(environContent, xposedBridge))
        {
            FUADXSHELL_LOG_D("XposedBridge detected in CLASSPATH");
            return (void *)(intptr_t)(-ERROR_XPOSED_ENVIRON);
        }
    }
    else
        FUADXSHELL_LOG_D("CLASSPATH environment variable not found. Checking manually");
    file = fopen(environPath, "r");
    if (!file)
    {
        FUADXSHELL_LOG_E("Error while opening /proc/self/environ: %s", strerror(errno));
        /* -EACCES */
        return (void *)(intptr_t)(0);
    }
    while (getdelim(&token, &tokenLength, '\0', file) != -1)
    {
        FUADXSHELL_LOG_D("Checking environment variable: %s", token);
        if (!strncmp(token, classpathEq, 10))
        {
            valueRetrieved = token + 10; /* Skip "CLASSPATH=" */
            FUADXSHELL_LOG_D("CLASSPATH value retrieved: %s", valueRetrieved);
            if (strstr(valueRetrieved, xposedBridge))
            {
                FUADXSHELL_LOG_D("XposedBridge detected in CLASSPATH");
                free(token);
                token = NULL;
                fclose(file);
                file = NULL;
                return (void *)(intptr_t)(-ERROR_XPOSED_ENVIRON);
            }
        }
    }
    return (void *)(intptr_t)(0); /* No XposedBridge detected in CLASSPATH */
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *check_maps_hook(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char maps[] = "/proc/self/maps";
    ATTRIBUTES(section(".rodata_ext"), used) static const char needles[][64] = { "XposedBridge", "\0" };

    if (traverse_file(maps, needles) == -1)
    {
        FUADXSHELL_LOG_D("XposedBridge detected in /proc/self/maps");
        return (void *)(intptr_t)(-ERROR_XPOSED_MAPS);
    }
    FUADXSHELL_LOG_D("No XposedBridge detected in /proc/self/maps");
    return (void *)(intptr_t)(0); /* No XposedBridge detected */
}

ATTRIBUTES(always_inline, used)
static inline void *detect_xposed(void *arg)
{
    JavaVM *vm = NULL;
    pthread_t checkAppsInstalledThreadId;
    pthread_t checkTestClassesThreadId;
    pthread_t checkExceptionTraceThreadId;
    pthread_t checkPropertyThreadId;
    pthread_t checkEnvironThreadId;
    pthread_t checkMapsHookThreadId;
    intptr_t resultCheckAppsInstalled = -1;
    intptr_t resultCheckTestClasses = -1;
    intptr_t resultCheckExceptionTrace = -1;
    intptr_t resultCheckProperty = -1;
    intptr_t resultCheckEnviron = -1;
    intptr_t resultCheckMapsHook = -1;

    vm = (JavaVM *)arg;
    if (!vm)
    {
        FUADXSHELL_LOG_E("JavaVM is NULL to be shared across threads");
        return (void *)(intptr_t)(-1); /* -ENOJVM */
    }
    if (pthread_create(&checkAppsInstalledThreadId, NULL, (void *(*)(void *))check_app_installed, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking installed apps: %s", strerror(errno));
        return (void *)(intptr_t)(-1);
    }
    if (pthread_create(&checkTestClassesThreadId, NULL, (void *(*)(void *))check_test_classes, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking test classes: %s", strerror(errno));
        pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
        return resultCheckAppsInstalled > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
    }
    if (pthread_create(&checkExceptionTraceThreadId, NULL, (void *(*)(void *))check_exception_trace, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking exception trace: %s", strerror(errno));
        pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
        pthread_join(checkTestClassesThreadId, (void **)&resultCheckTestClasses);
        return (resultCheckAppsInstalled || resultCheckTestClasses) > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
    }
    if (pthread_create(&checkPropertyThreadId, NULL, (void *(*)(void *))check_property, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking property: %s", strerror(errno));
        pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
        pthread_join(checkTestClassesThreadId, (void **)&resultCheckTestClasses);
        pthread_join(checkExceptionTraceThreadId, (void **)&resultCheckExceptionTrace);
        return (resultCheckAppsInstalled || resultCheckTestClasses || resultCheckExceptionTrace)
               > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
    }
    if (pthread_create(&checkEnvironThreadId, NULL, (void *(*)(void *))check_environ, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking environment: %s", strerror(errno));
        pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
        pthread_join(checkTestClassesThreadId, (void **)&resultCheckTestClasses);
        pthread_join(checkExceptionTraceThreadId, (void **)&resultCheckExceptionTrace);
        pthread_join(checkPropertyThreadId, (void **)&resultCheckProperty);
        return (resultCheckAppsInstalled || resultCheckTestClasses || resultCheckExceptionTrace
            || resultCheckProperty) > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
    }
    if (pthread_create(&checkMapsHookThreadId, NULL, (void *(*)(void *))check_maps_hook, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread for checking maps hook: %s", strerror(errno));
        pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
        pthread_join(checkTestClassesThreadId, (void **)&resultCheckTestClasses);
        pthread_join(checkExceptionTraceThreadId, (void **)&resultCheckExceptionTrace);
        pthread_join(checkPropertyThreadId, (void **)&resultCheckProperty);
        pthread_join(checkEnvironThreadId, (void **)&resultCheckEnviron);
        return (resultCheckAppsInstalled || resultCheckTestClasses || resultCheckExceptionTrace
            || resultCheckProperty || resultCheckEnviron) > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
    }
    pthread_join(checkAppsInstalledThreadId, (void **)&resultCheckAppsInstalled);
    pthread_join(checkTestClassesThreadId, (void **)&resultCheckTestClasses);
    pthread_join(checkExceptionTraceThreadId, (void **)&resultCheckExceptionTrace);
    pthread_join(checkPropertyThreadId, (void **)&resultCheckProperty);
    pthread_join(checkEnvironThreadId, (void **)&resultCheckEnviron);
    pthread_join(checkMapsHookThreadId, (void **)&resultCheckMapsHook);
    FUADXSHELL_LOG_D("Results: checkAppsInstalled: %" PRIdPTR ", checkTestClasses: %" PRIdPTR
                     ", checkExceptionTrace: %" PRIdPTR ", checkProperty: %" PRIdPTR
                     ", checkEnviron: %" PRIdPTR ", checkMapsHook: %" PRIdPTR,
                     resultCheckAppsInstalled, resultCheckTestClasses,
                     resultCheckExceptionTrace, resultCheckProperty, resultCheckEnviron, resultCheckMapsHook);
    return (resultCheckAppsInstalled || resultCheckTestClasses || resultCheckExceptionTrace
            || resultCheckProperty || resultCheckEnviron || resultCheckMapsHook) > 0 ? (void *)(intptr_t)(-EXPOSED) : 0;
}

ATTRIBUTES(always_inline, used)
int detect_hook(JavaVM *vm)
{
    pthread_t threadFrida;
    pthread_t threadXposed;
    intptr_t resultFrida = -1;
    intptr_t resultXposed = -1;

    if (pthread_create(&threadFrida, NULL, (void *(*)(void *))detect_frida, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread: %s", strerror(errno));
        return -1;
    }
    if (pthread_create(&threadXposed, NULL, (void *(*)(void *))detect_xposed, vm) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread. Deferring to only Frida: %s", strerror(errno));
        pthread_join(threadFrida, (void **)&resultFrida);
        if (resultFrida < 0)
        {
            FUADXSHELL_LOG_D("Frida was detected, but Xposed was not");
            return -EFRIDA;
        }
        return 0;
    }
    pthread_join(threadFrida, (void **)&resultFrida);
    pthread_join(threadXposed, (void **)&resultXposed);
    if (resultFrida == 0 && resultXposed < 0)
    {
        FUADXSHELL_LOG_D("Xposed was detected, but Frida was not");
        return resultXposed;
    }
    else if (resultFrida < 0 && resultXposed == 0)
    {
        FUADXSHELL_LOG_D("Frida was detected, but Xposed was not");
        return -EFRIDA;
    }
    return resultFrida == 0 && resultXposed == 0 ? 0 : -EHOOK; /* Both not detected or both detected */
}