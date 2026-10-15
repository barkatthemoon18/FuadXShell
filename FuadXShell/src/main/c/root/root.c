#include <root.h>

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_selinux_permissiveness(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char selinuxCmd[] = "getenforce";
    ATTRIBUTES(section(".rodata_ext"), used) static const char permissiveStr[] = "Permissive";
    FILE *pipe = NULL;
    char buffer[256] = { 0 };

    pipe = popen(selinuxCmd, "r");
    if (unlikely(!pipe))
    {
        FUADXSHELL_LOG_E("Error while executing command: %s", selinuxCmd);
        return (void *)(intptr_t)(0);
    }
    if (fgets(buffer, sizeof(buffer), pipe))
    {
        if (strstr(buffer, permissiveStr))
        {
            FUADXSHELL_LOG_D("SELinux is in permissive mode");
            pclose(pipe);
            return (void *)(intptr_t)(-SELINUX_PERMISSIVENESS_ENABLED);
        }
        else
        {
            FUADXSHELL_LOG_D("SELinux is not in permissive mode: %s", buffer);
            pclose(pipe);
            return (void *)(intptr_t)(0); /* SELinux is enforcing */
        }
    }
    FUADXSHELL_LOG_E("Error while reading command output: %s", strerror(errno));
    pclose(pipe);
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_root_packages(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char rootPkgs[][64] =
    {
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char rootPkgsCmd[] = "pm list packages | cut -d':' -f2";
    FILE *pipe = NULL;
    char buffer[256] = { 0 };

    pipe = popen(rootPkgsCmd, "r");
    if (unlikely(!pipe))
    {
        FUADXSHELL_LOG_E("Error while executing command: %s", rootPkgsCmd);
        return (void *)(intptr_t)(0);
    }
    while (fgets(buffer, sizeof(buffer), pipe))
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        for (size_t i = 0; i < sizeof(rootPkgs) / sizeof(rootPkgs[0]); i++)
        {
            if (strstr(buffer, rootPkgs[i]))
            {
                FUADXSHELL_LOG_D("Root package found: %s", rootPkgs[i]);
                pclose(pipe);
                return (void *)(intptr_t)(-ROOT_PKGS_FOUND);
            }
        }
    }
    return (void *)(intptr_t)(0); /* No root packages found */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_root_dangerous_packages(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char dangerousPkgs[][64] =
    {
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.android.vending.billing.InAppBillingService.LUCK",
        "com.chelpus.luckypatcher",
        "com.blackmartalpha",
        "org.blackmart.market",
        "com.allinone.free",
        "com.repodroid.app",
        "org.creeplays.hack",
        "com.baseappfull.fwd",
        "com.zmapp",
        "com.dv.marketmod.installer",
        "org.mobilism.android",
        "com.android.wp.net.log",
        "com.android.camera.update",
        "cc.madkite.freedom",
        "com.solohsu.android.edxp.manager",
        "org.meowcat.edxposed.manager",
        "com.xmodgame",
        "com.cih.game_cih",
        "com.charles.lpoqasert",
        "catch_.me_.if_.you_.can_"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char dangerousPkgsCmd[] = "pm list packages | cut -d':' -f2";
    FILE *pipe = NULL;
    char buffer[256] = { 0 };

    pipe = popen(dangerousPkgsCmd, "r");
    if (unlikely(!pipe))
    {
        FUADXSHELL_LOG_E("Error while executing command: %s", dangerousPkgsCmd);
        return (void *)(intptr_t)(0);
    }
    while (fgets(buffer, sizeof(buffer), pipe))
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        for (size_t i = 0; i < sizeof(dangerousPkgs) / sizeof(dangerousPkgs[0]); i++)
        {
            if (strstr(buffer, dangerousPkgs[i]))
            {
                FUADXSHELL_LOG_D("Root package found: %s", dangerousPkgs[i]);
                pclose(pipe);
                return (void *)(intptr_t)(-ROOT_DANGEROUS_PKGS_FOUND);
            }
        }
    }
    return (void *)(intptr_t)(0); /* No root packages found */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_root_cloaking_packages(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char cloakingPkgs[][64] =
    {
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",
        "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char cloakingPkgsCmd[] = "pm list packages | cut -d':' -f2";
    FILE *pipe = NULL;
    char buffer[256] = { 0 };

    pipe = popen(cloakingPkgsCmd, "r");
    if (unlikely(!pipe))
    {
        FUADXSHELL_LOG_E("Error while executing command: %s", cloakingPkgsCmd);
        return (void *)(intptr_t)(0);
    }
    while (fgets(buffer, sizeof(buffer), pipe))
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        for (size_t i = 0; i < sizeof(cloakingPkgs) / sizeof(cloakingPkgs[0]); i++)
        {
            if (strstr(buffer, cloakingPkgs[i]))
            {
                FUADXSHELL_LOG_D("Root package found: %s", cloakingPkgs[i]);
                pclose(pipe);
                return (void *)(intptr_t)(-ROOT_CLOAKING_PKGS_FOUND);
            }
        }
    }
    return (void *)(intptr_t)(0); /* No root packages found */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_root_su_path(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char suPaths[][64] =
    {
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/bin/su",
        "/system/bin/.ext/su",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/system/xbin/su",
        "/cache/su",
        "/data/su",
        "/dev/su"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char suCmd[] = "which su";
    FILE *pipe = NULL;
    char buffer[256] = { 0 };

    /* Test which su */
    pipe = popen(suCmd, "r");
    if (unlikely(!pipe))
    {
        FUADXSHELL_LOG_E("Error while executing command: %s", suCmd);
        return (void *)(intptr_t)(0);
    }
    if (fgets(buffer, sizeof(buffer), pipe))
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        if (strlen(buffer) > 0)
        {
            FUADXSHELL_LOG_D("Found su at path: %s", buffer);
            pclose(pipe);
            return (void *)(intptr_t)(-ROOT_SU_PATH_FOUND);
        }
    }
    pclose(pipe);
    /* No su found, check common paths */
    for (size_t i = 0; i < sizeof(suPaths) / sizeof(suPaths[0]); i++)
    {
        if (access(suPaths[i], F_OK) == 0)
        {
            FUADXSHELL_LOG_D("Found su at path: %s", suPaths[i]);
            return (void *)(intptr_t)(-ROOT_SU_PATH_FOUND);
        }
    }
    FUADXSHELL_LOG_D("No su found in common paths");
    return (void *)(intptr_t)(0); /* No su found */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void *check_root_path_non_rw(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char nonRwPaths[][64] =
    {
        "/system",
        "/system/bin",
        "/system/sbin",
        "/system/xbin",
        "/vendor/bin",
        "/sbin",
        "/etc",
        "/debug_ramdisk",
        "magisk"
    };
    FILE *file = NULL;
    char buffer[4096] = { 0 };
    char device[128] = { 0 };
    char mountPoint[128] = { 0 };
    char fsType[64] = { 0 };
    char options[256] = { 0 };
    int parsed;

    file = fopen("/proc/self/mounts", "r");
    if (unlikely(!file))
    {
        FUADXSHELL_LOG_E("Error while opening /proc/self/mounts: %s", strerror(errno));
        return (void *)(intptr_t)(0);
    }
    while (fgets(buffer, 4096, file))
    {
        parsed = sscanf(buffer, "%127s %127s %63s %255s", device, mountPoint, fsType, options);
        if (parsed != 4)
            continue;
        for (size_t i = 0; i < sizeof(nonRwPaths) / sizeof(nonRwPaths[0]); i++)
        {
            if (!strcmp(mountPoint, nonRwPaths[i]))
            {
                if (strstr(options, "rw"))
                {
                    FUADXSHELL_LOG_D("Found non-RW path: %s with options: %s", mountPoint, options);
                    fclose(file);
                    return (void *)(intptr_t)(-ROOT_PATH_NON_RW_FOUND);
                }
            }
        }
    }
    fclose(file);
    FUADXSHELL_LOG_D("No non-RW paths found");
    return (void *)(intptr_t)(0); /* No non-RW paths found */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
int detect_root(void)
{
    pthread_t selinuxThread;
    pthread_t rootPkgsThread;
    pthread_t rootDangerousPkgsThread;
    pthread_t rootCloakingPkgsThread;
    pthread_t rootSuPathThread;
    pthread_t rootPathNonRwThread;
    void *resultSelinuxTmp = NULL;
    void *resultRootPkgsTmp = NULL;
    void *resultRootDangerousPkgsTmp = NULL;
    void *resultRootCloakingPkgsTmp = NULL;
    void *resultRootSuPathTmp = NULL;
    void *resultRootPathNonRwTmp = NULL;
    intptr_t resultSelinux;
    intptr_t resultRootPkgs;
    intptr_t resultRootDangerousPkgs;
    intptr_t resultRootCloakingPkgs;
    intptr_t resultRootSuPath;
    intptr_t resultRootPathNonRw;

    if (pthread_create(&selinuxThread, NULL, check_selinux_permissiveness, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating SELinux thread: %s", strerror(errno));
        return -1;
    }
    if (pthread_create(&rootPkgsThread, NULL, check_root_packages, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating root packages thread: %s", strerror(errno));
        pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
        return (intptr_t)resultSelinuxTmp ? -EROOT : 0;
    }
    if (pthread_create(&rootDangerousPkgsThread, NULL, check_root_dangerous_packages, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating root dangerous packages thread: %s", strerror(errno));
        pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
        pthread_join(rootPkgsThread, (void **)&resultRootPkgsTmp);
        return (intptr_t)resultSelinuxTmp || (intptr_t)resultRootPkgsTmp ? -EROOT : 0;
    }
    if (pthread_create(&rootCloakingPkgsThread, NULL, check_root_cloaking_packages, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating root cloaking packages thread: %s", strerror(errno));
        pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
        pthread_join(rootPkgsThread, (void **)&resultRootPkgsTmp);
        pthread_join(rootDangerousPkgsThread, (void **)&resultRootDangerousPkgsTmp);
        return (intptr_t)resultSelinuxTmp || (intptr_t)resultRootPkgsTmp || (intptr_t)resultRootDangerousPkgsTmp ? -EROOT : 0;
    }
    if (pthread_create(&rootSuPathThread, NULL, check_root_su_path, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating root su path thread: %s", strerror(errno));
        pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
        pthread_join(rootPkgsThread, (void **)&resultRootPkgsTmp);
        pthread_join(rootDangerousPkgsThread, (void **)&resultRootDangerousPkgsTmp);
        pthread_join(rootCloakingPkgsThread, (void **)&resultRootCloakingPkgsTmp);
        return (intptr_t)resultSelinuxTmp || (intptr_t)resultRootPkgsTmp || (intptr_t)resultRootDangerousPkgsTmp  || (intptr_t)resultRootCloakingPkgsTmp  ? -EROOT : 0;
    }
    if (pthread_create(&rootPathNonRwThread, NULL, check_root_path_non_rw, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating root path non-rw thread: %s", strerror(errno));
        pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
        pthread_join(rootPkgsThread, (void **)&resultRootPkgsTmp);
        pthread_join(rootDangerousPkgsThread, (void **)&resultRootDangerousPkgsTmp);
        pthread_join(rootCloakingPkgsThread, (void **)&resultRootCloakingPkgsTmp);
        pthread_join(rootSuPathThread, (void **)&resultRootSuPathTmp);
        return (intptr_t)resultSelinuxTmp || (intptr_t)resultRootPkgsTmp || (intptr_t)resultRootDangerousPkgsTmp || (intptr_t)resultRootCloakingPkgsTmp || (intptr_t)resultRootSuPathTmp ? -EROOT : 0;
    }
    pthread_join(selinuxThread, (void **)&resultSelinuxTmp);
    pthread_join(rootPkgsThread, (void **)&resultRootPkgsTmp);
    pthread_join(rootDangerousPkgsThread, (void **)&resultRootDangerousPkgsTmp);
    pthread_join(rootCloakingPkgsThread, (void **)&resultRootCloakingPkgsTmp);
    pthread_join(rootSuPathThread, (void **)&resultRootSuPathTmp);
    pthread_join(rootPathNonRwThread, (void **)&resultRootPathNonRwTmp);
    resultSelinux = (intptr_t)resultSelinuxTmp;
    resultRootPkgs = (intptr_t)resultRootPkgsTmp;
    resultRootDangerousPkgs = (intptr_t)resultRootDangerousPkgsTmp;
    resultRootCloakingPkgs = (intptr_t)resultRootCloakingPkgsTmp;
    resultRootSuPath = (intptr_t)resultRootSuPathTmp;
    resultRootPathNonRw = (intptr_t)resultRootPathNonRwTmp;
    if (resultSelinux || resultRootPkgs || resultRootDangerousPkgs || resultRootCloakingPkgs || resultRootSuPath || resultRootPathNonRw)
    {
        FUADXSHELL_LOG_D("Root detected with results: SELinux: %" PRIdPTR ", Root Packages: %" PRIdPTR ", Dangerous Packages: %" PRIdPTR ", Cloaking Packages: %" PRIdPTR ", SU Path: %" PRIdPTR ", Non-RW Path: %" PRIdPTR,
                         resultSelinux, resultRootPkgs, resultRootDangerousPkgs, resultRootCloakingPkgs, resultRootSuPath, resultRootPathNonRw);
        return -EROOT;
    }
    FUADXSHELL_LOG_D("No root detected with results: SELinux: %" PRIdPTR ", Root Packages: %" PRIdPTR ", Dangerous Packages: %" PRIdPTR ", Cloaking Packages: %" PRIdPTR ", SU Path: %" PRIdPTR ", Non-RW Path: %" PRIdPTR,
                     resultSelinux, resultRootPkgs, resultRootDangerousPkgs, resultRootCloakingPkgs, resultRootSuPath, resultRootPathNonRw);
    return 0;
}


