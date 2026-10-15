#include "emulator.h"

/* Short definition for internal dual-string struct */
typedef struct dual_emulator_check_t
{
    const char emulatorCheck1[64];
    const char emulatorCheck2[64];
} dual_emulator_check_t;

/* TODO: Add logs for emulator detection */
ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *watch_emulator_advanced_features(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext")) static const char filesToBeAccessed[][64] =
    {
        "/system/bin/androVM-prop",
        "/system/bin/microvirt-prop",
        "/system/lib/libdroid4x.so",
        "/system/bin/windroyed",
        "/system/bin/nox-prop",
        "/system/lib/libnoxspeedup.so",
        "/system/bin/ttVM-prop",
        "/data/.bluestacks.prop",
        "/system/bin/duosconfig",
        "/system/etc/xxzs_prop.sh",
        "/system/etc/mumu-configs/device-prop-configs/mumu.config",
        "/system/priv-app/ldAppStore",
        "vmos.prop",
        "x8.prop",
        "/system/lib/libc_malloc_debug_qemu.so",
        "\0" /* Null-terminate the array */
    };
    ATTRIBUTES(section(".rodata_ext")) static const dual_emulator_check_t dualFilesToBeChecked[] =
    {
        { "/system/bin/ldinit", "/system/bin/ldmountsf" },
        { "/system/app/AntStore", "/system/app/AntLauncher" },
        { "/system/etc/fstab.titan", "/system/etc/init.titan.rc" },
        { "\0", "\0" }
    };

    for (const char (*iterator)[64] = filesToBeAccessed; (*iterator)[0] != '\0'; iterator++)
    {
        if (file_exists((*iterator)))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_FILE_ACCESSED_ADVANCED);
        }
    }
    for (const dual_emulator_check_t *it = dualFilesToBeChecked; it->emulatorCheck1[0] != '\0'; it++)
    {
        if (file_exists(it->emulatorCheck1) && file_exists(it->emulatorCheck2))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_FILE_ACCESSED_ADVANCED_DUAL);
        }
    }
    FUADXSHELL_LOG_D("No emulator detected");
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *watch_emulator_basic_features(void *arg)
{
    ATTRIBUTES(section(".rodata_ext")) static const char devMountsToBeChecked[][64] =
    {
        "/boot/bstmods/vboxguest.ko",
        "/boot/bstmods/vboxsf.ko",
        "/dev/mtp_usb",
        "/dev/qemu_pipe",
        "/dev/socket/baseband_genyd",
        "/dev/socket/genyd",
        "/dev/socket/qemud",
        "/dev/socket/windroyed-audio",
        "/dev/socket/windroyed-camera",
        "/dev/socket/windroyed-gps",
        "/dev/socket/windroyed-sensors",
        "/dev/vboxguest",
        "/dev/vboxpci",
        "/dev/vboxuser",
        "/fstab.goldfish",
        "/fstab.nox",
        "/fstab.ranchu-encrypt",
        "/fstab.ranchu-noencrypt",
        "/fstab.ttVM_x86",
        "/fstab.vbox86",
        "/init.goldfish.rc",
        "/init.magisk.rc",
        "/init.nox.rc",
        "/init.ranchu-encrypt.rc",
        "/init.ranchu-noencrypt.rc",
        "/init.ranchu.rc",
        "/init.ttVM_x86.rc",
        "/init.vbox86.rc",
        "/init.vbox86p.rc",
        "/init.windroye.rc",
        "/init.windroye.sh",
        "/init.x86.rc",
        "/proc/irq/20/vboxguest",
        "/sdcard/Android/data/com.redfinger.gamemanage",
        "/stab.andy",
        "/sys/bus/pci/drivers/vboxguest",
        "/sys/bus/pci/drivers/vboxpci",
        "/sys/bus/platform/drivers/qemu_pipe",
        "/sys/bus/platform/drivers/qemu_pipe/qemu_pipe",
        "/sys/bus/platform/drivers/qemu_trace",
        "/sys/bus/virtio/drivers/itolsvmlgtp",
        "/sys/bus/virtio/drivers/itoolsvmhft",
        "/sys/class/bdi/vboxsf-1",
        "/sys/class/bdi/vboxsf-2",
        "/sys/class/bdi/vboxsf-3",
        "/sys/class/misc/qemu_pipe",
        "/sys/class/misc/vboxguest",
        "/sys/class/misc/vboxuser",
        "/sys/devices/platform/qemu_pipe",
        "/sys/devices/virtual/bdi/vboxsf-1",
        "/sys/devices/virtual/bdi/vboxsf-2",
        "/sys/devices/virtual/bdi/vboxsf-3",
        "/sys/devices/virtual/misc/qemu_pipe",
        "/sys/devices/virtual/misc/vboxguest",
        "/sys/devices/virtual/misc/vboxpci",
        "/sys/devices/virtual/misc/vboxuser",
        "/sys/fs/selinux/booleans/in_qemu",
        "/sys/kernel/debug/bdi/vboxsf-1",
        "/sys/kernel/debug/bdi/vboxsf-2",
        "/sys/kernel/debug/x86",
        "/sys/module/qemu_trace_sysfs",
        "/sys/module/vboxguest",
        "/sys/module/vboxguest/drivers/pci:vboxguest",
        "/sys/module/vboxpcism",
        "/sys/module/vboxsf",
        "/sys/module/vboxvideo",
        "/sys/module/virtio_pt/drivers/virtio:itoolsvmhft",
        "/sys/module/virtio_pt_ie/drivers/virtio:itoolsvmlgtp",
        "/sys/qemu_trace",
        "/system/app/GenymotionLayout",
        "/system/bin/OpenglService",
        "/system/bin/androVM-vbox-sf",
        "/system/bin/droid4x",
        "/system/bin/droid4x-prop",
        "/system/bin/droid4x-vbox-sf",
        "/system/bin/droid4x_setprop",
        "/system/bin/enable_nox",
        "/system/bin/genymotion-vbox-sf",
        "/system/bin/microvirt-prop",
        "/system/bin/microvirt-vbox-sf",
        "/system/bin/microvirt_setprop",
        "/system/bin/microvirtd",
        "/system/bin/mount.vboxsf",
        "/system/bin/nox",
        "/system/bin/nox-prop",
        "/system/bin/nox-vbox-sf",
        "/system/bin/nox_setprop",
        "/system/bin/noxd",
        "/system/bin/noxscreen",
        "/system/bin/noxspeedup",
        "/system/bin/qemu-props",
        "/system/bin/qemud",
        "/system/bin/shellnox",
        "/system/bin/ttVM-prop",
        "/system/bin/windroyed",
        "/system/droid4x",
        "/system/etc/init.droid4x.sh",
        "/system/etc/init.tiantian.sh",
        "/system/lib/egl/libEGL_emulation.so",
        "/system/lib/egl/libEGL_tiantianVM.so",
        "/system/lib/egl/libEGL_windroye.so",
        "/system/lib/egl/libGLESv1_CM_emulation.so",
        "/system/lib/egl/libGLESv1_CM_tiantianVM.so",
        "/system/lib/egl/libGLESv1_CM_windroye.so",
        "/system/lib/egl/libGLESv2_emulation.so",
        "/system/lib/egl/libGLESv2_tiantianVM.so",
        "/system/lib/egl/libGLESv2_windroye.so",
        "/system/lib/hw/audio.primary.vbox86.so",
        "/system/lib/hw/audio.primary.windroye.so",
        "/system/lib/hw/audio.primary.x86.so",
        "/system/lib/hw/autio.primary.nox.so",
        "/system/lib/hw/camera.vbox86.so",
        "/system/lib/hw/camera.windroye.jpeg.so",
        "/system/lib/hw/camera.windroye.so",
        "/system/lib/hw/camera.x86.so",
        "/system/lib/hw/gps.nox.so",
        "/system/lib/hw/gps.vbox86.so",
        "/system/lib/hw/gps.windroye.so",
        "/system/lib/hw/gralloc.nox.so",
        "/system/lib/hw/gralloc.vbox86.so",
        "/system/lib/hw/gralloc.windroye.so",
        "/system/lib/hw/sensors.nox.so",
        "/system/lib/hw/sensors.vbox86.so",
        "/system/lib/hw/sensors.windroye.so",
        "/system/lib/init.nox.sh",
        "/system/lib/libGM_OpenglSystemCommon.so",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/lib/libclcore_x86.bc",
        "/system/lib/libdroid4x.so",
        "/system/lib/libnoxd.so",
        "/system/lib/libnoxspeedup.so",
        "/system/lib/modules/3.10.30-android-x86.hd+",
        "/system/lib/vboxguest.ko",
        "/system/lib/vboxpcism.ko",
        "/system/lib/vboxsf.ko",
        "/system/lib/vboxvideo.ko",
        "/system/lib64/egl/libEGL_emulation.so",
        "/system/lib64/egl/libGLESv1_CM_emulation.so",
        "/system/lib64/egl/libGLESv2_emulation.so",
        "/vendor/lib64/egl/libEGL_emulation.so",
        "/vendor/lib64/egl/libGLESv1_CM_emulation.so",
        "/vendor/lib64/egl/libGLESv2_emulation.so",
        "/vendor/lib64/libandroidemu.so",
        "/system/lib64/hw/gralloc.ranchu.so",
        "/system/lib64/libc_malloc_debug_qemu.so",
        "/system/usr/Keylayout/droid4x_Virtual_Input.kl",
        "/system/usr/idc/Genymotion_Virtual_Input.idc",
        "/system/usr/idc/droid4x_Virtual_Input.idc",
        "/system/usr/idc/nox_Virtual_Input.idc",
        "/system/usr/idc/windroye.idc",
        "/system/usr/keychars/nox_gpio.kcm",
        "/system/usr/keychars/windroye.kcm",
        "/system/usr/keylayout/Genymotion_Virtual_Input.kl",
        "/system/usr/keylayout/nox_Virtual_Input.kl",
        "/system/usr/keylayout/nox_gpio.kl",
        "/system/usr/keylayout/windroye.kl",
        "system/etc/init/ndk_translation_arm64.rc",
        "/system/xbin/noxsu",
        "/ueventd.android_x86.rc",
        "/ueventd.andy.rc",
        "/ueventd.goldfish.rc",
        "/ueventd.nox.rc",
        "/ueventd.ranchu.rc",
        "/ueventd.ttVM_x86.rc",
        "/ueventd.vbox86.rc",
        "/vendor/lib64/libgoldfish-ril.so",
        "/vendor/lib64/libgoldfish_codecs_common.so",
        "/vendor/lib64/libstagefright_goldfish_avcdec.so",
        "/vendor/lib64/libstagefright_goldfish_vpxdec.so",
        "/x86.prop",
        "\0"
    };

    ATTRIBUTES(section(".rodata_ext"), used) static const char fingerprintToBeChecked[][64] =
    {
        "generic",
        "vbox",
        "\0"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char modelToBeChecked[][64] =
    {
        "google_sdk",
        "emulator",
        "android sdk built for",
        "droid4x",
        "\0"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char productToBeChecked[][64] =
    {
        "google_sdk",
        "sdk_phone",
        "sdk_x86",
        "vbox86p",
        "nox",
        "\0"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char hardwareToBeChecked[][64] =
    {
        "ranchu",
        "goldfish",
        "vbox86",
        "\0"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char qemuPropsToBeChecked[][64] =
    {
        "ro.kernel.qemu.avd_name",
        "ro.kernel.qemu.gles",
        "ro.kernel.qemu.gltransport",
        "ro.kernel.qemu.opengles.version",
        "ro.kernel.qemu.uirenderer",
        "ro.kernel.qemu.vsync",
        "ro.qemu.initrc",
        "init.svc.qemu-props",
        "qemu.adb.secure",
        "qemu.cmdline",
        "qemu.hw.mainkeys",
        "qemu.logcat",
        "ro.adb.qemud",
        "qemu.sf.fake_camera",
        "qemu.sf.lcd_density",
        "qemu.timezone",
        "init.svc.goldfish-logcat",
        "ro.boottime.goldfish-logcat",
        "ro.hardware.audio.primary",
        "init.svc.ranchu-net",
        "init.svc.ranchu-setup",
        "ro.boottime.ranchu-net",
        "ro.boottime.ranchu-setup",
        "init.svc.droid4x",
        "init.svc.noxd",
        "init.svc.qemud",
        "init.svc.goldfish-setup",
        "init.svc.ttVM_x86-setup",
        "vmos.browser.home",
        "vmos.camera.enable",
        "ro.trd_yehuo_searchbox",
        "init.svc.microvirtd",
        "init.svc.vbox86-setup",
        "ro.ndk_translation.version",
        "redroid.width",
        "redroid.height",
        "redroid.fps",
        "ro.rf.vmname",
        "\0"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char propNames[][PROP_NAME_MAX] =
    {
            "ro.build.fingerprint",
            "ro.product.model",
            "ro.product.manufacturer",
            "Genymotion",
            "ro.product.name",
            "ro.product.board",
            "nox",
            "ro.bootloader",
            "ro.hardware",
            "Goldfish"
    };
    ATTRIBUTES(section(".rodata_ext"), used) static const char IPs[][INET_ADDRSTRLEN] =
    {
        "10.0.2.15",
        "10.0.2.16"
    };
    ASensorManager *sensorManager = NULL;
    ASensorList sensorList = NULL;
    struct ifaddrs *ifaddr = NULL;
    void *addr = NULL;
    char props[PROP_VALUE_MAX] = { 0 };
    char ip[INET_ADDRSTRLEN] = { 0 };
    int sensorCount = 0;

    /* Check files access */
    for (const char (*iterator)[64] = devMountsToBeChecked; (*iterator)[0] != '\0'; iterator++)
    {
        if (file_exists((*iterator)))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_DEVICE_MOUNTED_BASIC);
        }
    }

    /* Look for emulator fingerprint */
    if (get_android_prop(propNames[0], props) > 0)
    {
        for (const char (*iterator)[64] = fingerprintToBeChecked; (*iterator)[0] != '\0'; iterator++)
        {
            FUADXSHELL_LOG_E("Checking: %s", (*iterator));
            if (strstr(props, (*iterator)))
            {
                FUADXSHELL_LOG_D("Possible emulator detected");
                return (void *)(intptr_t)(-EMULATOR_FINGERPRINT_BASIC);
            }
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for emulator model */
    if (get_android_prop(propNames[1], props) > 0)
    {
        for (const char (*iterator)[64] = modelToBeChecked; (*iterator)[0] != '\0'; iterator++)
        {
            FUADXSHELL_LOG_E("Checking 2: %s", (*iterator));
            if (strstr(props, (*iterator)))
            {
                FUADXSHELL_LOG_D("Possible emulator detected");
                return (void *)(intptr_t)(-EMULATOR_MODEL_BASIC);
            }
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for Genymotion */
    if (get_android_prop(propNames[2], props) > 0)
    {
        if (strstr(props, propNames[3]))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_PRODUCT_BASIC);
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for emulator product */
    if (get_android_prop(propNames[4], props) > 0)
    {
        for (const char (*iterator)[64] = productToBeChecked; (*iterator)[0] != '\0'; iterator++)
        {
            FUADXSHELL_LOG_E("Checking 3: %s", (*iterator));
            if (strstr(props, (*iterator)))
            {
                FUADXSHELL_LOG_D("Possible emulator detected");
                return (void *)(intptr_t)(-EMULATOR_PRODUCT_BASIC);
            }
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for nox emulator board or bootloader */
    if (get_android_prop(propNames[5], props) > 0)
    {
        if (strstr(props, propNames[6]))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_BOARD_BASIC);
        }
    }
    if (get_android_prop(propNames[7], props) > 0)
    {
        if (strstr(props, propNames[6]))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_BOOTLOADER_BASIC);
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for emulator hardware */
    if (get_android_prop(propNames[8], props) > 0)
    {
        for (const char (*iterator)[64] = hardwareToBeChecked; (*iterator)[0] != '\0'; iterator++)
        {
            FUADXSHELL_LOG_E("Checking 4: %s", (*iterator));
            if (strstr(props, (*iterator)))
            {
                FUADXSHELL_LOG_D("Possible emulator detected");
                return (void *)(intptr_t)(-EMULATOR_HARDWARE_BASIC);
            }
        }
    }
    else
        FUADXSHELL_LOG_E("Unable to get properties");

    /* Look for suspicious emulator-related IPs */
    if (getifaddrs(&ifaddr) != 0)
    {
        FUADXSHELL_LOG_E("Error while getting interfaces: %s", strerror(errno));
        return (void *)((intptr_t)0);
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;
        addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        if (!inet_ntop(AF_INET, addr, ip, sizeof(ip)))
            continue;
        if (!strcmp(ip, IPs[0]) || !strcmp(ip, IPs[1]))
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            freeifaddrs(ifaddr);
            return (void *)((intptr_t)-EMULATOR_IP_SELECTED_BASIC);
        }
        FUADXSHELL_LOG_D("No detection. It went through: %s", ip);
    }
    freeifaddrs(ifaddr);

    /* Look for QEMU props */
    for (const char (*iterator)[64] = qemuPropsToBeChecked; (*iterator)[0] != '\0'; iterator++)
    {
        if (get_android_prop((*iterator), props) > 0)
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)(intptr_t)(-EMULATOR_QEMU_PROP_BASIC);
        }
    }

    /* Look for potential emulated sensors */
    if (android_get_device_api_level() < 26)
        sensorManager = ASensorManager_getInstance();
    else
    {
        if (__builtin_available(android 26, *))
        {
            if (!arg)
            {
                FUADXSHELL_LOG_E("Error while getting sensor manager: No package name provided");
                return (void *)(intptr_t)(-1);
            }
            sensorManager = ASensorManager_getInstanceForPackage((char *)arg);
        }
    }
    if (!sensorManager)
    {
        FUADXSHELL_LOG_E("Error while getting sensor manager");
        return (void *)((intptr_t)0);
    }
    sensorCount = ASensorManager_getSensorList(sensorManager, &sensorList);
    if (sensorCount > 0)
    {
        for (int i = 0; i < sensorCount; i++)
        {
            if (strstr(ASensor_getName(sensorList[i]), propNames[9]))
            {
                FUADXSHELL_LOG_D("Possible emulator detected");
                return (void *)((intptr_t)-EMULATOR_SENSOR_BASIC);
            }
        }
    }
    else
        FUADXSHELL_LOG_E("Error while getting sensor list");
    return (void *)(intptr_t)(0);
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *watch_thermal_zones(ATTRIBUTES(unused) void *arg)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char thermal[] = "/sys/class/thermal";
    ATTRIBUTES(section(".rodata_ext"), used) static const char thermalZone[] = "thermal_zone";
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    int count = 0;

    if ((dir = opendir(thermal)) != NULL)
    {
        while ((entry = readdir(dir)) != NULL)
        {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            {
                FUADXSHELL_LOG_D("Pointing to self or parent. Nothing to do");
                continue;
            }
            if (strstr(entry->d_name, thermalZone))
                count++;
        }
        closedir(dir);
        if (count > 0)
        {
            FUADXSHELL_LOG_D("Possible emulator detected");
            return (void *)((intptr_t)-NO_THERMAL_ZONE);
        }
        return (void *)(intptr_t)(0);
    }
    else
    {
        FUADXSHELL_LOG_E("Error while opening thermal directory: %s", strerror(errno));
        return (void *)(intptr_t)(0);
    }
}

ATTRIBUTES(section(".text_ext"), always_inline, used)
static inline void *watch_arch(ATTRIBUTES(unused) void *arg)
{
    int errnoResult;
    int pid;

    if (__builtin_available(android 26, *))
    {
        struct sock_filter filter[15] =
        {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, __NR_getpid, 0, 12),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP + BPF_JEQ, FLAG, 0, 10),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (uint32_t) offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_X86_64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (864 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_I386, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (386 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_ARM, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA32 & SECCOMP_RET_DATA)),
            BPF_JUMP(BPF_JMP + BPF_JEQ, AUDIT_ARCH_AARCH64, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (0xA64 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (6 & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
        };
        struct sock_fprog program =
        {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter
        };
        errno = 0;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        {
            FUADXSHELL_LOG_E("Error while setting no new privs: %s", strerror(errno));
            return (void *)(intptr_t)(-1);
        }
        errno = 0;
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
        {
            FUADXSHELL_LOG_E("Error while setting seccomp filter: %s", strerror(errno));
            return (void *)((intptr_t)-1);
        }
        errno = 0;
        pid = syscall(__NR_getpid, FLAG);
        errnoResult = errno;
        FUADXSHELL_LOG_D("syscall returned: %d, errno: %d", pid, errnoResult);
        switch (errnoResult)
        {
            case 386:
                return (void *)(intptr_t)(I386_ARCH);
            case 864:
                return (void *)(intptr_t)(X86_64_ARCH);
            case 0xA32:
                return (void *)(intptr_t)(ARM_ARCH);
            case 0xA64:
                return (void *)(intptr_t)(AARCH64_ARCH);
            default:
                FUADXSHELL_LOG_E("Error while getting architecture: %s", strerror(errno));
                return (void *)(intptr_t)(0);
        }
    }
    else
    {
        FUADXSHELL_LOG_E("Error: Android version is too low to use this function");
        return (void *)(intptr_t)(-1);
    }
}

/* Pass the package name to the function */
ATTRIBUTES(section(".text_ext"), always_inline, used)
int detect_emulator(void)
{
    intptr_t resultThermalZones;
    intptr_t resultArch;
    intptr_t resultEmuAdvanced;
    intptr_t resultEmuBasic;
    pthread_t threadThermalZones;
    pthread_t threadArch;
    pthread_t threadEmuAdvanced;
    pthread_t threadEmuBasic;

    if (pthread_create(&threadThermalZones, NULL, (void *(*)(void *))watch_thermal_zones, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread: %s", strerror(errno));
        return -1;
    }
    if (pthread_create(&threadArch, NULL, (void *(*)(void *))watch_arch, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread. Deferring to only thermal zones: %s", strerror(errno));
        pthread_join(threadThermalZones, (void **)&resultThermalZones);
        return resultThermalZones;
    }
    pthread_join(threadThermalZones, (void **)&resultThermalZones);
    pthread_join(threadArch, (void **)&resultArch);

    /* !0 -> 1 */
    if (!resultThermalZones && (resultArch != X86_64_ARCH && resultArch != I386_ARCH))
    {
        FUADXSHELL_LOG_D("No suspicious activity detected with thermal zones: %" PRIxPTR " and arch: %" PRIxPTR, resultThermalZones, resultArch);
        return 0;
    }
    FUADXSHELL_LOG_D("Either one of the initial conditions raised suspicious activity. Moving onto further detections");

    /* Running two more checks */
    if (pthread_create(&threadEmuAdvanced, NULL, (void *(*)(void *))watch_emulator_advanced_features, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread: %s", strerror(errno));
        return -1;
    }
    if (pthread_create(&threadEmuBasic, NULL, (void *(*)(void *))watch_emulator_basic_features, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating thread. Deferring to only advanced features: %s", strerror(errno));
        pthread_join(threadEmuAdvanced, (void **)&resultEmuAdvanced);
        if ((resultThermalZones < 0 || (resultArch != X86_64_ARCH && resultArch != I386_ARCH)) && resultEmuAdvanced < 0)
        {
            FUADXSHELL_LOG_D("Suspicious activity detected");
            return -EEMU;
        }
        else
        {
            FUADXSHELL_LOG_D("No suspicious activity detected");
            return 0;
        }
    }

    pthread_join(threadEmuAdvanced, (void **)&resultEmuAdvanced);
    pthread_join(threadEmuBasic, (void **)&resultEmuBasic);
    if (!resultEmuAdvanced && !resultEmuBasic)
    {
        FUADXSHELL_LOG_D("No suspicious activity detected");
        return 0;
    }
    /* Fallback. At least one of the conditions raised suspicious activity */
    return -EEMU;
}