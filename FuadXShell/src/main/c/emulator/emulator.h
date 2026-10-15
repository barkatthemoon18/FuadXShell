#ifndef EMULATOR_H
#define EMULATOR_H

/* Default includes */
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/socket.h>

/* Specific Seccomp / Linux Audit includes */
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* Inet includes */
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

/* Android specifics */
#include <sys/system_properties.h>
#include <android/sensor.h>

/* Main include */
#include <defs.h>

/* FuadXShellUtils includes */
#include <fuadxshell_utils.h>

/* Logger includes */
#include <logger.h>

/* Macro flags */
#define FLAG 0xFEEDFACEU

/* Macro arch returns */
#define I386_ARCH (386)
#define X86_64_ARCH (864)
#define ARM_ARCH (0xA32)
#define AARCH64_ARCH (0xA64)

/* Thermal macro */
#define NO_THERMAL_ZONE (10)

/* Props macros */
#define EMULATOR_FILE_ACCESSED_ADVANCED (40)
#define EMULATOR_FILE_ACCESSED_ADVANCED_DUAL (41)
#define EMULATOR_DEVICE_MOUNTED_BASIC (43)
#define EMULATOR_FINGERPRINT_BASIC (44)
#define EMULATOR_MODEL_BASIC (45)
#define EMULATOR_PRODUCT_BASIC (46)
#define EMULATOR_BOARD_BASIC (46)
#define EMULATOR_BOOTLOADER_BASIC (47)
#define EMULATOR_HARDWARE_BASIC (48)
#define EMULATOR_QEMU_PROP_BASIC (50)
#define EMULATOR_IP_SELECTED_BASIC (51)
#define EMULATOR_SENSOR_BASIC (52)
#define EEMU (53)

ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *watch_emulator_advanced_features(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *watch_emulator_basic_features(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *watch_thermal_zones(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) static inline void *watch_arch(void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) int detect_emulator(void);

#endif /* EMULATOR_H */