#ifndef ROOT_H
#define ROOT_H

/* Defs */
#include <defs.h>

/* Macros for root checks */
#define SELINUX_PERMISSIVENESS_ENABLED (-100)
#define ROOT_PKGS_FOUND (-101)
#define ROOT_DANGEROUS_PKGS_FOUND (-102)
#define ROOT_CLOAKING_PKGS_FOUND (-103)
#define ROOT_SU_PATH_FOUND (-104)
#define ROOT_PATH_NON_RW_FOUND (-105)
#define EROOT (-106)

ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_selinux_permissiveness(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_root_packages(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_root_dangerous_packages(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_root_cloaking_packages(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_root_su_path(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_root_path_non_rw(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) int detect_root(void);

#endif /* ROOT_H */