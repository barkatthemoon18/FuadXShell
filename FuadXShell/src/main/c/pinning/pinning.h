#ifndef PINNING_H
#define PINNING_H

/* Defs include */
#include <defs.h>

/* FuadXShell Utils include */
#include <fuadxshell_utils.h>

/* Logger include */
#include <logger.h>

/* OpenSSL includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

/* Internet availability */
#define CONNECTIVITY_SERVICE STRINGIFY(connectivity)
#define CAP_INTERNET 12
#define CAP_VALIDATED 16
#define TRANSPORT_WIFI 1
#define TRANSPORT_CELLULAR 0
#define TRANSPORT_UNAVAILABLE (-1)

/* Pinning return codes */
#define PINNING_OK 0
#define PINNING_NO_CERTS (-1)
#define PINNING_UNKNOWN (-2)
#define PINNING_ERROR (-3)
#define PINNING_NO_NETWORK_AVAILABLE (-4)

/* Host / Port */
#define HOST "api.stackexchange.com"
#define PORT 443

ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void *check_pinning(void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static int check_trusted_certs(const char *, const char *, X509 *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline struct stack_st_X509 *load_ca_store(void);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline struct stack_st_X509 *fill_missing_cert(X509 *[static 2], int, int);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline int check_internet_availability(JNIEnv *, void *);
ATTRIBUTES(always_inline, section(".text_ext"), used) int run_pinning(JNIEnv *, void *);

#endif /* PINNING_H */
