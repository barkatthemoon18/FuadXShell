#ifndef FUADXSHELL_UTILS_H
#define FUADXSHELL_UTILS_H

/* Defs */
#include <defs.h>

/* Link */
#include <link.h>

/* Minizip */
#include <mz_zip.h>
#include <mz_zip_rw.h>
#include <compat/unzip.h>

/* Android properties */
#include <sys/system_properties.h>

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

/* Reflection */
#include <../reflection/reflection.h>

#if defined(__aarch64__)
    #define LIB_SUBDIR "lib/arm64-v8a/"
#elif defined(__arm__)
    #define LIB_SUBDIR "lib/armeabi-v7a/"
#elif defined(__i386__)
    #define LIB_SUBDIR "lib/x86/"
#elif defined(__x86_64__)
    #define LIB_SUBDIR "lib/x86_64/"
#else
    #error "Unsupported architecture"
#endif

typedef enum
{
    CIPHER_AES = 0,
    CIPHER_BLOWFISH,
    CIPHER_CHACHA20,
    CIPHER_RC4,
    NO_ENCRYPTION = -1
} encryption_type_t;

typedef enum
{
    SHA_256 = 0,
    SHA_384,
    SHA_512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE_128,
    SHAKE_256,
    BLAKE2B512,
    BLAKE2S256,
    KECCAK256,
    NO_DIGEST = -1
} digest_type_t;

typedef enum
{
    C_MAC = 0,
    H_MAC,
    K_MAC128,
    K_MAC256,
    POLY_1305,
    NO_MAC = -1
} mac_type_t;

typedef enum
{
    KDF_ARGON2ID = 0,
    KDF_PBKDF2,
    KDF_HKDF,
    KDF_SCRYPT,
    NO_KDF = -1
} kdf_type_t;

typedef enum
{
    SIG_RSA_PKCS15 = 0,
    SIG_RSA_PSS,
    SIG_ECDSA_SHA_256,
    SIG_ED25519,
    NO_SIG = -1
} signature_type_t;

typedef struct map_entry
{
    uintptr_t start; /* Start address of the section */
    uintptr_t end; /* End address of the section */
    unsigned long offset; /* Offset of the section in the file */
    char permissions[5]; /* Permissions of the section */
    unsigned dev_major; /* Major device number */
    unsigned dev_minor; /* Minor device number */
    ino_t inode; /* Inode number */
    char *pathname; /* Pathname of the section */
} map_entry_t;

typedef struct ctx ctx_t;

/* Section handling */
ATTRIBUTES(always_inline, used) int lookup_library_info(struct dl_phdr_info *, Dl_info *, so_info_t *, const char *, bool);
ATTRIBUTES(always_inline, used) int lookup_section(Elf_Word *, Elf_Word *, void *,
                                                                 const char *);
/* Runtime decryption */
ATTRIBUTES(always_inline, used) static inline void rotate_init(ctx_t *, const uint8_t *);
ATTRIBUTES(always_inline, unused) void rotate(const char *, char *, size_t);
ATTRIBUTES(always_inline, overloadable, used) int unzip(const char *, const char *, void **, size_t *);
ATTRIBUTES(always_inline, overloadable, used) int unzip(const char *, const char *, so_info_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) int unzip_files(const char *);
ATTRIBUTES(always_inline, section(".text_ext"), used) int decrypt_dex(char *, const char *, const char *, size_t);

/* Android properties */
ATTRIBUTES(always_inline, used) static inline void prop_callback(void *, const char *, const char *, uint32_t);
ATTRIBUTES(always_inline, used) int get_android_prop(const char *, char *);

/* File operations */
ATTRIBUTES(always_inline, section(".text_ext"), used) int file_exists(const char *);
ATTRIBUTES(always_inline, used) ssize_t readline(int, char *, size_t);

/* Maps parsing */
ATTRIBUTES(always_inline, used) int parse_maps(pid_t, map_entry_t **, size_t *);
ATTRIBUTES(always_inline, used) void release_parsed_maps(map_entry_t *, size_t);

/* String handling */
ATTRIBUTES(always_inline, used) char *parse_cmdline(void);
ATTRIBUTES(always_inline, used) char *skip_line(char *);
ATTRIBUTES(always_inline, used) char *skip_delimiters(char *);

/* OpenSSL Crypto */
ATTRIBUTES(always_inline, section(".text_ext"), used) int kdf(kdf_type_t, uint8_t *, size_t, const uint8_t *, size_t,
                                        const uint8_t *, size_t, const uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) int encrypt(encryption_type_t, const uint8_t *, size_t, const uint8_t *,
                                            size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                                            uint8_t *, uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) int decrypt(encryption_type_t, const uint8_t *, size_t, const uint8_t *,
                                            size_t, const uint8_t *, size_t, const uint8_t *, size_t,
                                            const uint8_t *, size_t, uint8_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) int digest(digest_type_t, const uint8_t *, uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) int mac(mac_type_t, const uint8_t *, size_t, const uint8_t *, size_t,
                                        uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) int sign(signature_type_t, digest_type_t, EVP_PKEY *, const uint8_t *,
                                         size_t, uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) int verify(signature_type_t, digest_type_t, EVP_PKEY *, const uint8_t *,
                                           size_t, const uint8_t *, size_t);

/* Encoding */
ATTRIBUTES(always_inline, used) void bin_to_hex(const char *, char *, size_t);
ATTRIBUTES(always_inline, used) void hex_to_bin(const char *, char *, size_t);

/* RAII */
ATTRIBUTES(always_inline, used) void raii_fd(int *);
ATTRIBUTES(always_inline, used) void raii_mallocd(void **);
ATTRIBUTES(always_inline, used) void raii_so_info_t(so_info_t *);

#endif /* FUADXSHELL_UTILS_H */