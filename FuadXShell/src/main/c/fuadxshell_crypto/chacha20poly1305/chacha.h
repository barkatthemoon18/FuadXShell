#ifndef CHACHA_H
#define CHACHA_H

#include "../../fuadxshell/defs.h"

#define CHACHA_MINKEYLEN 16
#define CHACHA_NONCELEN 8
#define CHACHA_CTRLEN 8
#define CHACHA_STATELEN 16
#define CHACHA_BLOCKLEN 64

#define USE_MEMCPY 1
#define USE_UNALIGNED 0

typedef struct chacha_ctx_t
{
    uint32_t input[16];
} chacha_ctx_t;

ATTRIBUTES(always_inline, section(".text_ext")) extern void chacha_key_setup(chacha_ctx_t *, const uint8_t *, uint32_t);
ATTRIBUTES(always_inline, section(".text_ext")) extern void chacha_iv_setup(chacha_ctx_t *, const uint8_t *, const uint8_t *);
ATTRIBUTES(always_inline, section(".text_ext")) extern void chacha_encrypt_bytes(chacha_ctx_t *, const uint8_t *, uint8_t *, uint32_t);

#endif /* CHACHA_H */