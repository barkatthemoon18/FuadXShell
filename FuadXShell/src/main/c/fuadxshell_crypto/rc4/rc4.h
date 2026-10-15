#ifndef RC4_H
#define RC4_H

#include <defs.h>

typedef struct rc4_ctx
{
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} rc4_ctx_t;

ATTRIBUTES(always_inline, section(".text_ext"), used) extern void rc4_init(rc4_ctx_t *, const uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) extern void rc4_crypt(rc4_ctx_t *, uint8_t *, size_t);

#endif /* RC4_H */