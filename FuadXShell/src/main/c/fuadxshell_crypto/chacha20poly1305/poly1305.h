#ifndef POLY1305_H
#define POLY1305_H

#include "../../fuadxshell/defs.h"

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16
#define POLY1305_BLOCK_SIZE 16

#define USE_MEMCPY 1
#define USE_UNALIGNED 0

typedef struct poly1305_ctx
{
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char final;
} poly1305_ctx_t;

ATTRIBUTES(always_inline, section(".text_ext")) extern void poly1305_init(poly1305_ctx_t *, const unsigned char *);
ATTRIBUTES(always_inline, section(".text_ext")) extern void poly1305_update(poly1305_ctx_t *, const unsigned char *, size_t);
ATTRIBUTES(always_inline, section(".text_ext")) extern void poly1305_finish(poly1305_ctx_t *, unsigned char *);
ATTRIBUTES(always_inline, section(".text_ext"), unused) extern void poly1305_auth(unsigned char *, const unsigned char *, size_t, const unsigned char *);

#endif /* POLY1305_H */