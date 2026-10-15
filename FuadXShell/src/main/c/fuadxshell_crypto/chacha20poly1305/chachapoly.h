#ifndef CHACHAPOLY_H
#define CHACHAPOLY_H

/* Defs */
#include "../../fuadxshell/defs.h"

/* Default includes */
#include <assert.h>

/* ChaCha includes */
#include "chacha.h"
#include "poly1305.h"

#define CHACHAPOLY_OK 0
#define CHACHAPOLY_INVALID_MAC -1

typedef struct chachapoly_ctx
{
    chacha_ctx_t cha_ctx;
} chachapoly_ctx_t;

ATTRIBUTES(always_inline, section(".text_ext")) extern int chachapoly_init(chachapoly_ctx_t *, const void *, int);
ATTRIBUTES(always_inline, section(".text_ext")) extern int chachapoly_crypt(chachapoly_ctx_t *, const void *, const void *, int, const void *, int, void *, void *, int, int);
ATTRIBUTES(always_inline, section(".text_ext"), unused) extern int chachapoly_crypt_short(chachapoly_ctx_t *, const void *, const void *, int, void *, int, void *, void *, int, int);

#endif /* CHACHAPOLY_H */
