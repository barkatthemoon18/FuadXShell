#include <rc4.h>

ATTRIBUTES(always_inline, section(".text_ext"), used)
void rc4_init(rc4_ctx_t *ctx, const uint8_t *key, size_t keylength)
{
    uint8_t tmp;
    uint8_t j;

    for (int i = 0; i < 256; i++)
        ctx->S[i] = (uint8_t)i;
    ctx->i = 0;
    ctx->j = 0;
    j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (uint8_t)(j + ctx->S[i] + key[i % keylength]);
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
void rc4_crypt(rc4_ctx_t *ctx, uint8_t *data, size_t length)
{
    uint8_t tmp;
    uint8_t rnd;

    for (size_t k = 0; k < length; k++)
    {
        ctx->i = (uint8_t)(ctx->i + 1);
        ctx->j = (uint8_t)(ctx->j + ctx->S[ctx->i]);
        /* Swap S[i] <-> S[j] */
        tmp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = tmp;
        /* Keystream */
        rnd = ctx->S[(uint8_t)(ctx->S[ctx->i] + ctx->S[ctx->j])];
        data[k] ^= rnd;
    }
}
