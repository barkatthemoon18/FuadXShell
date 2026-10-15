#include <poly1305.h>

#if (USE_UNALIGNED == 1)
#define U8TO32(p) (*((uint32_t *)(p)))
    #define U32TO8(p, v) do { *((uint32_t *)(p)) = v; } while (0)
#else
static uint32_t U8TO32(const unsigned char *p)
{
    return (((uint32_t)(p[0] & 0xFF)) | ((uint32_t)(p[1] & 0xFF) << 8) | ((uint32_t)(p[2] & 0xFF) << 16) | ((uint32_t)(p[3] & 0xFF) << 24));
}

static void U32TO8(unsigned char *p, uint32_t v)
{
    p[0] = (v) & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24 ) & 0xFF;
}
#endif

ATTRIBUTES(always_inline, section(".text_ext"))
void poly1305_init(poly1305_ctx_t *ctx, const unsigned char *key)
{
    ctx->r[0] = (U8TO32(&key[0])) & 0x3FFFFFF;
    ctx->r[1] = (U8TO32(&key[3]) >> 2) & 0x3FFFF03;
    ctx->r[2] = (U8TO32(&key[6]) >> 4) & 0x3FFC0FF;
    ctx->r[3] = (U8TO32(&key[9]) >> 6) & 0x3F03FFF;
    ctx->r[4] = (U8TO32(&key[12]) >> 8) & 0x00FFFFF;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad for later */
    ctx->pad[0] = U8TO32(&key[16]);
    ctx->pad[1] = U8TO32(&key[20]);
    ctx->pad[2] = U8TO32(&key[24]);
    ctx->pad[3] = U8TO32(&key[28]);

    ctx->leftover = 0;
    ctx->final = 0;
}

ATTRIBUTES(always_inline, section(".text_ext"))
static void poly1305_blocks(poly1305_ctx_t *ctx, const unsigned char *plaintext, size_t bytes)
{
    const uint32_t hibit = (ctx->final) ? 0 : (1 << 24);
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    while (bytes >= POLY1305_BLOCK_SIZE)
    {
        h0 += (U8TO32(plaintext + 0)     ) & 0x3FFFFFF;
        h1 += (U8TO32(plaintext + 3) >> 2) & 0x3FFFFFF;
        h2 += (U8TO32(plaintext + 6) >> 4) & 0x3FFFFFF;
        h3 += (U8TO32(plaintext + 9) >> 6) & 0x3FFFFFF;
        h4 += (U8TO32(plaintext + 12) >> 8) | hibit;

        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFF;
        d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFF;
        d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFF;
        d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFF;
        d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFF;
        h0 += c * 5;  c =           (h0 >> 26); h0 =           h0 & 0x3FFFFFF;
        h1 += c;

        plaintext += POLY1305_BLOCK_SIZE;
        bytes -= POLY1305_BLOCK_SIZE;
    }
    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

ATTRIBUTES(always_inline, section(".text_ext"))
void poly1305_finish(poly1305_ctx_t *ctx, unsigned char *mac)
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;
    size_t i;

    if (ctx->leftover)
    {
        i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            ctx->buffer[i] = 0;
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->buffer, POLY1305_BLOCK_SIZE);
    }
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    c = h1 >> 26; h1 = h1 & 0x3FFFFFF;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3FFFFFF;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3FFFFFF;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3FFFFFF;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3FFFFFF;
    h1 +=     c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFF;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFF;
    g4 = h4 + c - (1 << 26);

    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = ((h0) | (h1 << 26)) & 0xFFFFFFFF;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xFFFFFFFF;

    f = (uint64_t)h0 + ctx->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;

    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);

    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->r[0] = 0;
    ctx->r[1] = 0;
    ctx->r[2] = 0;
    ctx->r[3] = 0;
    ctx->r[4] = 0;
    ctx->pad[0] = 0;
    ctx->pad[1] = 0;
    ctx->pad[2] = 0;
    ctx->pad[3] = 0;
}

ATTRIBUTES(always_inline, section(".text_ext"))
void poly1305_update(poly1305_ctx_t *ctx, const unsigned char *plaintext, size_t bytes)
{
    size_t want;

    if (ctx->leftover)
    {
        want = (POLY1305_BLOCK_SIZE - ctx->leftover);
        if (want > bytes)
            want = bytes;
        for (size_t i = 0; i < want; i++)
            ctx->buffer[ctx->leftover + i] = plaintext[i];
        bytes -= want;
        plaintext += want;
        if (ctx->leftover < POLY1305_BLOCK_SIZE)
            return;
        poly1305_blocks(ctx, ctx->buffer, POLY1305_BLOCK_SIZE);
        ctx->leftover = 0;
    }
    if (bytes >= POLY1305_BLOCK_SIZE)
    {
        want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
        poly1305_blocks(ctx, plaintext, want);
        plaintext += want;
        bytes -= want;
    }
    if (bytes)
    {
        memcpy(ctx->buffer + ctx->leftover, plaintext, bytes);
        ctx->leftover += bytes;
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), unused)
void poly1305_auth(unsigned char *mac, const unsigned char *plaintext, size_t bytes, const unsigned char *key)
{
    poly1305_ctx_t ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, plaintext, bytes);
    poly1305_finish(&ctx, mac);
}