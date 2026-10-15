#include "sha256.h"

struct sha2_ctx_t
{
    uint8_t buf[64];
    uint32_t total[2];
    uint32_t state[10];
};

ATTRIBUTES(always_inline, used)
static inline void sha256_start(sha2_ctx_t *ctx)
{
    /* Zero'd total array */
    ctx->total[0] = ctx->total[1] = 0;

    /* Init SHA-2 state */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

ATTRIBUTES(always_inline, used)
static inline void sha256_process(sha2_ctx_t *ctx, const uint8_t *data)
{
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t W[64];

    GET_UINT32(W[0], data, 0);
    GET_UINT32(W[1], data, 4);
    GET_UINT32(W[2], data, 8);
    GET_UINT32(W[3], data, 12);
    GET_UINT32(W[4], data, 16);
    GET_UINT32(W[5], data, 20);
    GET_UINT32(W[6], data, 24);
    GET_UINT32(W[7], data, 28);
    GET_UINT32(W[8], data, 32);
    GET_UINT32(W[9], data, 36);
    GET_UINT32(W[10], data, 40);
    GET_UINT32(W[11], data, 44);
    GET_UINT32(W[12], data, 48);
    GET_UINT32(W[13], data, 52);
    GET_UINT32(W[14], data, 56);
    GET_UINT32(W[15], data, 60);

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    P_SHA2(A, B, C, D, E, F, G, H, W[0], 0x428A2F98);
    P_SHA2(H, A, B, C, D, E, F, G, W[1], 0x71374491);
    P_SHA2(G, H, A, B, C, D, E, F, W[2], 0xB5C0FBCF);
    P_SHA2(F, G, H, A, B, C, D, E, W[3], 0xE9B5DBA5);
    P_SHA2(E, F, G, H, A, B, C, D, W[4], 0x3956C25B);
    P_SHA2(D, E, F, G, H, A, B, C, W[5], 0x59F111F1);
    P_SHA2(C, D, E, F, G, H, A, B, W[6], 0x923F82A4);
    P_SHA2(B, C, D, E, F, G, H, A, W[7], 0xAB1C5ED5);
    P_SHA2(A, B, C, D, E, F, G, H, W[8], 0xD807AA98);
    P_SHA2(H, A, B, C, D, E, F, G, W[9], 0x12835B01);
    P_SHA2(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
    P_SHA2(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
    P_SHA2(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
    P_SHA2(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
    P_SHA2(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
    P_SHA2(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(16), 0xE49B69C1);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(17), 0xEFBE4786);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(18), 0x0FC19DC6);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(19), 0x240CA1CC);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(20), 0x2DE92C6F);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(21), 0x4A7484AA);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(22), 0x5CB0A9DC);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(23), 0x76F988DA);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(24), 0x983E5152);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(25), 0xA831C66D);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(26), 0xB00327C8);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(27), 0xBF597FC7);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(28), 0xC6E00BF3);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(29), 0xD5A79147);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(30), 0x06CA6351);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(31), 0x14292967);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(32), 0x27B70A85);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(33), 0x2E1B2138);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(34), 0x4D2C6DFC);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(35), 0x53380D13);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(36), 0x650A7354);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(37), 0x766A0ABB);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(38), 0x81C2C92E);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(39), 0x92722C85);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(40), 0xA2BFE8A1);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(41), 0xA81A664B);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(42), 0xC24B8B70);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(43), 0xC76C51A3);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(44), 0xD192E819);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(45), 0xD6990624);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(46), 0xF40E3585);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(47), 0x106AA070);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(48), 0x19A4C116);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(49), 0x1E376C08);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(50), 0x2748774C);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(51), 0x34B0BCB5);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(52), 0x391C0CB3);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(53), 0x4ED8AA4A);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(54), 0x5B9CCA4F);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(55), 0x682E6FF3);
    P_SHA2(A, B, C, D, E, F, G, H, R_SHA2(56), 0x748F82EE);
    P_SHA2(H, A, B, C, D, E, F, G, R_SHA2(57), 0x78A5636F);
    P_SHA2(G, H, A, B, C, D, E, F, R_SHA2(58), 0x84C87814);
    P_SHA2(F, G, H, A, B, C, D, E, R_SHA2(59), 0x8CC70208);
    P_SHA2(E, F, G, H, A, B, C, D, R_SHA2(60), 0x90BEFFFA);
    P_SHA2(D, E, F, G, H, A, B, C, R_SHA2(61), 0xA4506CEB);
    P_SHA2(C, D, E, F, G, H, A, B, R_SHA2(62), 0xBEF9A3F7);
    P_SHA2(B, C, D, E, F, G, H, A, R_SHA2(63), 0xC67178F2);

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

ATTRIBUTES(always_inline, used)
static inline void sha256_update(sha2_ctx_t *ctx, const uint8_t *input, uint32_t length)
{
    uint32_t left;
    uint32_t fill;

    if (!length)
    {
#ifndef NDEBUG
        FUADXSHELL_LOG_D("Length is zero, nothing to do");
#endif
        return;
    }
    left = ctx->total[0] & 0x3F;
    fill = 64 - left;
    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;
    if (ctx->total[0] < length)
        ctx->total[1]++;
    if (left && length >= fill)
    {
        (void) memcpy(ctx->buf + left, input, fill);
        sha256_process(ctx, ctx->buf);
        length -= fill;
        input += fill;
        left = 0;
    }
    while (length >= 64)
    {
        sha256_process(ctx, input);
        length -= 64;
        input += 64;
    }
    if (length)
        (void) memcpy(ctx->buf + left, input, length);
}

ATTRIBUTES(always_inline, used)
static inline void sha256_finish(sha2_ctx_t *ctx, uint8_t *digest)
{
    uint32_t last;
    uint32_t padn;
    uint32_t high, low;
    uint8_t msglen[8] = { 0 };
    uint8_t pad[64] =
            {
                    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            };
    high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);

    PUT_UINT32(high, msglen, 0);
    PUT_UINT32(low, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    sha256_update(ctx, pad, padn);
    sha256_update(ctx, msglen, 8);

    PUT_UINT32(ctx->state[0], digest, 0);
    PUT_UINT32(ctx->state[1], digest, 4);
    PUT_UINT32(ctx->state[2], digest, 8);
    PUT_UINT32(ctx->state[3], digest, 12);
    PUT_UINT32(ctx->state[4], digest, 16);
    PUT_UINT32(ctx->state[5], digest, 20);
    PUT_UINT32(ctx->state[6], digest, 24);
    PUT_UINT32(ctx->state[7], digest, 28);
    digest[32] = '\0';
}

ATTRIBUTES(always_inline, used)
void sha256(const uint8_t *input, uint32_t length, uint8_t *output)
{
    sha2_ctx_t ctx = { .state = { 0 }, .buf = { 0 }, .total = { 0 } };

    if (!input)
    {
#ifndef NDEBUG
        FUADXSHELL_LOG_D("Input is null, nothing to do");
#endif
        return;
    }
    if (!length)
    {
#ifndef NDEBUG
        FUADXSHELL_LOG_D("Length is zero, nothing to do");
#endif
        return;
    }
    if (!output)
    {
#ifndef NDEBUG
        FUADXSHELL_LOG_D("Output is null, nothing to do");
#endif
        return;
    }
    sha256_start(&ctx);
    sha256_update(&ctx, input, length);
    sha256_finish(&ctx, output);
#ifndef NDEBUG
    FUADXSHELL_LOG_D("SHA256: %s", output);
#else
    (void) memset(&ctx, 0, sizeof(ctx));
        __asm__ __volatile__ ("" : : "r"(&ctx) : "memory");
#endif
}