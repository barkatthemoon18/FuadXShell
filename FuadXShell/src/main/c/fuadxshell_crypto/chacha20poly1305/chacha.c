#include <chacha.h>

#define U8C(v) (v ## U)
#define U32C(v) (v ## U)
#define U8V(v) ((unsigned char)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#if (USE_UNALIGNED == 1)
#define U8TO32_LITTLE(p) (*((uint32_t *)(p)))
    #define U32TO8_LITTLE(p, v) do { *((uint32_t *)(p)) = v } while (0)
#else
#define U8TO32_LITTLE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define U32TO8_LITTLE(p, v) \
        do \
        { \
            (p)[0] = U8V((v)); \
            (p)[1] = U8V((v) >> 8); \
            (p)[2] = U8V((v) >> 16); \
            (p)[3] = U8V((v) >> 24); \
        } while (0)
#endif

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))
#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b); d = ROTATE(XOR(d, a), 16); \
    c = PLUS(c, d); b = ROTATE(XOR(b, c), 12); \
    a = PLUS(a, b); d = ROTATE(XOR(d, a), 8); \
    c = PLUS(c, d); b = ROTATE(XOR(b, c), 7);

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

ATTRIBUTES(always_inline, section(".text_ext"))
void chacha_key_setup(chacha_ctx_t *ctx, const unsigned char *k, uint32_t kbits)
{
    const char *constants;

    ctx->input[4] = U8TO32_LITTLE(k + 0);
    ctx->input[5] = U8TO32_LITTLE(k + 4);
    ctx->input[6] = U8TO32_LITTLE(k + 8);
    ctx->input[7] = U8TO32_LITTLE(k + 12);
    if (kbits == 256)
    {
        k += 16;
        constants = sigma;
    }
    else
        constants = tau;
    ctx->input[8] = U8TO32_LITTLE(k + 0);
    ctx->input[9] = U8TO32_LITTLE(k + 4);
    ctx->input[10] = U8TO32_LITTLE(k + 8);
    ctx->input[11] = U8TO32_LITTLE(k + 12);
    ctx->input[0] = U8TO32_LITTLE(constants + 0);
    ctx->input[1] = U8TO32_LITTLE(constants + 4);
    ctx->input[2] = U8TO32_LITTLE(constants + 8);
    ctx->input[3] = U8TO32_LITTLE(constants + 12);
}

ATTRIBUTES(always_inline, section(".text_ext"))
void chacha_iv_setup(chacha_ctx_t *ctx, const unsigned char *iv, const unsigned char *ctr)
{
    ctx->input[12] = !ctr ? 0 : U8TO32_LITTLE(ctr + 0);
    ctx->input[13] = U8TO32_LITTLE(iv + 0);
    ctx->input[14] = U8TO32_LITTLE(iv + 4);
    ctx->input[15] = U8TO32_LITTLE(iv + 8);
}

ATTRIBUTES(always_inline, section(".text_ext"))
void chacha_encrypt_bytes(chacha_ctx_t *ctx, const unsigned char *plaintext, unsigned char *ciphertext, uint32_t bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    unsigned char *ctarget = NULL;
    unsigned char tmp[64];

    if (!bytes)
        return;
    j0 = ctx->input[0];
    j1 = ctx->input[1];
    j2 = ctx->input[2];
    j3 = ctx->input[3];
    j4 = ctx->input[4];
    j5 = ctx->input[5];
    j6 = ctx->input[6];
    j7 = ctx->input[7];
    j8 = ctx->input[8];
    j9 = ctx->input[9];
    j10 = ctx->input[10];
    j11 = ctx->input[11];
    j12 = ctx->input[12];
    j13 = ctx->input[13];
    j14 = ctx->input[14];
    j15 = ctx->input[15];

    for (;;)
    {
        if (bytes < 64)
        {
            memcpy(tmp, plaintext, bytes);
            plaintext = tmp;
            ctarget = ciphertext;
            ciphertext = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (int i = 20; i > 0; i -= 2)
        {
            QUARTERROUND(x0, x4, x8, x12)
            QUARTERROUND(x1, x5, x9, x13)
            QUARTERROUND(x2, x6, x10, x14)
            QUARTERROUND(x3, x7, x11, x15)
            QUARTERROUND(x0, x5, x10, x15)
            QUARTERROUND(x1, x6, x11, x12)
            QUARTERROUND(x2, x7, x8, x13)
            QUARTERROUND(x3, x4, x9, x14)
        }
        x0 = PLUS(x0, j0);
        x1 = PLUS(x1, j1);
        x2 = PLUS(x2, j2);
        x3 = PLUS(x3, j3);
        x4 = PLUS(x4, j4);
        x5 = PLUS(x5, j5);
        x6 = PLUS(x6, j6);
        x7 = PLUS(x7, j7);
        x8 = PLUS(x8, j8);
        x9 = PLUS(x9, j9);
        x10 = PLUS(x10, j10);
        x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12);
        x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14);
        x15 = PLUS(x15, j15);

        x0 = XOR(x0, U8TO32_LITTLE(plaintext + 0));
        x1 = XOR(x1, U8TO32_LITTLE(plaintext + 4));
        x2 = XOR(x2, U8TO32_LITTLE(plaintext + 8));
        x3 = XOR(x3, U8TO32_LITTLE(plaintext + 12));
        x4 = XOR(x4, U8TO32_LITTLE(plaintext + 16));
        x5 = XOR(x5, U8TO32_LITTLE(plaintext + 20));
        x6 = XOR(x6, U8TO32_LITTLE(plaintext + 24));
        x7 = XOR(x7, U8TO32_LITTLE(plaintext + 28));
        x8 = XOR(x8, U8TO32_LITTLE(plaintext + 32));
        x9 = XOR(x9, U8TO32_LITTLE(plaintext + 36));
        x10 = XOR(x10, U8TO32_LITTLE(plaintext + 40));
        x11 = XOR(x11, U8TO32_LITTLE(plaintext + 44));
        x12 = XOR(x12, U8TO32_LITTLE(plaintext + 48));
        x13 = XOR(x13, U8TO32_LITTLE(plaintext + 52));
        x14 = XOR(x14, U8TO32_LITTLE(plaintext + 56));
        x15 = XOR(x15, U8TO32_LITTLE(plaintext + 60));

        j12 = PLUSONE(j12);
        if (!j12)
            j13 = PLUSONE(j13);
        U32TO8_LITTLE(ciphertext + 0, x0);
        U32TO8_LITTLE(ciphertext + 4, x1);
        U32TO8_LITTLE(ciphertext + 8, x2);
        U32TO8_LITTLE(ciphertext + 12, x3);
        U32TO8_LITTLE(ciphertext + 16, x4);
        U32TO8_LITTLE(ciphertext + 20, x5);
        U32TO8_LITTLE(ciphertext + 24, x6);
        U32TO8_LITTLE(ciphertext + 28, x7);
        U32TO8_LITTLE(ciphertext + 32, x8);
        U32TO8_LITTLE(ciphertext + 36, x9);
        U32TO8_LITTLE(ciphertext + 40, x10);
        U32TO8_LITTLE(ciphertext + 44, x11);
        U32TO8_LITTLE(ciphertext + 48, x12);
        U32TO8_LITTLE(ciphertext + 52, x13);
        U32TO8_LITTLE(ciphertext + 56, x14);
        U32TO8_LITTLE(ciphertext + 60, x15);
        if (bytes <= 64)
        {
            if (bytes < 64)
                memcpy(ctarget, ciphertext, bytes);
            ctx->input[12] = j12;
            ctx->input[13] = j13;
            return;
        }
        bytes -= 64;
        ciphertext += 64;
        plaintext += 64;
    }
}