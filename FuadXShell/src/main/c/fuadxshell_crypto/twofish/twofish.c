#include <twofish.h>

static uint8_t tTable[2][4][16] =
{
    {
        { 0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4 },
        { 0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD },
        { 0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1 },
        { 0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA }
    },
    {
        { 0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5 },
        { 0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8 },
        { 0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF },
        { 0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA }
    }
};
static pthread_once_t onceExecution = PTHREAD_ONCE_INIT;
static qtype_t qTable[2][256];
static uint32_t mdsTable[4][256];
static const uint32_t mdsPolyDivxConst[] = { 0, 0xB4};
static const uint32_t rsPolyConst[] = { 0, 0x14D };
static uint32_t rsPolyDivConst[] = { 0, 0xA6 };

/* Supportive functions */
ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void init_q_boxes(void)
{
    make_q_table(tTable[0], qTable[0]);
    make_q_table(tTable[1], qTable[1]);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void init_mds_tables(void)
{
    uint32_t q;
    uint32_t qef;
    uint32_t q5b;

    for (int i = 0; i < 256; i++)
    {
        q = qTable[0][i];
        qef = (q >> 1) ^ mdsPolyDivxConst[q & 1];
        q5b = (qef >> 1) ^ mdsPolyDivxConst[qef & 1] ^ q;
        qef ^= q5b;

        mdsTable[1][i] = (q << 24) | (q5b << 16) | (qef << 8) | qef;
        mdsTable[3][i] = (q5b << 24) | (qef << 16) | (q << 8) | q5b;

        q = qTable[1][i];

        qef = (q >> 1) ^ mdsPolyDivxConst[q & 1];
        q5b = (qef >> 1) ^ mdsPolyDivxConst[qef & 1] ^ q;
        qef ^= q5b;

        mdsTable[0][i] = (qef << 24) | (qef << 16) | (q5b << 8) | q;
        mdsTable[2][i] = (qef << 24) | (q << 16) | (qef << 8) | q5b;
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void make_q_table(uint8_t t[4][16], qtype_t q[256])
{
    int ae;
    int be;
    int ao;
    int bo;

    for (int i = 0; i < 256; i++)
    {
        ae = i >> 4;
        be = i & 0xF;
        ao = ae ^ be;
        bo = ae ^ ROR4BY1(be) ^ ((ae << 3) & 8);
        ae = t[0][ao];
        be = t[1][bo];
        ao = ae ^ be;
        bo = ae ^ ROR4BY1(be) ^ ((ae << 3) & 8);
        ae = t[2][ao];
        be = t[3][bo];
        q[i] = (qtype_t)((be << 4) | ae);
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline uint32_t h(int k, uint8_t *L, int kCycles)
{
    switch (kCycles)
    {
        case 2:
            return H02(k, L) ^ H12(k, L) ^ H22(k, L) ^ H32(k, L);
        case 3:
            return H03(k, L) ^ H13(k, L) ^ H23(k, L) ^ H33(k, L);
        case 4:
            return H04(k, L) ^ H14(k, L) ^ H24(k, L) ^ H34(k, L);
        default:
            FUADXSHELL_LOG_E("Illegal argument for h(): %d", kCycles);
    }
    return 0; /* Should not reach this statement */
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void fill_boxes(uint8_t *S, int kCycles, tf_key_t *xKey)
{
    switch (kCycles)
    {
        case 2:
            for (int i = 0; i < 256; i++)
            {
                xKey->s[0][i] = H02(i, S);
                xKey->s[1][i] = H12(i, S);
                xKey->s[2][i] = H22(i, S);
                xKey->s[3][i] = H32(i, S);
            }
            break;
        case 3:
            for (int i = 0; i < 256; i++)
            {
                xKey->s[0][i] = H03(i, S);
                xKey->s[1][i] = H12(i, S);
                xKey->s[2][i] = H23(i, S);
                xKey->s[3][i] = H33(i, S);
            }
            break;
        case 4:
            for (int i = 0; i < 256; i++)
            {
                xKey->s[0][i] = H04(i, S);
                xKey->s[1][i] = H14(i, S);
                xKey->s[2][i] = H24(i, S);
                xKey->s[3][i] = H34(i, S);
            }
            break;
        default:
            FUADXSHELL_LOG_E("Illegal argument for fill_boxes(): %d", kCycles);
    }
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_first_init(void)
{
    FUADXSHELL_LOG_D("Initializing Twofish precomputed tables");
    init_q_boxes();
    init_mds_tables();
    FUADXSHELL_LOG_D("Twofish precomputed tables initialized successfully");
}

/* Functions */
ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_init(void)
{
    return (void)pthread_once(&onceExecution, tf_first_init);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_prep_key(uint8_t *key, int length, tf_key_t *xKey)
{
    uint8_t K[32 + 32 + 4];
    int kCycles;
    uint32_t A, B;
    uint8_t *kptr;
    uint8_t *sptr;
    uint8_t *t;
    uint8_t b, bx, bxx;

    tf_init();
    if (length < 0 || length > 32)
    {
        FUADXSHELL_LOG_E("Illegal key length: %d", length);
        return;
    }
    memcpy(K, key, length);
    memset(K + length, 0, sizeof(K) - length);
    kCycles = (length + 7) >> 3;
    if (kCycles < 2)
        kCycles = 2;
    for (int i = 0; i < 40; i++)
    {
        A = h(i, K, kCycles);
        B = h(i + 1, K + 4, kCycles);
        B = ROL32(B, 8);
        A += B;
        B += A;
        xKey->K[i] = A;
        xKey->K[i + 1] = ROL32(B, 9);
    }
    A = B = 0;
    kptr = K + 8 * kCycles;
    sptr = K + 32;
    while (kptr > K)
    {
        kptr -= 8;
        memset(sptr, 0, 4);
        memcpy(sptr + 4, kptr, 8);
        t = sptr + 11;
        while (t > sptr + 3)
        {
            b = (*t);
            bx = (uint8_t)((b << 1) ^ rsPolyConst[b >> 7]);
            bxx = (uint8_t)((b >> 1) ^ rsPolyDivConst[b & 1] ^ bx);
            t[-1] ^= bxx;
            t[-2] ^= bx;
            t[-3] ^= bxx;
            t[-4] ^= b;
            t--;
        }
        sptr += 8;
    }
    b = bx = bxx = 0;
    fill_boxes(&K[32], kCycles, xKey);
    memset(K, 0, sizeof(K));
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_enc_blk(tf_key_t *xKey, uint8_t *p, uint8_t *c)
{
    uint32_t A, B, C, D, T0, T1;

    GET_INPUT(p, A, B, C, D, xKey, 0);
    ENCRYPT(A, B, C, D, T0, T1, xKey);
    PUT_OUTPUT(C, D, A, B, c, xKey, 4);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_dec_blk(tf_key_t *xKey, uint8_t *c, uint8_t *p)
{
    uint32_t A, B, C, D, T0, T1;

    GET_INPUT(c, A, B, C, D, xKey, 4);
    DECRYPT(A, B, C, D, T0, T1, xKey);
    PUT_OUTPUT(C, D, A, B, p, xKey, 0);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
static inline void tf_setup(tf_ctx_t *ctx, uint8_t *key, uint8_t *iv)
{
    tf_init();
    tf_prep_key(key, 32, &(ctx->key));
    memcpy(ctx->iv, iv, 16);
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
inline ssize_t tf_enc(tf_ctx_t *ctx, uint8_t *hexKey, uint8_t *hexIv, uint8_t *text, size_t length)
{
    uint8_t keyBin[32] = { 0 };
    uint8_t ivBin[16] = { 0 };
    uint8_t counter[16] = { 0 };
    uint8_t buf[16] = { 0 };

    /* Preconditions */
    if (!ctx || !hexKey || !hexIv || !text || length == 0)
    {
        fprintf(stderr, "Invalid context, key, IV or plaintext provided for %s\n", __func__);
        return -1;
    }
    /* Convert hex key and IV to binary */
    hex_to_bin((const char *)hexKey, (char *)keyBin, 32);
    hex_to_bin((const char *)hexIv, (char *)ivBin, 16);
    /* Run the counter mode */
    for (size_t i = 0; i < 16; i++)
        counter[i] = ivBin[i];
    for (size_t i = 0; i < length; i++)
    {
        if ((i & 0xF) == 0)
        {
            for (size_t j = 0; j < 16; j++)
                buf[j] = counter[j];
            tf_enc_blk(&(ctx->key), buf, buf);
            for (size_t j = 15; j >= 0; j--)
            {
                counter[j]++;
                if (counter[j])
                    break;
            }
        }
        text[i] ^= buf[i & 0xF];
    }
    return 0;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
inline ssize_t tf_dec(tf_ctx_t *ctx, uint8_t *hexKey, uint8_t *hexIv, uint8_t *text, size_t length)
{
    return tf_enc(ctx, hexKey, hexIv, text, length); /* Decryption is the same as encryption in CTR mode */
}
