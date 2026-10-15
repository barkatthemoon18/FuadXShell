#include <chachapoly.h>

ATTRIBUTES(always_inline, section(".text_ext"))
static int memcmp_eq(const void *av, const void *bv, int n)
{
    const unsigned char *a = (const unsigned char *)av;
    const unsigned char *b = (const unsigned char *)bv;
    unsigned char res = 0;

    for (int i = 0; i < n; i++)
    {
        res |= (*a) ^ (*b);
        a++; b++;
    }
    return res;
}

ATTRIBUTES(always_inline, section(".text_ext"))
static void poly1305_get_tag(unsigned char *poly_key, const void *ad, int ad_len, const void *ct, int ct_len, unsigned char *tag)
{
    poly1305_ctx_t pctx;
    uint32_t leftover;
    uint64_t len;
    unsigned char pad[16];

    poly1305_init(&pctx, poly_key);
    memset(&pad, 0, sizeof(pad));
    poly1305_update(&pctx, ad, ad_len);
    leftover = ad_len % 16;
    if (leftover)
        poly1305_update(&pctx, pad, 16 - leftover);
    poly1305_update(&pctx, ct, ct_len);
    leftover = ct_len % 16;
    if (leftover)
        poly1305_update(&pctx, pad, 16 - leftover);
    len = ad_len;
    poly1305_update(&pctx, (unsigned char *)&len, 8);
    len = ct_len;
    poly1305_update(&pctx, (unsigned char *)&len, 8);
    poly1305_finish(&pctx, tag);
}

ATTRIBUTES(always_inline, section(".text_ext"))
int chachapoly_init(chachapoly_ctx_t *ctx, const void *key, int length)
{
    assert(length == 128 || length == 256);
    memset(ctx, 0, sizeof(*ctx));
    chacha_key_setup(&ctx->cha_ctx, key, length);
    return CHACHAPOLY_OK;
}

ATTRIBUTES(always_inline, section(".text_ext"))
int chachapoly_crypt(chachapoly_ctx_t *ctx, const void *nonce, const void *ad, int ad_len, const void *input, int input_len, void *output, void *tag, int tag_len, int encrypt)
{
    unsigned char polykey[CHACHA_BLOCKLEN];
    unsigned char calctag[POLY1305_TAGLEN];
    const unsigned char one[4] = { 1, 0, 0, 0 };

    memset(polykey, 0, sizeof(polykey));
    chacha_iv_setup(&ctx->cha_ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx->cha_ctx, polykey, polykey, sizeof(polykey));
    if (encrypt == 0 && tag_len)
    {
        poly1305_get_tag(polykey, ad, ad_len, input, input_len, calctag);
        if (memcmp_eq(calctag, tag, tag_len) != 0)
            return CHACHAPOLY_INVALID_MAC;
    }
    chacha_iv_setup(&ctx->cha_ctx, nonce, one);
    chacha_encrypt_bytes(&ctx->cha_ctx, (unsigned char *)input, (unsigned char *)output, input_len);
    if (encrypt && tag_len)
    {
        poly1305_get_tag(polykey, ad, ad_len, output, input_len, calctag);
        memcpy(tag, calctag, tag_len);
    }
    return CHACHAPOLY_OK;
}

ATTRIBUTES(always_inline, section(".text_ext"), unused)
int chachapoly_crypt_short(chachapoly_ctx_t *ctx, const void *nonce, const void *ad, int ad_len, void *input, int input_len, void *output, void *tag, int tag_len, int encrypt)
{
    unsigned char keystream[CHACHA_BLOCKLEN];
    unsigned char calctag[POLY1305_TAGLEN];

    assert(input_len <= 32);
    memset(keystream, 0, sizeof(keystream));
    chacha_iv_setup(&ctx->cha_ctx, nonce, NULL);
    chacha_encrypt_bytes(&ctx->cha_ctx, keystream, keystream, sizeof(keystream));
    if (encrypt == 0 && tag_len)
    {
        poly1305_get_tag(keystream, ad, ad_len, input, input_len, calctag);
        if (memcmp_eq(calctag, tag, tag_len) != 0)
            return CHACHAPOLY_INVALID_MAC;
    }
    for (int i = 0; i < input_len; i++)
        ((unsigned char *)output)[i] = ((unsigned char *)input)[i] ^ keystream[32 + i];
    if (encrypt && tag_len)
    {
        poly1305_get_tag(keystream, ad, ad_len, output, input_len, calctag);
        memcpy(tag, calctag, tag_len);
    }
    return CHACHAPOLY_OK;
}