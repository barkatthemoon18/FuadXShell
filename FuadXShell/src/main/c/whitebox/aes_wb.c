#include <aes_wb.h>

ATTRIBUTES(always_inline, used)
int wb_encrypt(uint8_t *plaintext, size_t size)
{
    uint8_t counter[16];
    uint8_t buf[16];
    char iv_internal[17] = { 0 };
    int ret = 0;

    ret = precompute();
    /* Precomputation may return AES_PRECOMPUTED_INITIALIZED if the tables are already initialized. That's ignored since ain't an error */
    if (ret == -ENOADDR || ret == -ENOWBC || ret == -ENOENT)
    {
        FUADXSHELL_LOG_E("Unable to decrypt. Critical error: -9000");
        return ret;
    }
    FUADXSHELL_LOG_D("Using IV: %s", iv);
    hex_to_bin((const char *)iv, iv_internal, 16); /* TODO: Fix the IV handling. Should be iv_internal instead of iv */
    for (int i = 0; i < 16; i++)
        counter[i] = iv_internal[i];
    for (size_t i = 0; i < size; i++)
    {
        if ((i & 0xF) == 0)
        {
            for (int j = 0; j < 16; j++)
                buf[j] = counter[j];
            aes(buf);
            for (int j = 15; j >= 0; j--)
            {
                counter[j]++;
                if (counter[j])
                    break;
            }
        }
        plaintext[i] = plaintext[i] ^ buf[i & 0xF];
    }
    return 0;
}

ATTRIBUTES(always_inline, used)
int wb_decrypt(uint8_t *encrypted, size_t size)
{
    return wb_encrypt(encrypted, size);
}