#include <aes_internal.h>
#include <ctype.h>
#include <assert.h>

_Thread_local ssize_t precomputed = -1;
uint8_t xor[ROUNDS - 1][96][16][16] = { 0 };
uint8_t iv[33] = { 0 };
uint8_t tboxes_last[16][256] = { 0 };
uint32_t ty_boxes[ROUNDS - 1][16][256] = { 0 };
uint32_t mbl[ROUNDS - 1][16][256] = { 0 };

ATTRIBUTES(always_inline, used)
inline int parse_tables_dat(void *buffer, size_t size)
{
    uint32_t *dest32 = NULL;
    uint8_t *dest8 = NULL;
    char *text = NULL;
    char *ptriv = NULL;
    char *ptr = NULL;
    char *end = NULL;
    char *lineEnd = NULL;
    char *next;
    char name[32] = { 0 };
    unsigned long value = 0;
    size_t nameLen = 0;
    size_t expected = 0;
    size_t count;
    tables_type_t which = NONE;

    text = malloc(size + 1);
    if (!text)
    {
        FUADXSHELL_LOG_E("Error while allocating memory for tables.dat buffer: %s", strerror(errno));
        return -ENOMEM;
    }
    memcpy(text, buffer, size);
    text[size] = '\0';
    ptriv = text;
    while ((*ptriv) != '\n')
        ptriv++;
    ptriv++;
    for (int i = 0; (*ptriv) != '\n'; ptriv++, i++)
        iv[i] = (uint8_t)(*ptriv);
    ptr = text;
    end = text + size;
    while (ptr < end)
    {
        if (ptr[0] == '/' && ptr[1] == '/')
        {
            ptr += 2;
            while (ptr < end && isspace((unsigned char)(*ptr)))
                ++ptr;
            lineEnd = strchr(ptr, '\n');
            nameLen = (lineEnd ? (size_t)(lineEnd - ptr) : strlen(ptr));
            if (nameLen >= sizeof(name))
                nameLen = sizeof(name) - 1;
            memcpy(name, ptr, nameLen);
            name[nameLen] = '\0';
            ptr = lineEnd ? (lineEnd + 1) : end;
            if (!strcmp(name, TY_BOXES_DEF))
            {
                which = TY;
                dest32 = &ty_boxes[0][0][0];
                expected = TY_BOXES_COUNT;
            }
            else if (!strcmp(name, TBOXES_LAST_DEF))
            {
                which = LAST;
                dest8 = &tboxes_last[0][0];
                expected = TBOXES_LAST_COUNT;
            }
            else if (!strcmp(name, MBL_DEF))
            {
                which = MBL;
                dest32 = &mbl[0][0][0];
                expected = MBL_COUNT;
            }
            else
                continue;
            count = 0;
            while (count < expected && ptr < end)
            {
                ptr = skip_delimiters(ptr);
                if (ptr[0] == '/' && ptr[1] == '/')
                    break;
                if (!(*ptr))
                    break;
                value = strtoul(ptr, &next, 16);
                if (next == ptr)
                    break;
                ptr = next;
                if (which == LAST)
                    dest8[count] = (uint8_t)value;
                else
                    dest32[count] = (uint32_t)value;
                ++count;
            }
        }
        else
            ++ptr;
    }
    free(text);
    text = NULL;
    return (count == expected) ? 0 : -EINVAL;
}

ATTRIBUTES(always_inline, used)
static inline void shift_rows(uint8_t state[16])
{
    const int shifts[16] =
    {
        0, 5, 10,15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6,11
    };
    const uint8_t in[16] =
    {
        state[0], state[1], state[2], state[3],
        state[4], state[5], state[6], state[7],
        state[8], state[9], state[10], state[11],
        state[12], state[13], state[14], state[15]
    };

    for (int i = 0; i < 16; i++)
        state[i] = in[shifts[i]];
}

ATTRIBUTES(always_inline, used)
inline int precompute(void)
{
    void *buffer = NULL;
    char *dir = NULL;
    char *parent = NULL;
    char *apkDir = NULL;
    char soPath[PATH_MAX] = { 0 };
    char apkPath[PATH_MAX] = { 0 };
    size_t bufferSize = 0;
    ssize_t bytesWritten;
    size_t span;
    Dl_info info;

    if (precomputed > 0)
    {
        FUADXSHELL_LOG_D("AES precomputed tables already initialized");
        return EWBCOMPUTED;
    }
    else
    {
        FUADXSHELL_LOG_D("Initializing AES precomputed tables");
        for (int i = 0; i < ROUNDS - 1; i++)
            for (int j = 0; j < 96; j++)
                for (int k = 0; k < 16; k++)
                    for (int l = 0; l < 16; l++)
                        xor[i][j][k][l] = k ^ l;
        /* Initialize all other boxes */
        if (!dladdr(precompute, &info))
        {
            FUADXSHELL_LOG_E("Error while retrieving dladdr: %s", strerror(errno));
            return -ENOADDR;
        }
        strncpy(soPath, info.dli_fname, sizeof(soPath));
        soPath[sizeof(soPath) - 1] = '\0';
        dir = dirname(soPath);         // = ".../lib/armeabi-v7a"
        parent = dirname(dir);          // = ".../lib"
        apkDir = dirname(parent);      // = "/data/app/com.mi.paquete-1"
        span = strcspn(apkDir, "!");
        if (apkDir[span] == '!')
        {
            apkDir[span] = '\0'; // Remove the "base.apk!" part if it exists
            bytesWritten = snprintf(apkPath, sizeof(apkPath), "%s", apkDir);
        }
        else
            bytesWritten = snprintf(apkPath, sizeof(apkPath), "%s/base.apk", apkDir);
        if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(apkPath))
        {
            FUADXSHELL_LOG_E("Error while formatting APK path (needed %d bytes with max %zu bytes)", bytesWritten, sizeof(apkPath));
            return -ENAMETOOLONG;
        }
        unzip(apkPath, "fuadxshell.dat", &buffer, &bufferSize);
        if (!buffer || bufferSize == 0)
        {
            FUADXSHELL_LOG_E("Error while unzipping tables.dat from %s", apkPath);
            return -ENOENT;
        }
        if (parse_tables_dat(buffer, bufferSize) != 0)
        {
            FUADXSHELL_LOG_E("Error while parsing tables.dat from %s", apkPath);
            free(buffer);
            buffer = NULL;
            return -ENOWBC;
        }
        precomputed = AES_PRECOMPUTED_INITIALIZED;
        return precomputed;
    }
}

ATTRIBUTES(always_inline, used)
inline void aes(uint8_t in[16])
{
    uint8_t n0, n1, n2, n3;
    uint32_t aa, bb, cc, dd;

    for (int i = 0; i < ROUNDS - 1; i++)
    {
        shift_rows(in);
        for (int j = 0; j < 4; j++)
        {
            aa = ty_boxes[i][j * 4 + 0][in[j * 4 + 0]],
            bb = ty_boxes[i][j * 4 + 1][in[j * 4 + 1]],
            cc = ty_boxes[i][j * 4 + 2][in[j * 4 + 2]],
            dd = ty_boxes[i][j * 4 + 3][in[j * 4 + 3]];

            n0 = xor[i][j * 24 + 0][(aa >> 28) & 0xF][(bb >> 28) & 0xF];
            n1 = xor[i][j * 24 + 1][(cc >> 28) & 0xF][(dd >> 28) & 0xF];
            n2 = xor[i][j * 24 + 2][(aa >> 24) & 0xF][(bb >> 24) & 0xF];
            n3 = xor[i][j * 24 + 3][(cc >> 24) & 0xF][(dd >> 24) & 0xF];
            in[j * 4 + 0] = (xor[i][j * 24 + 4][n0][n1] << 4) | xor[i][j * 24 + 5][n2][n3];

            n0 = xor[i][j * 24 + 6][(aa >> 20) & 0xF][(bb >> 20) & 0xF];
            n1 = xor[i][j * 24 + 7][(cc >> 20) & 0xF][(dd >> 20) & 0xF];
            n2 = xor[i][j * 24 + 8][(aa >> 16) & 0xF][(bb >> 16) & 0xF];
            n3 = xor[i][j * 24 + 9][(cc >> 16) & 0xF][(dd >> 16) & 0xF];
            in[j * 4 + 1] = (xor[i][j * 24 + 10][n0][n1] << 4) | xor[i][j * 24 + 11][n2][n3];

            n0 = xor[i][j * 24 + 12][(aa >> 12) & 0xF][(bb >> 12) & 0xF];
            n1 = xor[i][j * 24 + 13][(cc >> 12) & 0xF][(dd >> 12) & 0xF];
            n2 = xor[i][j * 24 + 14][(aa >> 8) & 0xF][(bb >> 8) & 0xF];
            n3 = xor[i][j * 24 + 15][(cc >> 8) & 0xF][(dd >> 8) & 0xF];
            in[j * 4 + 2] = (xor[i][j * 24 + 16][n0][n1] << 4) | xor[i][j * 24 + 17][n2][n3];

            n0 = xor[i][j * 24 + 18][(aa >> 4) & 0xF][(bb >> 4) & 0xF];
            n1 = xor[i][j * 24 + 19][(cc >> 4) & 0xF][(dd >> 4) & 0xF];
            n2 = xor[i][j * 24 + 20][(aa >> 0) & 0xF][(bb >> 0) & 0xF];
            n3 = xor[i][j * 24 + 21][(cc >> 0) & 0xF][(dd >> 0) & 0xF];
            in[j * 4 + 3] = (xor[i][j * 24 + 22][n0][n1] << 4) | xor[i][j * 24 + 23][n2][n3];

            aa = mbl[i][j * 4 + 0][in[j * 4 + 0]];
            bb = mbl[i][j * 4 + 1][in[j * 4 + 1]];
            cc = mbl[i][j * 4 + 2][in[j * 4 + 2]];
            dd = mbl[i][j * 4 + 3][in[j * 4 + 3]];

            n0 = xor[i][j*24 + 0][(aa >> 28) & 0xF][(bb >> 28) & 0xF];
            n1 = xor[i][j*24 + 1][(cc >> 28) & 0xF][(dd >> 28) & 0xF];
            n2 = xor[i][j*24 + 2][(aa >> 24) & 0xF][(bb >> 24) & 0xF];
            n3 = xor[i][j*24 + 3][(cc >> 24) & 0xF][(dd >> 24) & 0xF];
            in[j * 4 + 0] = (xor[i][j * 24 + 4][n0][n1] << 4) | xor[i][j * 24 + 5][n2][n3];

            n0 = xor[i][j * 24 + 6][(aa >> 20) & 0xF][(bb >> 20) & 0xF];
            n1 = xor[i][j * 24 + 7][(cc >> 20) & 0xF][(dd >> 20) & 0xF];
            n2 = xor[i][j * 24 + 8][(aa >> 16) & 0xF][(bb >> 16) & 0xF];
            n3 = xor[i][j * 24 + 9][(cc >> 16) & 0xF][(dd >> 16) & 0xF];
            in[j * 4 + 1] = (xor[i][j * 24 + 10][n0][n1] << 4) | xor[i][j * 24 + 11][n2][n3];

            n0 = xor[i][j * 24 + 12][(aa >> 12) & 0xF][(bb >> 12) & 0xF];
            n1 = xor[i][j * 24 + 13][(cc >> 12) & 0xF][(dd >> 12) & 0xF];
            n2 = xor[i][j * 24 + 14][(aa >> 8) & 0xF][(bb >> 8) & 0xF];
            n3 = xor[i][j * 24 + 15][(cc >> 8) & 0xF][(dd >> 8) & 0xF];
            in[j * 4 + 2] = (xor[i][j * 24 + 16][n0][n1] << 4) | xor[i][j * 24 + 17][n2][n3];

            n0 = xor[i][j * 24 + 18][(aa >> 4) & 0xF][(bb >> 4) & 0xF];
            n1 = xor[i][j * 24 + 19][(cc >> 4) & 0xF][(dd >> 4) & 0xF];
            n2 = xor[i][j * 24 + 20][(aa >> 0) & 0xF][(bb >> 0) & 0xF];
            n3 = xor[i][j * 24 + 21][(cc >> 0) & 0xF][(dd >> 0) & 0xF];
            in[j * 4 + 3] = (xor[i][j * 24 + 22][n0][n1] << 4) | xor[i][j * 24 + 23][n2][n3];
        }
    }
    shift_rows(in);
    for (int i = 0; i < 16; i++)
        in[i] = tboxes_last[i][in[i]];
}