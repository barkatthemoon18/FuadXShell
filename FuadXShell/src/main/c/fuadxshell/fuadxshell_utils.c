#include <fuadxshell_utils.h>

typedef struct ctx
{
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} ctx_t;

ATTRIBUTES(always_inline, used)
int lookup_library_info(struct dl_phdr_info *info, Dl_info *dlInfo, so_info_t *output, const char *path, bool isExtracted)
{
    static const char needle[] = "libfuadxshell.so";
    struct kernel_stat stat;
    ssize_t readBytes;
    int fd;

    if ((!dlInfo || !dlInfo->dli_fname) || (!info || !info->dlpi_name))
    {
        FUADXSHELL_LOG_E("Invalid Dl_info or dl_phdr_info provided for shared library %s", path);
        return -EINVAL;
    }
    /* Get PT_LOAD relative address and SO info */
    for (int i = 0; i < info->dlpi_phnum; i++)
    {
        if (info->dlpi_phdr[i].p_type == PT_LOAD && (info->dlpi_phdr[i].p_flags == (PF_X | PF_R)))
        {
            output->loadedAddr = (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            output->resource.resources[output->resource.count++] = (resource_t)
                {
                    .ptr = output->loadedAddr, .size = 0, .type = CT_NULLD
                };
            FUADXSHELL_LOG_D("Loaded shared library address: %p", output->loadedAddr);
            /* Get loaded data and size */
            if (isExtracted)
            {
                output->path = strdup(path);
                if (!output->path)
                {
                    FUADXSHELL_LOG_E("Error while allocating memory for library path: %s", strerror(errno));
                    return -ENOMEM;
                }
                output->resource.resources[output->resource.count++] = (resource_t)
                    {
                        .ptr = output->path, .size = -1, .type = CT_MALLOC
                    };
                if (sys_stat(output->path, &stat) == -1)
                {
                    FUADXSHELL_LOG_E("Error while getting shared library stats: %s", strerror(errno));
                    /* TODO: Add cleanup */
                }
                output->loadedMemSize = stat.st_size;
                output->loadedMem = malloc(output->loadedMemSize);
                if (!output->loadedMem)
                {
                    FUADXSHELL_LOG_E("Error while allocating memory for loaded shared library: %s", strerror(errno));
                    return -ENOMEM;
                }
                output->resource.resources[output->resource.count++] = (resource_t)
                    {
                        .ptr = output->loadedMem, .size = output->loadedMemSize, .type = CT_MALLOC
                    };
                fd = sys_open(path, O_RDONLY, 0);
                if (fd < 0)
                {
                    FUADXSHELL_LOG_E("Error while opening shared library file: %s", strerror(errno));
                    return -errno;
                }
                readBytes = sys_read(fd, output->loadedMem, output->loadedMemSize);
                if (readBytes < 0)
                {
                    FUADXSHELL_LOG_E("Error while reading shared library file: %s", strerror(errno));
                    sys_close(fd);
                    return -errno;
                }
                else if (unlikely((size_t)readBytes != output->loadedMemSize) || unlikely(readBytes == 0))
                {
                    FUADXSHELL_LOG_E("Error while reading shared library file: read %zu bytes, "
                                     "expected %zu bytes", readBytes, output->loadedMemSize);
                    sys_close(fd);
                    return -ENOREADBYTES;
                }
                FUADXSHELL_LOG_D("Shared library %s loaded into memory at %p with size %zu bytes",
                                 output->path, output->loadedMem, output->loadedMemSize);
                break;
            }
            else
            {
                /* Fallback when shared library is not extracted */
                if (unzip(path, needle, output) != 0)
                {
                    FUADXSHELL_LOG_E("Error while unzipping shared library %s", path);
                    return -ENODECR;
                }
                output->path = strdup(dlInfo->dli_fname);
                if (!output->path)
                {
                    FUADXSHELL_LOG_E("Error while allocating memory for library path: %s", strerror(errno));
                    return -ENOMEM;
                }
                output->resource.resources[output->resource.count++] = (resource_t)
                    {
                        .ptr = output->path, .size = -1, .type = CT_MALLOC
                    };
                break;
            }
        }
    }
    return 0;
}

ATTRIBUTES(always_inline, used)
inline int lookup_section(Elf_Word *sectionOffset,
                                 Elf_Word *sectionSize, void *paddr, const char *section)
{
    const char *sh_strtab_ptr = NULL;
    Elf_Ehdr *ehdr = NULL;
    Elf_Shdr *shdr = NULL;
    Elf_Shdr *sh_strtab = NULL;

    if (!paddr)
    {
        FUADXSHELL_LOG_E("Invalid memory-mapped address provided");
        return -EINVAL;
    }
    ehdr = (Elf_Ehdr *)paddr;
    shdr = (Elf_Shdr *)(paddr + ehdr->e_shoff);
    sh_strtab = &shdr[ehdr->e_shstrndx];
    sh_strtab_ptr = (paddr + sh_strtab->sh_offset);
    FUADXSHELL_LOG_D("%d sections found in shared library. Looking for %s", ehdr->e_shnum, ".text_ext");
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (!strcmp(sh_strtab_ptr + shdr[i].sh_name, section))
        {
            FUADXSHELL_LOG_D("Section %s found at offset %" PRIu64 " with size %" PRIu64 "\n",
                             section, (uint64_t)shdr[i].sh_offset, (uint64_t)shdr[i].sh_size);
            (*sectionOffset) = shdr[i].sh_offset;
            (*sectionSize) = shdr[i].sh_size;
            return 0;
        }
    }
    FUADXSHELL_LOG_E("Section %s wasn't found in shared library", section);
    return -ENOSECT;
}

ATTRIBUTES(always_inline, used)
static inline void rotate_init(ctx_t *ctx, const uint8_t *key)
{
    uint8_t j = 0;
    uint8_t tmp;

    for (int i = 0; i < 256; i++)
        ctx->S[i] = (uint8_t)i;
    ctx->i = 0;
    ctx->j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (uint8_t)(j + ctx->S[i] + key[i % 32]);
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
}

ATTRIBUTES(always_inline, unused)
void rotate(const char *input, char *output, size_t length)
{
    ATTRIBUTES(section(".rodata_ext")) static const char master[] = "d78548a4bf6b15eeff09e839236186873b44c1d9224968613c5d6823701c99d5";
    static char masterKey[32] = { 0 };

    ctx_t ctx;
    uint8_t tmp;
    uint8_t rnd;

    hex_to_bin(master, masterKey, 32);
    rotate_init(&ctx, (uint8_t *)masterKey);
    for (size_t i = 0; i < length; i++)
    {
        ctx.i = (uint8_t)(ctx.i + 1);
        ctx.j = (uint8_t)(ctx.j + ctx.S[ctx.i]);
        tmp = ctx.S[ctx.i];
        ctx.S[ctx.i] = ctx.S[ctx.j];
        ctx.S[ctx.j] = tmp;
        rnd = ctx.S[(uint8_t)(ctx.S[ctx.i] + ctx.S[ctx.j])];
        output[i] = (char)(input[i] ^ rnd);
    }
}

ATTRIBUTES(always_inline, overloadable, used)
int unzip(const char *path, const char *needle, void **buffer, size_t *bufferSize)
{
    void *apkFile = NULL;
    mz_zip_file *fileInfo = NULL;
    char insidePath[512] = { 0 };
    int minizipError = MZ_OK;
    int written;

    if (!path || !needle)
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for unzip operation: %p - %p", path, needle);
        return -EINVAL;
    }
    written = snprintf(insidePath, sizeof(insidePath), "%s%s", "assets/", needle);
    if (written < 0 || (size_t)written >= sizeof(insidePath))
    {
        FUADXSHELL_LOG_E("Error while formatting inside path for unzip operation");
        return -ENAMETOOLONG;
    }
    apkFile = mz_zip_reader_create();
    minizipError = mz_zip_reader_open_file(apkFile, path);
    if (minizipError != MZ_OK)
    {
        FUADXSHELL_LOG_E("Error while opening zip file %s: %d", path, minizipError);
        goto error;
    }
    minizipError = mz_zip_reader_locate_entry(apkFile, insidePath, 0);
    if (minizipError < 0)
    {
        FUADXSHELL_LOG_E("Error while locating entry %s in zip file %s: %d", insidePath, path, minizipError);
        goto error;
    }
    minizipError = mz_zip_reader_entry_get_info(apkFile, &fileInfo);
    if (minizipError != MZ_OK || !fileInfo)
    {
        FUADXSHELL_LOG_E("Error while getting entry info for %s in zip file %s: %d", insidePath, path, minizipError);
        goto error;
    }
    if (fileInfo->uncompressed_size == 0)
    {
        FUADXSHELL_LOG_E("Entry %s in zip file %s is empty", insidePath, path);
        mz_zip_reader_close(apkFile);
        mz_zip_reader_delete(&apkFile);
        return -ENOENT;
    }
    (*buffer) = malloc(fileInfo->uncompressed_size);
    if (!(*buffer))
    {
        FUADXSHELL_LOG_E("Error while allocating memory for %s: %d", insidePath, minizipError);
        goto error;
    }
    if ((minizipError = mz_zip_reader_entry_open(apkFile) != MZ_OK) ||
        (minizipError = mz_zip_reader_entry_read(apkFile, (*buffer),
                                                 (int)fileInfo->uncompressed_size)) < 0)
    {
        FUADXSHELL_LOG_E("Error while reading entry %s from zip file %s: %d", insidePath, path, minizipError);
        free(buffer);
        goto error;
    }
    (*bufferSize) = fileInfo->uncompressed_size;
    mz_zip_reader_entry_close(apkFile);
    mz_zip_reader_close(apkFile);
    mz_zip_reader_delete(&apkFile);
    FUADXSHELL_LOG_D("Unzipped %s from %s successfully", insidePath, path);
    return MZ_OK;
    error:
        FUADXSHELL_LOG_E("Error during unzip operation: %d", minizipError);
        mz_zip_reader_close(apkFile);
        mz_zip_reader_delete(&apkFile);
        return minizipError;
}

ATTRIBUTES(always_inline, overloadable, used)
inline int unzip(const char *path, const char *needle, so_info_t *soinfo)
{
    void *apkFile = NULL;
    mz_zip_file *fileInfo = NULL;
    char insidePath[512] = { 0 };
    int minizipError = MZ_OK;
    int written;

    if (!path || !needle || !soinfo)
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for unzip operation: %p - %p - %p", path, needle, soinfo);
        return -EINVAL;
    }
    written = snprintf(insidePath, sizeof(insidePath), "%s%s", LIB_SUBDIR, needle);
    if (written < 0 || (size_t)written >= sizeof(insidePath))
    {
        FUADXSHELL_LOG_E("Error while formatting inside path for unzip operation");
        return -ENAMETOOLONG;
    }
    apkFile = mz_zip_reader_create();
    minizipError = mz_zip_reader_open_file(apkFile, path);
    if (minizipError != MZ_OK)
    {
        FUADXSHELL_LOG_E("Error while opening zip file %s: %d", path, minizipError);
        goto error;
    }
    minizipError = mz_zip_reader_locate_entry(apkFile, insidePath, 0);
    if (minizipError < 0)
    {
        FUADXSHELL_LOG_E("Error while locating entry %s in zip file %s: %d", insidePath, path, minizipError);
        goto error;
    }
    minizipError = mz_zip_reader_entry_get_info(apkFile, &fileInfo);
    if (minizipError != MZ_OK || !fileInfo)
    {
        FUADXSHELL_LOG_E("Error while getting entry info for %s in zip file %s: %d", insidePath, path, minizipError);
        goto error;
    }
    soinfo->loadedMemSize = fileInfo->uncompressed_size;
    soinfo->loadedMem = malloc(fileInfo->uncompressed_size);
    if (!soinfo->loadedMem)
    {
        FUADXSHELL_LOG_E("Error while allocating memory for %s: %d", insidePath, minizipError);
        goto error;
    }
    if ((minizipError = mz_zip_reader_entry_open(apkFile) != MZ_OK) ||
        (minizipError = mz_zip_reader_entry_read(apkFile, soinfo->loadedMem,
                                                 (int)soinfo->loadedMemSize)) < 0)
    {
        FUADXSHELL_LOG_E("Error while reading entry %s from zip file %s: %d", insidePath, path, minizipError);
        goto error;
    }
    mz_zip_reader_entry_close(apkFile);
    mz_zip_reader_close(apkFile);
    mz_zip_reader_delete(&apkFile);
    return MZ_OK;
    error:
        FUADXSHELL_LOG_E("Error during unzip operation: %d", minizipError);
        mz_zip_reader_close(apkFile);
        mz_zip_reader_delete(&apkFile);
        return minizipError;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
int unzip_files(const char *path)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char needleExt[] = ".dex";
    ATTRIBUTES(section(".rodata_ext"), used) static const char dexName[] = "classes";
    const char *breakChar = NULL;
    char *parentDir = NULL;
    void *buffer = NULL;
    char fileNameEntry[256] = { 0 };
    char outFile[512] = { 0 };
    char fileNameNoExt[256] = { 0 };
    char iv[12] = { 0 };
    char key[32] = { 0 };
    char saltBin[16] = { 0 };
    int fd;
    ssize_t bytesWritten;
    int classesIterator = 1;
    int status = 0;
    unzFile unzipFile;
    unz_file_info64 fileInfo;

    if (!path)
    {
        FUADXSHELL_LOG_E("Invalid path provided for unzip_files operation: %s", path);
        return -EINVAL;
    }
    parentDir = dirname(path);
    unzipFile = unzOpen64(path);
    if (!unzipFile)
    {
        FUADXSHELL_LOG_E("Error while opening zip file %s", path);
        return -ENOENT;
    }
    if (unzGoToFirstFile(unzipFile) != UNZ_OK)
    {
        unzClose(unzipFile);
        return -ENOENT;
    }
    do
    {
        if (unzGetCurrentFileInfo64(unzipFile, &fileInfo, fileNameEntry,
                                    sizeof(fileNameEntry), NULL,
                                    0, NULL, 0) != UNZ_OK)
        {
            status = -ENOENT;
            break;
        }
        breakChar = strrchr(fileNameEntry, '.');
        if (!breakChar || strcasecmp(breakChar, needleExt) != 0)
        {
            FUADXSHELL_LOG_D("Skipping file %s as it is not a dex file", fileNameEntry);
            continue;
        }
        bytesWritten = snprintf(outFile, sizeof(outFile), "%s/%s%d%s", parentDir, dexName, classesIterator++, needleExt);
        if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(outFile))
        {
            FUADXSHELL_LOG_E("Error while formatting output file path for %s", fileNameEntry);
            status = -ENAMETOOLONG;
            break;
        }
        FUADXSHELL_LOG_D("Unzipping file %s to %s", fileNameEntry, outFile);
        if (unzOpenCurrentFilePassword(unzipFile, NULL) != UNZ_OK)
        {
            FUADXSHELL_LOG_E("Error while opening entry %s in zip file %s", fileNameEntry, path);
            status = -EACCES;
            break;
        }
        fd = sys_open(outFile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
        {
            FUADXSHELL_LOG_E("Error while opening file %s for writing after unzipping: %s", outFile, strerror(errno));
            unzCloseCurrentFile(unzipFile);
            status = -errno;
            break;
        }
        buffer = malloc(fileInfo.uncompressed_size + 1);
        if (!buffer)
        {
            FUADXSHELL_LOG_E("Error while allocating memory for file %s: %d", fileNameEntry, errno);
            sys_close(fd);
            unzCloseCurrentFile(unzipFile);
            status = -ENOMEM;
            break;
        }
        if (unzReadCurrentFile(unzipFile, buffer, fileInfo.uncompressed_size) < 0)
        {
            FUADXSHELL_LOG_E("Error while reading entry %s from zip file %s: %d", fileNameEntry, path, errno);
            free(buffer);
            sys_close(fd);
            unzCloseCurrentFile(unzipFile);
            status = -errno;
            break;
        }
        ((char *)buffer)[fileInfo.uncompressed_size] = '\0'; /* Ensure null-termination */
        /* Extract IV */
        memcpy(iv, buffer + fileInfo.uncompressed_size - 12, 12);
        memset(buffer + fileInfo.uncompressed_size - 12, 0, 12);
        /* Get salt and derive key */
        strlcpy(fileNameNoExt, fileNameEntry, (strrchr(fileNameEntry, '.') - fileNameEntry) + 1);
        FUADXSHELL_LOG_D("File name without extension: %s", fileNameNoExt);
        hex_to_bin(fileNameNoExt, saltBin, 16);
        if (kdf(KDF_ARGON2ID, (uint8_t *)key, 32, (const uint8_t *)fileNameNoExt, strlen(fileNameNoExt), (const uint8_t *)saltBin, 16, NULL, 0) < 0)
        {
            FUADXSHELL_LOG_E("Error while deriving key for file %s", fileNameEntry);
            free(buffer);
            buffer = NULL;
            if (__builtin_available(android 34, *))
            {
                memset_explicit(key, 0, sizeof(key));
                memset_explicit(iv, 0, sizeof(iv));
            }
            else
            {
                OPENSSL_cleanse(key, sizeof(key));
                OPENSSL_cleanse(iv, sizeof(iv));
            }
            sys_close(fd);
            unzCloseCurrentFile(unzipFile);
            status = -ENOKEY;
            break;
        }
        FUADXSHELL_LOG_D("KDF was derived successfully");
        /* Decrypt data using ChaCha20Poly1305 */
        if (decrypt_dex(buffer, iv, key, fileInfo.uncompressed_size - 12) < 0)
        {
            FUADXSHELL_LOG_E("Error while decrypting file %s", fileNameEntry);
            free(buffer);
            buffer = NULL;
            if (__builtin_available(android 34, *))
            {
                memset_explicit(key, 0, sizeof(key));
                memset_explicit(iv, 0, sizeof(iv));
            }
            else
            {
                OPENSSL_cleanse(key, sizeof(key));
                OPENSSL_cleanse(iv, sizeof(iv));
            }
            sys_close(fd);
            unzCloseCurrentFile(unzipFile);
            status = -ENODECR;
            break;
        }
        sys_write(fd, buffer, fileInfo.uncompressed_size - 12);
        FUADXSHELL_LOG_D("File %s unzipped and decrypted and written to %s successfully", fileNameEntry, outFile);
        sys_close(fd);
        free(buffer);
        buffer = NULL;
        if (__builtin_available(android 34, *))
        {
            memset_explicit(key, 0, sizeof(key));
            memset_explicit(iv, 0, sizeof(iv));
        }
        else
        {
            OPENSSL_cleanse(key, sizeof(key));
            OPENSSL_cleanse(iv, sizeof(iv));
        }
        unzCloseCurrentFile(unzipFile);
    } while(unzGoToNextFile(unzipFile) == UNZ_OK);
    unzClose(unzipFile);
    return status;
}

ATTRIBUTES(always_inline, section(".text_ext"), used)
inline int decrypt_dex(char *dexBuffer, const char *dexIv, const char *masterKey, size_t size)
{
    EVP_CIPHER_CTX *ctx = NULL;
    char tag[16] = { 0 };
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        FUADXSHELL_LOG_E("Error while creating EVP_CIPHER_CTX: %s", strerror(errno));
        return -ENODECR;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
    {
        FUADXSHELL_LOG_E("Error while initializing encryption context");
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
    {
        FUADXSHELL_LOG_E("Error while setting IV length for encryption context");
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, (const uint8_t *)masterKey, (uint8_t *)dexIv) != 1)
    {
        FUADXSHELL_LOG_E("Error while setting key and IV for encryption context");
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    if (EVP_EncryptUpdate(ctx, (uint8_t *)dexBuffer, &len, (uint8_t *)dexBuffer, (int)size) != 1)
    {
        FUADXSHELL_LOG_E("Error while encrypting dex buffer: %s", strerror(errno));
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    if (EVP_EncryptFinal_ex(ctx, (uint8_t *)(dexBuffer + len), &len) != 1)
    {
        FUADXSHELL_LOG_E("Error while finalizing encryption: %s", strerror(errno));
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag) != 1)
    {
        FUADXSHELL_LOG_E("Error while getting tag from encryption context: %s", strerror(errno));
        EVP_CIPHER_CTX_free(ctx);
        return -ENODECR;
    }
    FUADXSHELL_LOG_D("Dex buffer decrypted successfully with IV: %s and tag: %s", dexIv, tag);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* Properties */
ATTRIBUTES(always_inline, used)
static inline void prop_callback(void *cookie, const char *name, const char *value, ATTRIBUTES(unused) uint32_t serial)
{
    FUADXSHELL_LOG_D("In prop callback: name: %s, value: %s, serial: %u", name, value, serial);
    if (cookie && value)
    {
        FUADXSHELL_LOG_D("Setting property value: %s", value);
        snprintf(cookie, PROP_VALUE_MAX, "%s", value);
    }
    else
        FUADXSHELL_LOG_E("Unable to set property value, buffer or value is NULL");
}

ATTRIBUTES(always_inline, used)
int get_android_prop(const char *name, char *value)
{
    const prop_info *propInfo = NULL;

    if (!name || !value)
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for getting Android property");
        return -EINVAL;
    }
    if (unlikely(android_get_device_api_level() < 26))
    {
        if (__system_property_get(name, value) < 0)
        {
            FUADXSHELL_LOG_E("Unable to get property %s", name);
            return -ENOPROP;
        }
    }
    else
    {
        if (__builtin_available(android 26, *))
        {
            propInfo = __system_property_find(name);
            if (propInfo)
            {
                __system_property_read_callback(propInfo, prop_callback, value);
                FUADXSHELL_LOG_D("Property %s: %s", name, value);
                return 0;
            }
            else
            {
                FUADXSHELL_LOG_E("Property %s not found", name);
                return -ENOPROP;
            }
        }
    }
    return 0; /* Should not reach here */
}

/* File operations */
ATTRIBUTES(always_inline, used)
inline int file_exists(const char *path)
{
    return !access(path, F_OK);
}

ATTRIBUTES(always_inline, used)
ssize_t readline(int fd, char *buffer, size_t size)
{
    char b;
    ssize_t readBytes = 0;
    ssize_t ret;

    if (unlikely(size == 0))
    {
        FUADXSHELL_LOG_E("Buffer size is zero, cannot read line");
        return -EINVAL;
    }
    do
    {
        ret = sys_read(fd, &b, 1);
        if (ret != 1)
        {
            *(buffer + readBytes) = '\0';
            if (!readBytes)
            {
                FUADXSHELL_LOG_E("Error while reading from file descriptor %d: %s", fd, strerror(errno));
                return -EIO;
            }
            else
            {
                FUADXSHELL_LOG_D("End of file reached or error occurred, read %zd bytes", readBytes);
                return readBytes;
            }
        }
        /* Case \n */
        if (b == '\n')
        {
            *(buffer + readBytes) = '\0';
            return readBytes;
        }
        /* Fallback */
        if (readBytes < (ssize_t)(size - 1))
        {
            *(buffer + readBytes) = b;
            readBytes++;
        }
        else
        {
            FUADXSHELL_LOG_E("Buffer overflow, size limit reached: %zu", size);
            break;
        }
    } while(true);
    *(buffer + readBytes) = '\0'; /* Null-terminate the string */
    FUADXSHELL_LOG_D("Read %zd bytes from file descriptor %d", readBytes, fd);
    return readBytes;
}

/* Maps parsing */
ATTRIBUTES(always_inline, used)
int parse_maps(pid_t pid, map_entry_t **entries, size_t *count)
{
    ATTRIBUTES(section(".rodata_ext"), used) static const char mapsFile[] = "/proc/self/maps";
    map_entry_t *mapEntries = NULL;
    map_entry_t *mapEntryTmp = NULL;
    map_entry_t tmpEntry = { 0 };
    char line[LINE_MAX] = { 0 };
    char path[PATH_MAX] = { 0 };
    char dev[16] = { 0 };
    char *tmpLine = NULL;
    ssize_t bytesRead;
    ssize_t bytesWritten = 0;
    size_t mapCount = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;
    int fd;

    if (unlikely(pid < 0))
    {
        FUADXSHELL_LOG_E("Invalid PID provided for parsing maps");
        return -EINVAL;
    }
    bytesWritten += (pid == 0) ? snprintf(path, sizeof(path), "/proc/self/maps") :
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    if (bytesWritten < 0 || bytesWritten >= sizeof(path))
    {
        FUADXSHELL_LOG_E("Error while formatting path for maps file: %s", strerror(errno));
        /* TODO: Add LOG */
        return -ENAMETOOLONG;
    }
    fd = sys_open(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
    {
        FUADXSHELL_LOG_E("Error while opening maps file %s: %s", path, strerror(errno));
        return -errno;
    }
    FUADXSHELL_LOG_D("Opened maps file %s for PID %d", path, pid);
    while ((bytesRead = readline(fd, line, sizeof(line))) > 0)
    {
        memset(&tmpEntry, 0, sizeof(map_entry_t));
        tmpLine = line;
        errno = 0; /* Reset errno before parsing */
        start = strtoul(tmpLine, &tmpLine, 16);
        if (errno)
            continue;
        tmpEntry.start = start;
        if (*tmpLine == '-')
            tmpLine++;
        end = strtoul(tmpLine, &tmpLine, 16);
        tmpEntry.end = end;
        if (errno)
            continue;
        /* Perms */
        while (*tmpLine == ' ')
            tmpLine++;
        memcpy(tmpEntry.permissions, tmpLine, 4);
        tmpEntry.permissions[4] = '\0'; /* Null-terminate the permissions string */
        tmpLine += 4; /* Skip to the next part */
        /* Offset */
        while (*tmpLine == ' ')
            tmpLine++;
        tmpEntry.offset = strtoul(tmpLine, &tmpLine, 16);
        if (errno)
            continue;
        /* Device */
        while (*tmpLine == ' ')
            tmpLine++;
        sscanf(tmpLine, "%15[^ ]", dev);
        if (sscanf(dev, "%x:%x", &tmpEntry.dev_major, &tmpEntry.dev_minor) != 2)
            tmpEntry.dev_major = tmpEntry.dev_minor = 0; /* Default to 0 if parsing fails */
        tmpLine = strchr(tmpLine, ' ');
        if (unlikely(!tmpLine))
            continue;
        /* Inode */
        while (*tmpLine == ' ')
            tmpLine++;
        tmpEntry.inode = strtoull(tmpLine, &tmpLine, 10);
        /* Pathname */
        while (*tmpLine == ' ')
            tmpLine++;
        if (*tmpLine)
        {
            tmpEntry.pathname = strdup(tmpLine);
            if (unlikely(!tmpEntry.pathname))
            {
                FUADXSHELL_LOG_E("Error while allocating memory for pathname: %s", strerror(errno));
                errno = ENOMEM;
                break;
            }
        }
        /* Add entry to the list */
        mapEntryTmp = realloc(mapEntries, (mapCount + 1) * sizeof(map_entry_t));
        if (unlikely(!mapEntryTmp))
        {
            FUADXSHELL_LOG_E("Error while reallocating memory for map entries: %s", strerror(errno));
            free(tmpEntry.pathname);
            errno = ENOMEM;
            break;
        }
        mapEntries = mapEntryTmp;
        mapEntries[mapCount++] = tmpEntry; /* Copy the temporary entry */
    }
    sys_close(fd);
    if (bytesRead < 0 && mapCount == 0)
    {
        FUADXSHELL_LOG_E("Error while reading maps file %s: %s", path, strerror(errno));
        free(mapEntries);
        return -1;
    }
    (*entries) = mapEntries;
    (*count) = mapCount;
    FUADXSHELL_LOG_D("Parsed %zu map entries from %s", mapCount, path);
    return 0; /* Success */
}

ATTRIBUTES(always_inline, used)
void release_parsed_maps(map_entry_t *entries, size_t entriesCount)
{
    if (!entries || entriesCount == 0)
    {
        FUADXSHELL_LOG_E("Invalid entries or count provided for releasing parsed maps");
        return;
    }
    else
    {
        FUADXSHELL_LOG_D("Releasing %zu parsed map entries", entriesCount);
        for (size_t i = 0; i < entriesCount; i++)
        {
            if (entries[i].pathname)
            {
                FUADXSHELL_LOG_D("Freeing pathname %s", entries[i].pathname);
                free(entries[i].pathname);
                entries[i].pathname = NULL;
            }
        }
        free(entries);
        entries = NULL;
    }
}

/* String handling */
ATTRIBUTES(always_inline, used)
char *parse_cmdline(void)
{
    int fd;
    ssize_t bytesRead;
    char buf[4096] = { 0 };

    fd = sys_open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
    {
        FUADXSHELL_LOG_E("Error while opening /proc/self/cmdline: %s", strerror(errno));
        return NULL;
    }
    bytesRead = sys_read(fd, buf, sizeof(buf) - 1);
    if (bytesRead < 0)
    {
        FUADXSHELL_LOG_E("Error while reading /proc/self/cmdline: %s", strerror(errno));
        sys_close(fd);
        return NULL;
    }
    sys_close(fd);
    buf[bytesRead] = '\0'; /* Null-terminate the string */
    FUADXSHELL_LOG_D("Command line: %s", buf);
    return strdup(buf); /* Return a copy of the command line */
}

ATTRIBUTES(always_inline, used)
char *skip_line(char *ptr)
{
    while (*ptr && *ptr != '\n')
        ptr++;
    return ptr;
}

ATTRIBUTES(always_inline, used)
char *skip_delimiters(char *ptr)
{
    while (*ptr && (isspace((unsigned char)*ptr) || *ptr == ','))
        ++ptr;
    return ptr;
}

/* OpenSSL Crypto */
ATTRIBUTES(always_inline, used)
int kdf(kdf_type_t kdfType, uint8_t *output, size_t outputSize, const uint8_t *pwd, size_t pwdSize,
        const uint8_t *salt, size_t saltSize, const uint8_t *info, size_t infoSize)
{
    int ret = -1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[16];
    OSSL_PARAM *pargs = params;
    uint32_t tCost;
    uint32_t mCost;
    uint32_t lanes;
    const char *mode = NULL;
    const char *digest = NULL;

    switch (kdfType)
    {
        case KDF_ARGON2ID:
            tCost = 3;
            mCost = 12 * 1024;
            lanes = 1;
            mode = "id";
            digest = "sha256";
            kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
            if (!kdf)
            {
                FUADXSHELL_LOG_E("Failed to fetch KDF for ARGON2");
                return -EBADKDF;
            }
            ctx = EVP_KDF_CTX_new(kdf);
            if (!ctx)
            {
                FUADXSHELL_LOG_E("Failed to create KDF context for ARGON2");
                EVP_KDF_free(kdf);
                return -EBADKDF;
            }
            *pargs++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (char *)pwd, pwdSize);
            *pargs++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (char *)salt, saltSize);
            *pargs++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &tCost);
            *pargs++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mCost);
            *pargs++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
            *pargs++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char *)mode, 0);
            *pargs++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)digest, 0);
            break;
        case KDF_PBKDF2:
            FUADXSHELL_LOG_E("KDF_PBKDF2 is not implemented yet");
            return -ENOKDF; /* -ENOKDF */
        case KDF_HKDF:
            FUADXSHELL_LOG_E("KDF_HKDF is not implemented yet");
            return -ENOKDF; /* -ENOKDF */
        case KDF_SCRYPT:
            FUADXSHELL_LOG_E("KDF_SCRYPT is not implemented yet");
            return -ENOKDF; /* -ENOKDF */
        default:
            FUADXSHELL_LOG_E("Unsupported KDF type: %d", kdfType);
            return -ENOKDF; /* -ENOKDF */
    }
    (*pargs) = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(ctx, params) <= 0)
    {
        FUADXSHELL_LOG_E("Failed to set parameters for KDF");
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
        return -EBADKDF;
    }
    if (EVP_KDF_derive(ctx, output, outputSize, params) <= 0)
    {
        FUADXSHELL_LOG_E("Failed to derive key using KDF");
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
        return -EBADKDF;
    }
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return 0; /* Placeholder for KDF implementation */
}

ATTRIBUTES(always_inline, used)
int encrypt(encryption_type_t encryptionType, const uint8_t *key, size_t keySize, const uint8_t *iv,
            size_t ivSize, const uint8_t *aad, size_t aadSize, const uint8_t *plaintext, size_t plaintextSize,
            uint8_t *ciphertext, uint8_t *tag, size_t tagSize)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    return 0; /* Placeholder for encryption implementation */
}

ATTRIBUTES(always_inline, used)
int decrypt(encryption_type_t encryptionType, const uint8_t *key, size_t keySize, const uint8_t *iv,
            size_t ivSize, const uint8_t *aad, size_t aadSize, const uint8_t *ciphertext, size_t ciphertextSize,
            const uint8_t *tag, size_t tagSize, uint8_t *plaintext)
{
    return 0; /* Placeholder for decryption implementation */
}

ATTRIBUTES(always_inline, used)
int digest(digest_type_t digestType, const uint8_t *key, uint8_t *digest, size_t digestSize)
{
    return 0; /* Placeholder for digest implementation */
}

ATTRIBUTES(always_inline, used)
int mac(mac_type_t macType, const uint8_t * key, size_t keySize, const uint8_t *data, size_t dataSize,
        uint8_t *output, size_t outputSize)
{
    return 0; /* Placeholder for MAC implementation */
}


ATTRIBUTES(always_inline, used)
int sign(signature_type_t signatureType, digest_type_t digestType, EVP_PKEY *privateKey, const uint8_t *data,
         size_t dataSize, uint8_t *signature, size_t signatureSize)
{
    return 0; /* Placeholder for signing implementation */
}



ATTRIBUTES(always_inline, used)
int verify(signature_type_t signatureType, digest_type_t digestType, EVP_PKEY *publicKey, const uint8_t *data,
           size_t dataSize, const uint8_t *signature, size_t signatureSize)
{
    return 0; /* Placeholder for verification implementation */
}

/* Encoding */
ATTRIBUTES(always_inline, used)
void bin_to_hex(const char *input, char *output, size_t size)
{
    const char hex[] = "0123456789abcdef";

    if (!input || !output || size == 0)
    {
        FUADXSHELL_LOG_E("Invalid input, output or size provided for %s", __func__);
        return;
    }
    for (size_t i = 0; i < size; i++)
    {
        output[i * 2 + 0] = hex[(input[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex[input[i] & 0x0F];
    }
    output[size * 2] = '\0'; /* Null-terminate the output string */
}

ATTRIBUTES(always_inline, used)
void hex_to_bin(const char *input, char *output, size_t size)
{
    char hi;
    char lo;
    int hi_val;
    int lo_val;

    FUADXSHELL_LOG_D("Converting hex to binary %s with input size %zu", input, size);
    if (!input || !output || size == 0)
    {
        FUADXSHELL_LOG_E("Invalid input, output or size provided for %s", __func__);
        return;
    }
    for (size_t i = 0; i < size; i++)
    {
        hi = input[2 * i];
        lo = input[2 * i + 1];

        if (hi >= '0' && hi <= '9')
            hi_val = hi - '0';
        else if (hi >= 'A' && hi <= 'F')
            hi_val = hi - 'A' + 10;
        else if (hi >= 'a' && hi <= 'f')
            hi_val = hi - 'a' + 10;
        else
        {
            FUADXSHELL_LOG_E("%s: invalid hex digit '%c' at pos %zu", __func__, hi, 2 * i);
            return;
        }
        if (lo >= '0' && lo <= '9')
            lo_val = lo - '0';
        else if (lo >= 'A' && lo <= 'F')
            lo_val = lo - 'A' + 10;
        else if (lo >= 'a' && lo <= 'f')
            lo_val = lo - 'a' + 10;
        else
        {
            FUADXSHELL_LOG_E("%s: invalid hex digit '%c' at pos %zu", __func__, lo, 2 * i + 1);
            return;
        }
        output[i] = (char)((hi_val << 4) | lo_val);
    }
}

/* RAII */
ATTRIBUTES(always_inline, used)
void raii_fd(int *fd)
{
    if (fd && (*fd) >= 0)
    {
        FUADXSHELL_LOG_D("Closing file descriptor %d", (*fd));
        sys_close((*fd));
        (*fd) = -1;
    }
    else
        FUADXSHELL_LOG_E("Invalid file descriptor provided for cleanup");
}

ATTRIBUTES(always_inline, used)
void raii_mallocd(void **ptr)
{
    if (likely((*ptr)))
    {
        FUADXSHELL_LOG_D("Freeing allocated memory at %p", (*ptr));
        free((*ptr));
        (*ptr) = NULL;
    }
    else
        FUADXSHELL_LOG_E("Invalid pointer provided for cleanup");
}

ATTRIBUTES(always_inline, used)
void raii_so_info_t(so_info_t *info)
{
    FUADXSHELL_LOG_D("Cleaning up so_info_t resources");
    if (info)
    {
        for (int i = 0; i < info->resource.count; i++)
        {
            switch (info->resource.resources[i].type) {
                case CT_NONE:
                    FUADXSHELL_LOG_D("No cleanup needed for resource %d", i);
                    break;
                case CT_MALLOC:
                    FUADXSHELL_LOG_D("Cleaning up malloc resource %d at %p", i, info->resource.resources[i].ptr);
                    if (info->resource.resources[i].ptr)
                    {
                        free(info->resource.resources[i].ptr);
                        info->resource.resources[i].ptr = NULL;
                    }
                    break;
                case CT_MMAP:
                    FUADXSHELL_LOG_D("Cleaning up mmap resource %d at %p", i, info->resource.resources[i].ptr);
                    if (info->resource.resources[i].ptr)
                    {
                        sys_munmap(info->resource.resources[i].ptr, info->resource.resources[i].size);
                        info->resource.resources[i].ptr = NULL;
                    }
                    break;
                case CT_ZEROD:
                    FUADXSHELL_LOG_D("Cleaning up zero'd resource %d at %p", i, info->resource.resources[i].ptr);
                    if (info->resource.resources[i].ptr)
                    {
                        (void)memset(info->resource.resources[i].ptr, 0,
                                     info->resource.resources[i].size == -1 ?
                                        1 : info->resource.resources[i].size);
                        info->resource.resources[i].ptr = NULL;
                    }
                    break;
                case CT_FD:
                    FUADXSHELL_LOG_D("Cleaning up file descriptor resource %d at %p", i, &info->resource.resources[i].fd);
                    if (info->resource.resources[i].fd >= 0)
                    {
                        sys_close(info->resource.resources[i].fd);
                        info->resource.resources[i].fd = -1;
                    }
                    break;
                case CT_SOCKET:
                    FUADXSHELL_LOG_D("Cleaning up socket resource %d at %p", i, &info->resource.resources[i].fd);
                    if (info->resource.resources[i].fd >= 0)
                    {
                        sys_close(info->resource.resources[i].fd);
                        info->resource.resources[i].fd = -1;
                    }
                    break;
                case CT_NULLD:
                    FUADXSHELL_LOG_D("Cleaning up null resource %d at %p", i, info->resource.resources[i].ptr);
                    if (info->resource.resources[i].ptr)
                        info->resource.resources[i].ptr = NULL;
                    break;
            }
        }
    }
    else
    {
        FUADXSHELL_LOG_E("Invalid so_info_t pointer provided for cleanup");
        return;
    }
}