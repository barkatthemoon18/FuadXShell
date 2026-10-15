#ifndef AES_WB_H
#define AES_WB_H

/* Defs */
#include <defs.h>

/* FuadXShell Utils includes */
#include <fuadxshell_utils.h>

/* AES internal includes */
#include <aes_internal.h>

/*
ATTRIBUTES(always_inline, used) int wb_encrypt(const uint8_t *, size_t, uint8_t *);
ATTRIBUTES(always_inline, used) int wb_decrypt(const uint8_t *, size_t, uint8_t *);
*/
ATTRIBUTES(always_inline, used) int wb_encrypt(uint8_t *, size_t);
ATTRIBUTES(always_inline, used) int wb_decrypt(uint8_t *, size_t);

#endif /* AES_WB_H */