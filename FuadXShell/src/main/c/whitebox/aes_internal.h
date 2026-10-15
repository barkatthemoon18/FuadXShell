#ifndef AES_INTERNAL_H
#define AES_INTERNAL_H

/* Default includes */
#include <defs.h>

/* FuadXShell Utils includes */
#include <fuadxshell_utils.h>

/* Macros */
#define ROUNDS 14
#define TY_BOXES_DEF "ty_boxes"
#define TBOXES_LAST_DEF "tboxes_last"
#define MBL_DEF "mbl"
#define TY_BOXES_COUNT ((ROUNDS - 1) * 16 * 256)
#define TBOXES_LAST_COUNT (16 * 256)
#define MBL_COUNT ((ROUNDS - 1) * 16 * 256)
#define AES_PRECOMPUTED_INITIALIZED (2 << 20)

typedef enum
{
    NONE = 0,
    TY = 1,
    LAST = 2,
    MBL = 3
} tables_type_t;

ATTRIBUTES(always_inline, used) static inline int parse_tables_dat(void *, size_t);
ATTRIBUTES(always_inline, used) static inline void shift_rows(uint8_t [16]);
ATTRIBUTES(always_inline, used) int precompute(void);
ATTRIBUTES(always_inline, used) void aes(uint8_t [16]);

extern uint8_t xor[ROUNDS - 1][96][16][16];
extern uint8_t iv[33];
extern uint8_t tboxes_last[16][256];
extern uint32_t ty_boxes[ROUNDS - 1][16][256];
extern uint32_t mbl[ROUNDS - 1][16][256];

#endif /* AES_INTERNAL_H */