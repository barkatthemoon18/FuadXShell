#ifndef TWOFISH_H
#define TWOFISH_H

/* Defs include */
#include <defs.h>

/* FuadXShell Utils include */
#include <fuadxshell_utils.h>

#define UINT32_MASK ((((uint32_t)2) << 31) - 1)
#define ROL32(x, n) ((x) << (n) | ((x) & UINT32_MASK) >> (32 - (n)))
#define ROR32(x, n) ROL32((x), 32 - (n))
#define LARGE_Q_TABLE 0
#define SELECT_BYTE_FROM_UINT32_IN_MEMORY 0
#define CPU_IS_BIG_ENDIAN 0
#define BSWAP(x) ((ROL32((x), 8) & 0x00FF00FF) | (ROR((x), 8) & 0xFF00FF00))

#if CPU_IS_BIG_ENDIAN
#define ENDIAN_CNVERT(x) BSWAP(x)
#else
#define ENDIAN_CONVERT(x) (x)
#endif

#if CPU_IS_BIG_ENDIAN
#define BYTE_OFFSET(n) (sizeof(tf_uint32_t) - 1 - (n))
#else
#define BYTE_OFFSET(n) (n)
#endif

#if SELECT_BYTE_FROM_UINT32_IN_MEMORY
#define SELECT_BYTE(X, b) (((tf_byte_t *)(&(X)))[BYTE_OFFSET(b)])
#else
#define SELECT_BYTE(X, b) (((X) >> 8 * (b)) & 0xFF)
#endif

#define b0(X) SELECT_BYTE((X), 0)
#define b1(X) SELECT_BYTE((X), 1)
#define b2(X) SELECT_BYTE((X), 2)
#define b3(X) SELECT_BYTE((X), 3)

#if CONVER_USING_CASTS
#define GET32(p) ENDIAN_CONVERT(*((tf_uint32_t *)(p)))
	#define PUT32(v, p) *((tf_uint32_t *)(p)) = ENDIAN_CONVERT(v)
#else
#define GET32(p) ((uint32_t)((p)[0]) | (uint32_t)((p)[1]) << 8 | (uint32_t)((p)[2]) << 16 | (uint32_t)((p)[3]) << 24)
#define PUT32(v, p) (p)[0] = (uint8_t)(((v)) & 0xFF); \
    	                (p)[1] = (uint8_t)(((v) >>  8) & 0xFF); \
        	            (p)[2] = (uint8_t)(((v) >> 16) & 0xFF); \
            	        (p)[3] = (uint8_t)(((v) >> 24) & 0xFF)
#endif

#define ROR4BY1(x) (((x) >> 1) | (((x) << 3) & 0x8))

#define q0 qTable[0]
#define q1 qTable[1]

#define H02(y, L)  mdsTable[0][q0[q0[y] ^ (L)[8]] ^ (L)[0]]
#define H12(y, L)  mdsTable[1][q0[q1[y] ^ (L)[9]] ^ (L)[1]]
#define H22(y, L)  mdsTable[2][q1[q0[y] ^ (L)[10]] ^ (L)[2]]
#define H32(y, L)  mdsTable[3][q1[q1[y] ^ (L)[11]] ^ (L)[3]]
#define H03(y, L)  H02(q1[y] ^ (L)[16], L)
#define H13(y, L)  H12(q1[y] ^ (L)[17], L)
#define H23(y, L)  H22(q0[y] ^ (L)[18], L)
#define H33(y, L)  H32(q0[y] ^ (L)[19], L)
#define H04(y, L)  H03(q1[y] ^ (L)[24], L)
#define H14(y, L)  H13(q0[y] ^ (L)[25], L)
#define H24(y, L)  H23(q0[y] ^ (L)[26], L)
#define H34(y, L)  H33(q1[y] ^ (L)[27], L)

#define g0(X, xkey) ((xkey)->s[0][b0(X)] ^ (xkey)->s[1][b1(X)] ^ (xkey)->s[2][b2(X)] ^ (xkey)->s[3][b3(X)])
#define g1(X, xkey) ((xkey)->s[0][b3(X)] ^ (xkey)->s[1][b0(X)] ^ (xkey)->s[2][b1(X)] ^ (xkey)->s[3][b2(X)])

#define ENCRYPT_RND(A, B, C, D, T0, T1, xkey, r) \
    (T0) = g0(A, xkey); \
    (T1) = g1(B, xkey); \
    (C) ^= (T0) + (T1) + (xkey)->K[8 + 2 * (r)]; \
    (C) = ROR32(C, 1); \
    (D) = ROL32(D, 1); \
    (D) ^= (T0) + 2 * (T1) + (xkey)->K[8 + 2 * (r) + 1]

#define ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, r) \
    ENCRYPT_RND(A, B, C, D, T0, T1, xkey, 2 * (r)); \
    ENCRYPT_RND(C, D, A, B, T0, T1, xkey, 2 * (r) + 1)

#define ENCRYPT(A, B, C, D, T0, T1, xkey) \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 0); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 1); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 2); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 3); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 4); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 5); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 6); \
    ENCRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 7)

#define DECRYPT_RND(A, B, C, D, T0, T1, xkey, r) \
    (T0) = g0(A, xkey); \
    (T1) = g1(B, xkey); \
    (C) = ROL32(C, 1); \
    (C) ^= (T0) + (T1) + (xkey)->K[8 + 2 * (r)]; \
    (D) ^= (T0) + 2 * (T1) + (xkey)->K[8 + 2 * (r) + 1]; \
    (D) = ROR32(D, 1)

#define DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, r) \
    DECRYPT_RND(A, B, C, D, T0, T1, xkey, 2 * (r) + 1); \
    DECRYPT_RND(C, D, A, B, T0, T1, xkey, 2 * (r))

#define DECRYPT(A, B, C, D, T0, T1, xkey) \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 7); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 6); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 5); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 4); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 3); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 2); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 1); \
    DECRYPT_CYCLE(A, B, C, D, T0, T1, xkey, 0)

#define GET_INPUT(src, A, B, C, D, xkey, koff) \
    A = GET32(src) ^ (xkey)->K[koff]; \
    (B) = GET32((src) + 4) ^ (xkey)->K[1 + (koff)]; \
    (C) = GET32((src) + 8) ^ (xkey)->K[2 + (koff)]; \
    (D) = GET32((src) + 12) ^ (xkey)->K[3 + (koff)]

#define PUT_OUTPUT(A, B, C, D, dst, xkey, koff) \
    A ^= (xkey)->K[koff]; \
    (B) ^= (xkey)->K[1 + (koff)]; \
    (C) ^= (xkey)->K[2 + (koff)]; \
    (D) ^= (xkey)->K[3 + (koff)]; \
    PUT32(A, dst); \
    PUT32(B, (dst) + 4); \
    PUT32(C, (dst) + 8); \
    PUT32(D, (dst) + 12);

#if LARGE_Q_TABLE
    typedef uint32_t qtype_t;
#else
    typedef uint8_t qtype_t;
#endif

typedef struct tf_key_t
{
    uint32_t s[4][256];
    uint32_t K[40];
} tf_key_t;

typedef struct tf_ctx_t
{
    uint8_t iv[16];
    tf_key_t key;
} tf_ctx_t;

/* Supportive function declarations */
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void init_q_boxes(void);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void init_mds_tables(void);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void make_q_table(uint8_t [4][16], qtype_t [256]);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline uint32_t h(int, uint8_t *, int);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void fill_boxes(uint8_t *, int, tf_key_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_first_init(void);
/* Functions */
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_init(void);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_prep_key(uint8_t *, int, tf_key_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_enc_blk(tf_key_t *, uint8_t *, uint8_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_dec_blk(tf_key_t *, uint8_t *, uint8_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) static inline void tf_setup(tf_ctx_t *, uint8_t *, uint8_t *);
ATTRIBUTES(always_inline, section(".text_ext"), used) extern inline ssize_t tf_enc(tf_ctx_t *, uint8_t *, uint8_t *, uint8_t *, size_t);
ATTRIBUTES(always_inline, section(".text_ext"), used) extern inline ssize_t tf_dec(tf_ctx_t *, uint8_t *, uint8_t *, uint8_t *, size_t);

#endif /* TWOFISH_H */