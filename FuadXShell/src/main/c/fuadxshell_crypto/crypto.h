#ifndef CRYPTO_H
#define CRYPTO_H

/* Default includes */
#include <pthread.h>

/* Defs */
#include <defs.h>

/* SHA-2 Macros */
#define GET_UINT32(n,b,i) \
    {                                          \
        (n) = ((uint32_t) (b)[(i)] << 24)      \
            | ((uint32_t) (b)[(i) + 1] << 16)  \
            | ((uint32_t) (b)[(i) + 2] <<  8)  \
            | ((uint32_t) (b)[(i) + 3]);       \
    }
#define PUT_UINT32(n,b,i) \
    {                                               \
        (b)[(i)] = (uint8_t) ((n) >> 24);       \
        (b)[(i) + 1] = (uint8_t) ((n) >> 16);       \
        (b)[(i) + 2] = (uint8_t) ((n) >> 8);       \
        (b)[(i) + 3] = (uint8_t) ((n));       \
    }
#define SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))
#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))
#define R_SHA2(t) (W[t] = S1(W[t -  2]) + W[t -  7] + S0(W[t - 15]) + W[t - 16])
#define P_SHA2(a,b,c,d,e,f,g,h,x,K) \
    { \
        tmp1 = h + S3(e) + F1(e,f,g) + K + x; \
        tmp2 = S2(a) + F0(a,b,c); \
        d += tmp1; \
        h = tmp1 + tmp2; \
    }

/* Struct that holds the SHA-2 context */
typedef struct sha2_ctx_t sha2_ctx_t;

/* Function declarations */
ATTRIBUTES(always_inline, used) static inline void sha256_start(sha2_ctx_t *);
ATTRIBUTES(always_inline, used) static inline void sha256_process(sha2_ctx_t *, const uint8_t *);
ATTRIBUTES(always_inline, used) static inline void sha256_update(sha2_ctx_t *, const uint8_t *, uint32_t);
ATTRIBUTES(always_inline, used) static inline void sha256_finish(sha2_ctx_t *, uint8_t *);
ATTRIBUTES(always_inline, used) void sha256(const uint8_t *, uint32_t, uint8_t *);

#endif /* CRYPTO_H */