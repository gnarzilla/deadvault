/**
 * pbkdf2_shim.c - PBKDF2-SHA256 key derivation for vault.deadlight
 * 
 * Pure C implementation, public domain reference code.
 * RFC 2898 compliant, no external dependencies.
 * 
 * ~280 LOC: SHA256 (~200) + PBKDF2 (~80)
 */

#include "pbkdf2_shim.h"
#include <string.h>
#include <stdint.h>
#include <assert.h>

/* ============================================================================
 * SHA256 Implementation (FIPS 180-4)
 * ============================================================================ */

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buf[64];
} sha256_ctx_t;

/* SHA256 constants */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)       (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)      (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    /* Copy block into first 16 words (big-endian) */
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    }

    /* Extend the first 16 words into remaining 48 words */
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    /* Compression function main loop */
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Add the compressed chunk to the current hash value */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t index = (ctx->count / 8) % SHA256_BLOCK_SIZE;
    ctx->count += (len * 8);

    size_t partlen = SHA256_BLOCK_SIZE - index;
    size_t i = 0;

    if (len >= partlen) {
        memcpy(&ctx->buf[index], data, partlen);
        sha256_transform(ctx, ctx->buf);

        for (i = partlen; i + SHA256_BLOCK_SIZE <= len; i += SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, &data[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&ctx->buf[index], &data[i], len - i);
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]) {
    uint8_t bits[8];
    uint32_t index = (ctx->count / 8) % SHA256_BLOCK_SIZE;
    uint32_t padlen = (index < 56) ? (56 - index) : (120 - index);

    /* Encode count in big-endian */
    for (int i = 0; i < 8; ++i) {
        bits[i] = (ctx->count >> (56 - i * 8)) & 0xff;
    }

    /* Padding: append 0x80 then zeros then length */
    sha256_update(ctx, (const uint8_t *)"\x80", 1);
    while (padlen-- > 1) {
        sha256_update(ctx, (const uint8_t *)"\x00", 1);
    }
    sha256_update(ctx, bits, 8);

    /* Produce the final hash value (big-endian) */
    for (int i = 0; i < 8; ++i) {
        digest[i*4]     = (ctx->state[i] >> 24) & 0xff;
        digest[i*4 + 1] = (ctx->state[i] >> 16) & 0xff;
        digest[i*4 + 2] = (ctx->state[i] >> 8) & 0xff;
        digest[i*4 + 3] = (ctx->state[i]) & 0xff;
    }
}

/* ============================================================================
 * HMAC-SHA256
 * ============================================================================ */

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t digest[32]) {
    sha256_ctx_t ctx;
    uint8_t k_ipad[64], k_opad[64];

    /* If key is longer than block size, hash it first */
    if (key_len > 64) {
        sha256_ctx_t key_ctx;
        sha256_init(&key_ctx);
        sha256_update(&key_ctx, key, key_len);
        uint8_t key_hash[32];
        sha256_final(&key_ctx, key_hash);
        key = key_hash;
        key_len = 32;
    }

    /* XOR key with ipad and opad constants */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner hash: SHA256(K_ipad || data) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    uint8_t inner[32];
    sha256_final(&ctx, inner);

    /* Outer hash: SHA256(K_opad || inner) */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, digest);

    /* Secure wipe temporary buffers */
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memset(inner, 0, 32);
}

/* ============================================================================
 * PBKDF2-SHA256 (RFC 2898)
 * ============================================================================ */

int vault_derive_key_pbkdf2_sha256(
    const char *password,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t out_key[VAULT_KEY_LEN]) {

    if (!password || !salt || !out_key || iterations == 0 || salt_len == 0) {
        return -1;
    }

    /* Get password length (null-terminated string) */
    size_t password_len = strlen(password);

    uint8_t U[32], T[32];
    uint32_t block_index = 1;
    size_t offset = 0;

    /* Generate output key in 32-byte blocks */
    while (offset < VAULT_KEY_LEN) {
        size_t copy_len = (VAULT_KEY_LEN - offset < 32) ? (VAULT_KEY_LEN - offset) : 32;

        /* U₁ = HMAC-SHA256(password, salt || block_index) */
        {
            uint8_t salt_block[VAULT_SALT_LEN + 4];
            assert(salt_len == VAULT_SALT_LEN);
            memcpy(salt_block, salt, salt_len);
            
            /* Encode block_index as big-endian 4-byte integer */
            salt_block[salt_len + 0] = (block_index >> 24) & 0xff;
            salt_block[salt_len + 1] = (block_index >> 16) & 0xff;
            salt_block[salt_len + 2] = (block_index >> 8) & 0xff;
            salt_block[salt_len + 3] = block_index & 0xff;

            hmac_sha256((const uint8_t *)password, password_len, 
                       salt_block, salt_len + 4, U);
        }

        /* T = U₁ */
        memcpy(T, U, 32);

        /* Uᵢ = HMAC-SHA256(password, Uᵢ₋₁) for i = 2 to iterations */
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256((const uint8_t *)password, password_len, U, 32, U);
            
            /* T = T XOR U */
            for (int j = 0; j < 32; j++) {
                T[j] ^= U[j];
            }
        }

        /* Copy block to output */
        memcpy(&out_key[offset], T, copy_len);
        offset += copy_len;
        block_index++;
    }

    /* Secure wipe temporary buffers */
    memset(U, 0, 32);
    memset(T, 0, 32);

    return 0;
}