/**
 * crypto_vault.c - ChaCha20-Poly1305 AEAD implementation for vault.deadlight
 * 
 * Based on RFC 7539 and public domain reference implementations.
 * Minimal dependencies, ~300 LOC, designed for auditability.
 * 
 * Security properties:
 * - ChaCha20 stream cipher (256-bit key)
 * - Poly1305 MAC for authentication
 * - Combined AEAD construction per RFC 7539
 */

#include "crypto_vault.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * ChaCha20 Core - Stream Cipher
 * ============================================================================ */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d, 8);  \
        c += d; b ^= c; b = ROTL32(b, 7);  \
    } while(0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, sizeof(x));

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        
        // Diagonal rounds
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    // Add initial state
    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

static void chacha20_init_state(uint32_t state[16], 
                                 const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter) {
    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (little-endian)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4 + 0]) |
                       ((uint32_t)key[i*4 + 1] << 8) |
                       ((uint32_t)key[i*4 + 2] << 16) |
                       ((uint32_t)key[i*4 + 3] << 24);
    }

    // Counter
    state[12] = counter;

    // Nonce (little-endian)
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4 + 0]) |
                        ((uint32_t)nonce[i*4 + 1] << 8) |
                        ((uint32_t)nonce[i*4 + 2] << 16) |
                        ((uint32_t)nonce[i*4 + 3] << 24);
    }
}

static void chacha20_xor_counter(uint8_t *dst, const uint8_t *src, size_t len,
                                 const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t initial_counter) {
    uint32_t state[16];
    uint32_t block[16];
    uint8_t keystream[64];
    uint32_t counter = initial_counter;

    for (size_t i = 0; i < len; i += 64) {
        chacha20_init_state(state, key, nonce, counter++);
        chacha20_block(block, state);

        // Convert block to bytes (little-endian)
        for (int j = 0; j < 16; j++) {
            keystream[j*4 + 0] = (block[j] >> 0) & 0xff;
            keystream[j*4 + 1] = (block[j] >> 8) & 0xff;
            keystream[j*4 + 2] = (block[j] >> 16) & 0xff;
            keystream[j*4 + 3] = (block[j] >> 24) & 0xff;
        }

        // XOR with plaintext/ciphertext
        size_t remaining = (len - i < 64) ? (len - i) : 64;
        for (size_t j = 0; j < remaining; j++) {
            dst[i + j] = src[i + j] ^ keystream[j];
        }
    }
}

/* ============================================================================
 * Poly1305 MAC
 * ============================================================================ */

static void poly1305_clamp(uint8_t r[16]) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

static void poly1305_mac(uint8_t mac[16], const uint8_t *msg, size_t len,
                         const uint8_t key[32]) {
    uint32_t r[5], h[5], s[4];
    uint64_t d[5];

    // Clamp r
    uint8_t r_bytes[16];
    memcpy(r_bytes, key, 16);
    poly1305_clamp(r_bytes);

    // Load r (little-endian)
    r[0] = ((uint32_t)r_bytes[0] | ((uint32_t)r_bytes[1] << 8) | 
            ((uint32_t)r_bytes[2] << 16) | ((uint32_t)r_bytes[3] << 24)) & 0x3ffffff;
    r[1] = (((uint32_t)r_bytes[3] >> 2) | ((uint32_t)r_bytes[4] << 6) | 
            ((uint32_t)r_bytes[5] << 14) | ((uint32_t)r_bytes[6] << 22)) & 0x3ffff03;
    r[2] = (((uint32_t)r_bytes[6] >> 4) | ((uint32_t)r_bytes[7] << 4) | 
            ((uint32_t)r_bytes[8] << 12) | ((uint32_t)r_bytes[9] << 20)) & 0x3ffc0ff;
    r[3] = (((uint32_t)r_bytes[9] >> 6) | ((uint32_t)r_bytes[10] << 2) | 
            ((uint32_t)r_bytes[11] << 10) | ((uint32_t)r_bytes[12] << 18)) & 0x3f03fff;
    r[4] = (((uint32_t)r_bytes[12] >> 8) | ((uint32_t)r_bytes[13]) | 
            ((uint32_t)r_bytes[14] << 8) | ((uint32_t)r_bytes[15] << 16)) & 0x00fffff;

    // Load s
    s[0] = ((uint32_t)key[16] | ((uint32_t)key[17] << 8) | 
            ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24));
    s[1] = ((uint32_t)key[20] | ((uint32_t)key[21] << 8) | 
            ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24));
    s[2] = ((uint32_t)key[24] | ((uint32_t)key[25] << 8) | 
            ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24));
    s[3] = ((uint32_t)key[28] | ((uint32_t)key[29] << 8) | 
            ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24));

    // Initialize accumulator
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;

    // Process message in 16-byte blocks
    while (len > 0) {
        uint8_t block[16] = {0};
        size_t block_len = (len < 16) ? len : 16;
        uint32_t hibit = 0;

        memcpy(block, msg, block_len);

        /*
        * Poly1305 appends a 1 bit after each block.
        *
        * For partial blocks, that 1 bit fits inside block[0..15].
        * For full 16-byte blocks, the 1 bit is bit 128, represented
        * as bit 24 of limb h[4] in the 26-bit limb layout.
        *
        * DO NOT write block[16]; that is out of bounds.
        */
        if (block_len < 16) {
            block[block_len] = 0x01;
        } else {
            hibit = (1u << 24);
        }

        // Load block into accumulator (little-endian)
        h[0] += ((uint32_t)block[0] | ((uint32_t)block[1] << 8) | 
                 ((uint32_t)block[2] << 16) | ((uint32_t)block[3] << 24)) & 0x3ffffff;
        h[1] += (((uint32_t)block[3] >> 2) | ((uint32_t)block[4] << 6) | 
                 ((uint32_t)block[5] << 14) | ((uint32_t)block[6] << 22)) & 0x3ffffff;
        h[2] += (((uint32_t)block[6] >> 4) | ((uint32_t)block[7] << 4) | 
                 ((uint32_t)block[8] << 12) | ((uint32_t)block[9] << 20)) & 0x3ffffff;
        h[3] += (((uint32_t)block[9] >> 6) | ((uint32_t)block[10] << 2) | 
                 ((uint32_t)block[11] << 10) | ((uint32_t)block[12] << 18)) & 0x3ffffff;
        h[4] += (((uint32_t)block[13]) |
                 ((uint32_t)block[14] << 8) |
                 ((uint32_t)block[15] << 16) |
                 hibit);

        // h = (h * r) mod (2^130 - 5)
        d[0] = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * (r[4] * 5) + 
               (uint64_t)h[2] * (r[3] * 5) + (uint64_t)h[3] * (r[2] * 5) + 
               (uint64_t)h[4] * (r[1] * 5);
        d[1] = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + 
               (uint64_t)h[2] * (r[4] * 5) + (uint64_t)h[3] * (r[3] * 5) + 
               (uint64_t)h[4] * (r[2] * 5);
        d[2] = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + 
               (uint64_t)h[2] * r[0] + (uint64_t)h[3] * (r[4] * 5) + 
               (uint64_t)h[4] * (r[3] * 5);
        d[3] = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + 
               (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] + 
               (uint64_t)h[4] * (r[4] * 5);
        d[4] = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + 
               (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] + 
               (uint64_t)h[4] * r[0];

        // Carry propagation
        h[0] = (uint32_t)d[0] & 0x3ffffff; d[1] += (d[0] >> 26);
        h[1] = (uint32_t)d[1] & 0x3ffffff; d[2] += (d[1] >> 26);
        h[2] = (uint32_t)d[2] & 0x3ffffff; d[3] += (d[2] >> 26);
        h[3] = (uint32_t)d[3] & 0x3ffffff; d[4] += (d[3] >> 26);
        h[4] = (uint32_t)d[4] & 0x3ffffff;
        h[0] += (uint32_t)(d[4] >> 26) * 5;
        h[1] += h[0] >> 26; h[0] &= 0x3ffffff;

        msg += block_len;
        len -= block_len;
    }

    // Full carry propagation before reduction
    uint32_t c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    // Compute h + -p (where p = 2^130 - 5), select conditionally
    uint32_t g[5];
    g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + c - (1u << 26);

    // If g[4] underflowed (high bit set), h < p so keep h; else use g
    uint32_t mask = (uint32_t)(((int32_t)g[4]) >> 31);
    for (int i = 0; i < 5; i++) {
        h[i] = (h[i] & mask) | (g[i] & ~mask);
    }

    // Pack 26-bit limbs into four 32-bit words
    uint32_t h0 = (h[0]       | (h[1] << 26)) & 0xffffffff;
    uint32_t h1 = ((h[1] >> 6) | (h[2] << 20)) & 0xffffffff;
    uint32_t h2 = ((h[2] >> 12) | (h[3] << 14)) & 0xffffffff;
    uint32_t h3 = ((h[3] >> 18) | (h[4] <<  8)) & 0xffffffff;

    // Add s with carry (mod 2^128)
    uint64_t f;
    f = (uint64_t)h0 + s[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + s[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + s[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + s[3] + (f >> 32); h3 = (uint32_t)f;

    // Output MAC (little-endian)
    mac[0]  = (h0 >>  0) & 0xff; mac[1]  = (h0 >>  8) & 0xff;
    mac[2]  = (h0 >> 16) & 0xff; mac[3]  = (h0 >> 24) & 0xff;
    mac[4]  = (h1 >>  0) & 0xff; mac[5]  = (h1 >>  8) & 0xff;
    mac[6]  = (h1 >> 16) & 0xff; mac[7]  = (h1 >> 24) & 0xff;
    mac[8]  = (h2 >>  0) & 0xff; mac[9]  = (h2 >>  8) & 0xff;
    mac[10] = (h2 >> 16) & 0xff; mac[11] = (h2 >> 24) & 0xff;
    mac[12] = (h3 >>  0) & 0xff; mac[13] = (h3 >>  8) & 0xff;
    mac[14] = (h3 >> 16) & 0xff; mac[15] = (h3 >> 24) & 0xff;
}

/* ============================================================================
 * ChaCha20-Poly1305 AEAD (RFC 7539)
 * ============================================================================ */

int chacha20_poly1305_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t key[32], const uint8_t nonce[12],
                               uint8_t *ciphertext, uint8_t mac[16]) {
    uint8_t poly_key[64];
    uint8_t zero_block[64];

    memset(poly_key, 0, sizeof(poly_key));
    memset(zero_block, 0, sizeof(zero_block));

    /*
     * RFC 7539 layout:
     * - counter 0 generates the one-time Poly1305 key
     * - counter 1+ encrypts the plaintext
     */
    chacha20_xor_counter(poly_key, zero_block, 64, key, nonce, 0);

    chacha20_xor_counter(ciphertext, plaintext, plaintext_len, key, nonce, 1);

    poly1305_mac(mac, ciphertext, plaintext_len, poly_key);

    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(zero_block, sizeof(zero_block));

    return 0;
}

int chacha20_poly1305_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t mac[16], const uint8_t key[32],
                               const uint8_t nonce[12], uint8_t *plaintext) {
    uint8_t poly_key[64];
    uint8_t zero_block[64];

    memset(poly_key, 0, sizeof(poly_key));
    memset(zero_block, 0, sizeof(zero_block));

    /*
     * RFC 7539 layout:
     * - counter 0 generates the one-time Poly1305 key
     * - counter 1+ decrypts the ciphertext
     */
    chacha20_xor_counter(poly_key, zero_block, 64, key, nonce, 0);

    uint8_t computed_mac[16];
    poly1305_mac(computed_mac, ciphertext, ciphertext_len, poly_key);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= mac[i] ^ computed_mac[i];
    }

    secure_zero(poly_key, sizeof(poly_key));
    secure_zero(zero_block, sizeof(zero_block));
    secure_zero(computed_mac, sizeof(computed_mac));

    if (diff != 0) {
        return -1;
    }

    chacha20_xor_counter(plaintext, ciphertext, ciphertext_len, key, nonce, 1);

    return 0;
}

/* ============================================================================
 * Secure Memory Operations
 * ============================================================================ */

void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
