/**
 * crypto_vault.h - ChaCha20-Poly1305 AEAD for vault.deadlight
 */

#ifndef CRYPTO_VAULT_H
#define CRYPTO_VAULT_H

#include <stdint.h>
#include <stddef.h>

/**
 * Encrypt data using ChaCha20-Poly1305 AEAD
 * 
 * @param plaintext     Input plaintext
 * @param plaintext_len Length of plaintext
 * @param key           256-bit encryption key (32 bytes)
 * @param nonce         96-bit nonce (12 bytes) - MUST be unique per message
 * @param ciphertext    Output buffer (same size as plaintext)
 * @param mac           Output authentication tag (16 bytes)
 * @return 0 on success, -1 on error
 */
int chacha20_poly1305_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t key[32], const uint8_t nonce[12],
                               uint8_t *ciphertext, uint8_t mac[16]);

/**
 * Decrypt and authenticate data using ChaCha20-Poly1305 AEAD
 * 
 * @param ciphertext     Input ciphertext
 * @param ciphertext_len Length of ciphertext
 * @param mac            Authentication tag (16 bytes)
 * @param key            256-bit encryption key (32 bytes)
 * @param nonce          96-bit nonce (12 bytes)
 * @param plaintext      Output buffer (same size as ciphertext)
 * @return 0 on success, -1 if authentication fails
 */
int chacha20_poly1305_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t mac[16], const uint8_t key[32],
                               const uint8_t nonce[12], uint8_t *plaintext);

/**
 * Securely zero memory (prevents compiler optimization)
 * 
 * @param ptr Pointer to memory
 * @param len Length in bytes
 */
void secure_zero(void *ptr, size_t len);

#endif /* CRYPTO_VAULT_H */
