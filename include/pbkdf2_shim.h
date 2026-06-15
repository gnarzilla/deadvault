// include/pbkdf2_shim.h
#ifndef DEADLIGHT_VAULT_PBKDF2_SHIM_H
#define DEADLIGHT_VAULT_PBKDF2_SHIM_H

#include <stddef.h>
#include <stdint.h>

#define VAULT_KDF_ITERATIONS 100000
#define VAULT_KEY_LEN 32
#define VAULT_SALT_LEN 16

int vault_derive_key_pbkdf2_sha256(
    const char *password,
    const uint8_t *salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t out_key[VAULT_KEY_LEN]
);

#endif