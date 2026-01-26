/**
 * vault.h - Core vault operations for credential storage
 */

#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Credential types */
typedef enum {
    CRED_TYPE_TOKEN,
    CRED_TYPE_PASSWORD,
    CRED_TYPE_SSH_KEY
} cred_type_t;

/* Credential structure */
typedef struct {
    int64_t id;
    char *name;
    cred_type_t type;
    uint8_t *encrypted_value;
    size_t encrypted_len;
    uint8_t nonce[12];
    uint8_t mac[16];
    char *metadata;  /* JSON string */
    time_t created_at;
    time_t last_used;
} credential_t;

/* Vault context (opaque) */
typedef struct vault vault_t;

/**
 * Initialize a new vault at given path
 * User will be prompted for master password
 * 
 * @param path Vault path (NULL = default ~/.deadlight/vault.db)
 * @return 0 on success, -1 on error
 */
int vault_init(const char *path);

/**
 * Open existing vault
 * User will be prompted for master password
 * 
 * @param path Vault path (NULL = default)
 * @return Vault context or NULL on error
 */
vault_t *vault_open(const char *path);

/**
 * Close vault and wipe keys from memory
 */
void vault_close(vault_t *vault);

/**
 * Add credential to vault
 * 
 * @param vault Vault context
 * @param name Credential name (unique)
 * @param type Credential type
 * @param value Plaintext value
 * @param value_len Length of value
 * @param metadata Optional JSON metadata (can be NULL)
 * @return 0 on success, -1 on error
 */
int vault_add_credential(vault_t *vault,
                         const char *name,
                         cred_type_t type,
                         const uint8_t *value,
                         size_t value_len,
                         const char *metadata);

/**
 * Get credential by name
 * Caller must free returned credential with credential_free()
 * 
 * @param vault Vault context
 * @param name Credential name
 * @return Credential or NULL if not found
 */
credential_t *vault_get_credential(vault_t *vault, const char *name);

/**
 * List all credential names
 * Caller must free returned array and strings
 * 
 * @param vault Vault context
 * @param count Output: number of credentials
 * @return Array of credential names (NULL-terminated)
 */
char **vault_list_credentials(vault_t *vault, int *count);

/**
 * Delete credential by name
 * 
 * @param vault Vault context
 * @param name Credential name
 * @return 0 on success, -1 on error
 */
int vault_delete_credential(vault_t *vault, const char *name);

/**
 * Decrypt credential value
 * Caller must free and secure_zero() returned buffer
 * 
 * @param vault Vault context
 * @param cred Credential to decrypt
 * @param plaintext Output: decrypted value
 * @param plaintext_len Output: length of plaintext
 * @return 0 on success, -1 on error
 */
int vault_decrypt_value(vault_t *vault,
                        credential_t *cred,
                        uint8_t **plaintext,
                        size_t *plaintext_len);

/**
 * Free credential structure
 */
void credential_free(credential_t *cred);

/**
 * Get default vault path
 * @return Static string with path
 */
const char *vault_default_path(void);

/**
 * Convert credential type to string
 */
const char *cred_type_to_string(cred_type_t type);

/**
 * Convert string to credential type
 * @return type or -1 on error
 */
int string_to_cred_type(const char *str, cred_type_t *type);

#endif /* VAULT_H */
