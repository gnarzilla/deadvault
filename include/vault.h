/**
 * vault.h - Core vault operations for credential storage
 */

#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define VAULT_NONCE_LEN 12          /* ChaCha20 nonce size */
#define VAULT_KEY_LEN 32            /* ChaCha20 key size */
#define VAULT_SALT_LEN 16           /* PBKDF2 salt size */
#define VAULT_KDF_ITERATIONS 100000 /* PBKDF2 iterations */

/* ============================================================================
 * Credential Types
 * ============================================================================ */

typedef enum {
    CRED_TYPE_TOKEN,
    CRED_TYPE_PASSWORD,
    CRED_TYPE_SSH_KEY,
    CRED_TYPE_IDENTITY
} cred_type_t;

/* ============================================================================
 * Credential Structure
 * ============================================================================ */

typedef struct {
    int64_t id;
    char *name;
    cred_type_t type;
    uint8_t *encrypted_value;      /* Encrypted blob */
    size_t encrypted_len;           /* Includes MAC (16 bytes at end) */
    uint8_t nonce[12];              /* ChaCha20 nonce */
    char *metadata;                 /* JSON string */
    time_t created_at;
    time_t last_used;
} credential_t;

/* ============================================================================
 * Vault Context (opaque)
 * ============================================================================ */

typedef struct vault vault_t;

/* ============================================================================
 * Core Vault Functions
 * ============================================================================ */

/**
 * Initialize a new vault at given path.
 * Prompts user for master password interactively.
 * 
 * @param path Vault path (NULL = default ~/.deadlight/vault.db)
 * @return 0 on success, -1 on error
 */
int vault_init(const char *path);

/**
 * Open existing vault (LOCKED state initially).
 * Does NOT prompt for password—call vault_unlock() after.
 * 
 * @param path Vault path (NULL = default)
 * @return Vault context or NULL on error
 */
vault_t *vault_open(const char *path);

/**
 * Unlock vault with master password.
 * Required before adding/retrieving/deleting credentials.
 * 
 * @param vault Vault context
 * @param master_password Master password (or NULL to prompt)
 * @return 0 on success, -1 on error (wrong password)
 * 
 * If master_password is NULL, prompts user interactively.
 */
int vault_unlock(vault_t *vault, const char *master_password);

/**
 * Lock vault (secure wipe of master key).
 * Credentials cannot be accessed until vault_unlock() again.
 * 
 * @param vault Vault context
 * @return 0 on success
 */
int vault_lock(vault_t *vault);

/**
 * Check if vault is locked.
 * 
 * @param vault Vault context
 * @return 1 if locked, 0 if unlocked
 */
int vault_is_locked(vault_t *vault);

/**
 * Close vault and wipe keys from memory.
 * 
 * @param vault Vault context
 */
void vault_close(vault_t *vault);

/* ============================================================================
 * Credential Operations (require vault_unlock())
 * ============================================================================ */

/**
 * Add credential to vault.
 * Encrypts value with ChaCha20-Poly1305, stores in database.
 * 
 * @param vault Vault context (must be unlocked)
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
 * Get credential metadata (WITHOUT decryption).
 * Useful for `vault show` where we display name/type/metadata only.
 * 
 * @param vault Vault context
 * @param name Credential name
 * @return Credential with name/type/metadata (encrypted_value is NULL), or NULL if not found
 */
credential_t *vault_get_metadata(vault_t *vault, const char *name);

/**
 * Get full credential (with encrypted value).
 * To decrypt, call vault_decrypt_value().
 * 
 * @param vault Vault context
 * @param name Credential name
 * @return Credential with encrypted_value populated, or NULL if not found
 */
credential_t *vault_get_credential(vault_t *vault, const char *name);

/**
 * Decrypt credential value.
 * Caller must free and secure_zero() returned buffer.
 * 
 * @param vault Vault context (must be unlocked)
 * @param cred Credential to decrypt (must have encrypted_value set)
 * @param plaintext Output: decrypted value
 * @param plaintext_len Output: length of plaintext
 * @return 0 on success, -1 on error (decryption failed, wrong password)
 */
int vault_decrypt_value(vault_t *vault,
                        credential_t *cred,
                        uint8_t **plaintext,
                        size_t *plaintext_len);

/**
 * List all credential names.
 * Caller must free returned array with vault_list_free().
 * 
 * @param vault Vault context
 * @param count Output: number of credentials
 * @return Array of credential names (strings), or NULL if empty
 */
char **vault_list_credentials(vault_t *vault, int *count);

/**
 * Free credential names array.
 * 
 * @param names Array from vault_list_credentials()
 * @param count Count from vault_list_credentials()
 */
void vault_list_free(char **names, int count);

/**
 * Delete credential by name.
 * 
 * @param vault Vault context (must be unlocked)
 * @param name Credential name
 * @return 0 on success, -1 on error
 */
int vault_delete_credential(vault_t *vault, const char *name);

/* ============================================================================
 * Import/Export
 * ============================================================================ */

/**
 * Export vault to encrypted file (for backup/USB transfer).
 * 
 * @param vault Vault context
 * @param output_path Path to write encrypted vault
 * @return 0 on success, -1 on error
 */
int vault_export(vault_t *vault, const char *output_path);

/**
 * Import vault from encrypted file.
 * 
 * @param vault Vault context
 * @param input_path Path to read encrypted vault
 * @return 0 on success, -1 on error
 */
int vault_import(vault_t *vault, const char *input_path);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Free credential structure (securely wipes encrypted_value).
 */
void credential_free(credential_t *cred);

/**
 * Get default vault path.
 * @return Static string "~/.deadlight/vault.db"
 */
const char *vault_default_path(void);

/**
 * Convert credential type to string.
 */
const char *cred_type_to_string(cred_type_t type);

/**
 * Convert string to credential type.
 * @return 0 on success, -1 on error
 */
int string_to_cred_type(const char *str, cred_type_t *type);

#endif /* VAULT_H */