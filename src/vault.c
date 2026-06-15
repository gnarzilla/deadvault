/**
 * vault.c - Local encrypted credential store implementation
 * 
 * SQLite backend, ChaCha20-Poly1305 encryption, PBKDF2 key derivation
 */
#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include "vault.h"
#include "crypto_vault.h"
#include "pbkdf2_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sqlite3.h>

/* ============================================================================
 * Vault Context Structure (opaque)
 * ============================================================================ */

struct vault {
    sqlite3 *db;
    char *db_path;

    uint8_t master_key[VAULT_KEY_LEN];
    uint8_t salt[VAULT_SALT_LEN];

    uint8_t verifier_nonce[VAULT_NONCE_LEN];
    uint8_t *verifier_blob;
    size_t verifier_len;

    int is_locked;
};

/* ============================================================================
 * Constants
 * ============================================================================ */

#define VAULT_DB_VERSION 1

/* ============================================================================
 * Random Number Generation
 * ============================================================================ */

static int vault_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        return -1;
    }

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n < 0) {
            perror("read /dev/urandom");
            close(fd);
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "Error: Unexpected EOF on /dev/urandom\n");
            close(fd);
            return -1;
        }
        total += n;
    }

    close(fd);
    return 0;
}

/* ============================================================================
 * Password Prompting
 * ============================================================================ */

static int vault_read_password(char *buf, size_t maxlen, const char *prompt) {
    const char *pwd = getpass(prompt);
    if (!pwd) {
        fprintf(stderr, "Error: Failed to read password\n");
        return -1;
    }

    strncpy(buf, pwd, maxlen - 1);
    buf[maxlen - 1] = '\0';
    return 0;
}

/* ============================================================================
 * Path Handling
 * ============================================================================ */

static char *vault_expand_path(const char *path) {
    if (!path || path[0] != '~') {
        return strdup(path ? path : vault_default_path());
    }

    const char *home = getenv("HOME");
    if (!home) {
        home = "/root";  /* Fallback */
    }

    size_t home_len = strlen(home);
    size_t path_len = strlen(path);
    char *expanded = malloc(home_len + path_len + 1);

    if (!expanded) {
        return NULL;
    }

    strcpy(expanded, home);
    strcpy(expanded + home_len, path + 1);  /* Skip the ~ */

    return expanded;
}

static int vault_mkdir_p(const char *path) {
    char *dir = strdup(path);
    if (!dir) {
        return -1;
    }

    /* Find last / */
    char *last_slash = strrchr(dir, '/');
    if (!last_slash) {
        free(dir);
        return 0;  /* No directory component */
    }

    *last_slash = '\0';

    /* Create directory (0700 = user read/write/execute only) */
    if (mkdir(dir, 0700) == 0 || errno == EEXIST) {
        free(dir);
        return 0;
    }

    perror("mkdir");
    free(dir);
    return -1;
}

/* ============================================================================
 * Database Schema
 * ============================================================================ */

static int vault_create_schema(sqlite3 *db) {
    const char *schema = 
        "CREATE TABLE IF NOT EXISTS vault_meta (\n"
        "    version INTEGER,\n"
        "    salt BLOB NOT NULL,\n"
        "    verifier_nonce BLOB NOT NULL,\n"
        "    verifier_blob BLOB NOT NULL,\n"
        "    created_at INTEGER\n"
        ");\n"
        "\n"
        "CREATE TABLE IF NOT EXISTS credentials (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    name TEXT UNIQUE NOT NULL,\n"
        "    type INTEGER NOT NULL,\n"
        "    encrypted_value BLOB NOT NULL,\n"
        "    nonce BLOB NOT NULL,\n"
        "    metadata TEXT,\n"
        "    created_at INTEGER,\n"
        "    last_used INTEGER\n"
        ");\n";

    char *errmsg = NULL;
    int rc = sqlite3_exec(db, schema, NULL, NULL, &errmsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Vault Initialization
 * ============================================================================ */

int vault_init(const char *path) {
    if (!path) {
        path = vault_default_path();
    }

    char *db_path = vault_expand_path(path);
    if (!db_path) {
        return -1;
    }

    /* Create directory */
    if (vault_mkdir_p(db_path) != 0) {
        free(db_path);
        return -1;
    }

    /* Refuse to overwrite existing vault */
    if (access(db_path, F_OK) == 0) {
        fprintf(stderr, "Error: Vault already exists at %s\n", db_path);
        free(db_path);
        return -1;
    }

    /* Prompt for master password */
    char password[256];
    if (vault_read_password(password, sizeof(password), 
                           "Master password: ") != 0) {
        free(db_path);
        return -1;
    }

    char password_confirm[256];
    if (vault_read_password(password_confirm, sizeof(password_confirm),
                           "Confirm password: ") != 0) {
        memset(password, 0, sizeof(password));
        free(db_path);
        return -1;
    }

    /* Verify passwords match */
    if (strcmp(password, password_confirm) != 0) {
        fprintf(stderr, "Error: Passwords do not match\n");
        memset(password, 0, sizeof(password));
        memset(password_confirm, 0, sizeof(password_confirm));
        free(db_path);
        return -1;
    }

    memset(password_confirm, 0, sizeof(password_confirm));

    /* Open SQLite */
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to open SQLite\n");
        sqlite3_close(db);
        memset(password, 0, sizeof(password));
        free(db_path);
        return -1;
    }

    /* Create schema */
    if (vault_create_schema(db) != 0) {
        sqlite3_close(db);
        unlink(db_path);
        memset(password, 0, sizeof(password));
        free(db_path);
        return -1;
    }

    /* Generate random salt */
    uint8_t salt[VAULT_SALT_LEN];
    if (vault_random_bytes(salt, VAULT_SALT_LEN) != 0) {
        fprintf(stderr, "Error: Failed to generate salt\n");
        sqlite3_close(db);
        unlink(db_path);
        memset(password, 0, sizeof(password));
        free(db_path);
        return -1;
    }

    /* Derive master key from password */
    uint8_t master_key[VAULT_KEY_LEN];
        if (vault_derive_key_pbkdf2_sha256(password,
                                       salt, VAULT_SALT_LEN,
                                       VAULT_KDF_ITERATIONS,
                                       master_key) != 0) {
        fprintf(stderr, "Error: Failed to derive master key\n");
        sqlite3_close(db);
        unlink(db_path);
        memset(password, 0, sizeof(password));
        secure_zero(master_key, VAULT_KEY_LEN);
        free(db_path);
        return -1;
    }

    memset(password, 0, sizeof(password));

    static const uint8_t verifier_plain[] = "deadlight-vault-verifier-v1";
    size_t verifier_plain_len = sizeof(verifier_plain) - 1;

    uint8_t verifier_nonce[VAULT_NONCE_LEN];
    uint8_t *verifier_cipher = malloc(verifier_plain_len);
    uint8_t verifier_mac[16];
    uint8_t *verifier_blob = malloc(verifier_plain_len + 16);

    if (!verifier_cipher || !verifier_blob) {
        fprintf(stderr, "Error: Failed to allocate verifier\n");
        free(verifier_cipher);
        free(verifier_blob);
        sqlite3_close(db);
        unlink(db_path);
        secure_zero(master_key, VAULT_KEY_LEN);
        free(db_path);
        return -1;
    }

    if (vault_random_bytes(verifier_nonce, VAULT_NONCE_LEN) != 0) {
        fprintf(stderr, "Error: Failed to generate verifier nonce\n");
        free(verifier_cipher);
        free(verifier_blob);
        sqlite3_close(db);
        unlink(db_path);
        secure_zero(master_key, VAULT_KEY_LEN);
        free(db_path);
        return -1;
    }

    if (chacha20_poly1305_encrypt(
            verifier_plain,
            verifier_plain_len,
            master_key,
            verifier_nonce,
            verifier_cipher,
            verifier_mac) != 0) {
        fprintf(stderr, "Error: Failed to encrypt verifier\n");
        free(verifier_cipher);
        free(verifier_blob);
        sqlite3_close(db);
        unlink(db_path);
        secure_zero(master_key, VAULT_KEY_LEN);
        free(db_path);
        return -1;
    }

    memcpy(verifier_blob, verifier_cipher, verifier_plain_len);
    memcpy(verifier_blob + verifier_plain_len, verifier_mac, 16);
    free(verifier_cipher);

    /* Store salt in vault_meta */
    const char *insert_meta = 
        "INSERT INTO vault_meta "
        "(version, salt, verifier_nonce, verifier_blob, created_at) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, insert_meta, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement\n");
        sqlite3_close(db);
        unlink(db_path);
        secure_zero(master_key, VAULT_KEY_LEN);
        free(db_path);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, VAULT_DB_VERSION);
    sqlite3_bind_blob(stmt, 2, salt, VAULT_SALT_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, verifier_nonce, VAULT_NONCE_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, verifier_blob, verifier_plain_len + 16, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, time(NULL));

    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);

    secure_zero(verifier_blob, verifier_plain_len + 16);
    free(verifier_blob);

    secure_zero(master_key, VAULT_KEY_LEN);
    sqlite3_close(db);

    if (rc != 0) {
        fprintf(stderr, "Error: Failed to insert vault_meta\n");
        unlink(db_path);
        free(db_path);
        return -1;
    }

    fprintf(stderr, "Vault initialized: %s\n", db_path);
    free(db_path);
    return 0;
}

/* ============================================================================
 * Vault Opening and Closing
 * ============================================================================ */

vault_t *vault_open(const char *path) {
    if (!path) {
        path = vault_default_path();
    }

    vault_t *vault = malloc(sizeof(vault_t));
    if (!vault) {
        return NULL;
    }

    memset(vault, 0, sizeof(vault_t));

    /* Expand path */
    vault->db_path = vault_expand_path(path);
    if (!vault->db_path) {
        free(vault);
        return NULL;
    }

    /* Check if vault exists */
    if (access(vault->db_path, F_OK) != 0) {
        fprintf(stderr, "Error: Vault not found at %s\n", vault->db_path);
        fprintf(stderr, "Run 'vault init' to create a new vault\n");
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    /* Open SQLite */
    if (sqlite3_open(vault->db_path, &vault->db) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to open vault database\n");
        sqlite3_close(vault->db);
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    /* Load salt from vault_meta */
    const char *query =
        "SELECT salt, verifier_nonce, verifier_blob "
        "FROM vault_meta LIMIT 1;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(vault->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement\n");
        sqlite3_close(vault->db);
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        fprintf(stderr, "Error: vault_meta not found\n");
        sqlite3_finalize(stmt);
        sqlite3_close(vault->db);
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    const void *salt = sqlite3_column_blob(stmt, 0);
    int salt_len = sqlite3_column_bytes(stmt, 0);

    const void *verifier_nonce = sqlite3_column_blob(stmt, 1);
    int verifier_nonce_len = sqlite3_column_bytes(stmt, 1);

    const void *verifier_blob = sqlite3_column_blob(stmt, 2);
    int verifier_blob_len = sqlite3_column_bytes(stmt, 2);

    if (salt_len != VAULT_SALT_LEN ||
        verifier_nonce_len != VAULT_NONCE_LEN ||
        verifier_blob_len < 16) {
        fprintf(stderr, "Error: Invalid vault metadata\n");
        sqlite3_finalize(stmt);
        sqlite3_close(vault->db);
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    memcpy(vault->salt, salt, VAULT_SALT_LEN);
    memcpy(vault->verifier_nonce, verifier_nonce, VAULT_NONCE_LEN);

    vault->verifier_blob = malloc(verifier_blob_len);
    if (!vault->verifier_blob) {
        sqlite3_finalize(stmt);
        sqlite3_close(vault->db);
        free(vault->db_path);
        free(vault);
        return NULL;
    }

    memcpy(vault->verifier_blob, verifier_blob, verifier_blob_len);
    vault->verifier_len = verifier_blob_len;
    sqlite3_finalize(stmt);

    /* Vault is LOCKED initially (master_key is zeroed) */
    vault->is_locked = 1;

    return vault;
}

int vault_unlock(vault_t *vault, const char *master_password) {
    if (!vault) {
        return -1;
    }

    char password[256];

    /* Prompt for password if not provided */
    if (!master_password) {
        if (vault_read_password(password, sizeof(password),
                               "Master password: ") != 0) {
            return -1;
        }
        master_password = password;
    }

    /* Derive key from password + stored salt */
    uint8_t derived_key[VAULT_KEY_LEN];
    if (vault_derive_key_pbkdf2_sha256(password,
                                       vault->salt, VAULT_SALT_LEN,
                                       VAULT_KDF_ITERATIONS,
                                       derived_key) != 0) {
        fprintf(stderr, "Error: Failed to derive key\n");
        memset(password, 0, sizeof(password));
        return -1;
    }

    /* Wipe temporary password */
    memset(password, 0, sizeof(password));

    static const uint8_t verifier_plain[] = "deadlight-vault-verifier-v1";
    size_t verifier_plain_len = sizeof(verifier_plain) - 1;

    if (!vault->verifier_blob || vault->verifier_len < 16) {
        fprintf(stderr, "Error: Vault verifier missing\n");
        secure_zero(derived_key, VAULT_KEY_LEN);
        return -1;
    }

    size_t verifier_cipher_len = vault->verifier_len - 16;
    const uint8_t *verifier_cipher = vault->verifier_blob;
    const uint8_t *verifier_mac = vault->verifier_blob + verifier_cipher_len;

    uint8_t *decrypted = malloc(verifier_cipher_len);
    if (!decrypted) {
        secure_zero(derived_key, VAULT_KEY_LEN);
        return -1;
    }

    if (chacha20_poly1305_decrypt(
            verifier_cipher,
            verifier_cipher_len,
            verifier_mac,
            derived_key,
            vault->verifier_nonce,
            decrypted) != 0) {
        fprintf(stderr, "Error: Invalid master password\n");
        secure_zero(decrypted, verifier_cipher_len);
        free(decrypted);
        secure_zero(derived_key, VAULT_KEY_LEN);
        return -1;
    }

    if (verifier_cipher_len != verifier_plain_len ||
        memcmp(decrypted, verifier_plain, verifier_plain_len) != 0) {
        fprintf(stderr, "Error: Invalid master password\n");
        secure_zero(decrypted, verifier_cipher_len);
        free(decrypted);
        secure_zero(derived_key, VAULT_KEY_LEN);
        return -1;
    }

    secure_zero(decrypted, verifier_cipher_len);
    free(decrypted);

    /* Copy to vault master key */
    memcpy(vault->master_key, derived_key, VAULT_KEY_LEN);
    secure_zero(derived_key, VAULT_KEY_LEN);

    vault->is_locked = 0;
    return 0;
}

int vault_lock(vault_t *vault) {
    if (!vault) {
        return -1;
    }

    secure_zero(vault->master_key, VAULT_KEY_LEN);
    vault->is_locked = 1;
    return 0;
}

int vault_is_locked(vault_t *vault) {
    return vault ? vault->is_locked : 1;
}

void vault_close(vault_t *vault) {
    if (!vault) {
        return;
    }

    if (vault->db) {
        sqlite3_close(vault->db);
    }

    secure_zero(vault->master_key, VAULT_KEY_LEN);
    secure_zero(vault->salt, VAULT_SALT_LEN);

    if (vault->db_path) {
        free(vault->db_path);
    }

    if (vault->verifier_blob) {
        secure_zero(vault->verifier_blob, vault->verifier_len);
        free(vault->verifier_blob);
    }

    free(vault);
}

/* ============================================================================
 * Credential Operations
 * ============================================================================ */

int vault_add_credential(vault_t *vault,
                         const char *name,
                         cred_type_t type,
                         const uint8_t *value,
                         size_t value_len,
                         const char *metadata) {
    if (!vault || vault->is_locked || !name || !value) {
        fprintf(stderr, "Error: Vault locked or invalid arguments\n");
        return -1;
    }

    /* Generate random nonce */
    uint8_t nonce[VAULT_NONCE_LEN];
    if (vault_random_bytes(nonce, VAULT_NONCE_LEN) != 0) {
        fprintf(stderr, "Error: Failed to generate nonce\n");
        return -1;
    }

    /* Encrypt value */
    uint8_t *ciphertext = malloc(value_len);
    if (!ciphertext) {
        return -1;
    }

    uint8_t mac[16];
    if (chacha20_poly1305_encrypt(value, value_len, vault->master_key, nonce,
                                   ciphertext, mac) != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(ciphertext);
        return -1;
    }

    /* Build encrypted blob: ciphertext || mac */
    uint8_t *encrypted_blob = malloc(value_len + 16);
    if (!encrypted_blob) {
        free(ciphertext);
        return -1;
    }

    memcpy(encrypted_blob, ciphertext, value_len);
    memcpy(encrypted_blob + value_len, mac, 16);
    free(ciphertext);

    /* Store in database */
    const char *insert = 
        "INSERT INTO credentials (name, type, encrypted_value, nonce, metadata, created_at, last_used) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(vault->db, insert, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare statement\n");
        free(encrypted_blob);
        return -1;
    }

    time_t now = time(NULL);

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)type);
    sqlite3_bind_blob(stmt, 3, encrypted_blob, value_len + 16, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, nonce, VAULT_NONCE_LEN, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, metadata, metadata ? -1 : 0, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, now);
    sqlite3_bind_int64(stmt, 7, now);

    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    free(encrypted_blob);

    if (rc != 0) {
        fprintf(stderr, "Error: Failed to insert credential: %s\n", 
                sqlite3_errmsg(vault->db));
        return -1;
    }

    return 0;
}

credential_t *vault_get_metadata(vault_t *vault, const char *name) {
    if (!vault || !name) {
        return NULL;
    }

    const char *query =
        "SELECT id, type, metadata, created_at, last_used "
        "FROM credentials WHERE name = ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(vault->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare metadata query\n");
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    int64_t id = sqlite3_column_int64(stmt, 0);
    int type = sqlite3_column_int(stmt, 1);
    const char *metadata = (const char *)sqlite3_column_text(stmt, 2);
    time_t created_at = sqlite3_column_int64(stmt, 3);
    time_t last_used = sqlite3_column_int64(stmt, 4);

    credential_t *cred = calloc(1, sizeof(credential_t));
    if (!cred) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    /*
     * Copy SQLite-owned memory BEFORE finalize.
     */
    cred->id = id;
    cred->name = strdup(name);
    cred->type = (cred_type_t)type;
    cred->encrypted_value = NULL;
    cred->encrypted_len = 0;
    memset(cred->nonce, 0, sizeof(cred->nonce));
    cred->metadata = metadata ? strdup(metadata) : NULL;
    cred->created_at = created_at;
    cred->last_used = last_used;

    sqlite3_finalize(stmt);
    return cred;
}

credential_t *vault_get_credential(vault_t *vault, const char *name) {
    if (!vault || !name) {
        return NULL;
    }

    const char *query =
        "SELECT id, type, encrypted_value, nonce, metadata, created_at, last_used "
        "FROM credentials WHERE name = ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(vault->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to prepare credential query\n");
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        fprintf(stderr, "Error: Credential not found\n");
        sqlite3_finalize(stmt);
        return NULL;
    }

    int64_t id = sqlite3_column_int64(stmt, 0);
    int type = sqlite3_column_int(stmt, 1);

    const void *encrypted_blob = sqlite3_column_blob(stmt, 2);
    int blob_len = sqlite3_column_bytes(stmt, 2);

    const void *nonce = sqlite3_column_blob(stmt, 3);
    int nonce_len = sqlite3_column_bytes(stmt, 3);

    const char *metadata = (const char *)sqlite3_column_text(stmt, 4);

    time_t created_at = sqlite3_column_int64(stmt, 5);
    time_t last_used = sqlite3_column_int64(stmt, 6);

    if (!encrypted_blob || !nonce || nonce_len != VAULT_NONCE_LEN || blob_len < 16) {
        fprintf(stderr, "Error: Invalid encrypted credential data\n");
        sqlite3_finalize(stmt);
        return NULL;
    }

    credential_t *cred = calloc(1, sizeof(credential_t));
    if (!cred) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    cred->id = id;
    cred->name = strdup(name);
    cred->type = (cred_type_t)type;

    cred->encrypted_value = malloc((size_t)blob_len);
    if (!cred->encrypted_value) {
        credential_free(cred);
        sqlite3_finalize(stmt);
        return NULL;
    }

    /*
     * IMPORTANT:
     * Copy SQLite-owned buffers BEFORE sqlite3_finalize().
     */
    memcpy(cred->encrypted_value, encrypted_blob, (size_t)blob_len);
    cred->encrypted_len = (size_t)blob_len;

    memcpy(cred->nonce, nonce, VAULT_NONCE_LEN);

    cred->metadata = metadata ? strdup(metadata) : NULL;
    cred->created_at = created_at;
    cred->last_used = last_used;

    sqlite3_finalize(stmt);
    return cred;
}

int vault_decrypt_value(vault_t *vault,
                        credential_t *cred,
                        uint8_t **plaintext,
                        size_t *plaintext_len) {
    if (!vault || vault->is_locked || !cred || !plaintext || !plaintext_len) {
        fprintf(stderr, "Error: Vault locked or invalid arguments\n");
        return -1;
    }

    if (!cred->encrypted_value || cred->encrypted_len < 16) {
        fprintf(stderr, "Error: Credential has no encrypted value\n");
        return -1;
    }

    /* Split encrypted blob into ciphertext and MAC */
    size_t ciphertext_len = cred->encrypted_len - 16;
    const uint8_t *ciphertext = cred->encrypted_value;
    const uint8_t *mac = cred->encrypted_value + ciphertext_len;

    /* Allocate plaintext buffer */
    uint8_t *decrypted = malloc(ciphertext_len);
    if (!decrypted) {
        return -1;
    }

    #ifdef DEBUG
    fprintf(stderr, "DEBUG: encrypted_len=%zu ciphertext_len=%zu\n",
            cred->encrypted_len,
            cred->encrypted_len >= 16 ? cred->encrypted_len - 16 : 0);
    #endif

    /* Decrypt and verify MAC */
    if (chacha20_poly1305_decrypt(ciphertext, ciphertext_len, mac,
                                   vault->master_key, cred->nonce,
                                   decrypted) != 0) {
        fprintf(stderr, "Error: Decryption/authentication failed\n");
        free(decrypted);
        return -1;
    }

    /* Update last_used timestamp */
    const char *update = "UPDATE credentials SET last_used = ? WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(vault->db, update, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, time(NULL));
        sqlite3_bind_int64(stmt, 2, cred->id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    *plaintext = decrypted;
    *plaintext_len = ciphertext_len;
    return 0;
}

char **vault_list_credentials(vault_t *vault, int *count) {
    if (!vault || !count) {
        return NULL;
    }

    const char *query = "SELECT name FROM credentials ORDER BY name;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(vault->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    /* Count rows */
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        n++;
    }

    if (n == 0) {
        sqlite3_finalize(stmt);
        *count = 0;
        return NULL;
    }

    /* Allocate array */
    char **name_array = malloc(sizeof(char *) * (n + 1));
    if (!name_array) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    /* Reset and re-query */
    sqlite3_reset(stmt);
    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        name_array[i++] = strdup(name);
    }

    sqlite3_finalize(stmt);

    name_array[i] = NULL;  /* NULL-terminate for safety */
    *count = i;
    return name_array;
}

void vault_list_free(char **names, int count) {
    if (!names) {
        return;
    }

    for (int i = 0; i < count; i++) {
        if (names[i]) {
            free(names[i]);
        }
    }
    free(names);
}

int vault_delete_credential(vault_t *vault, const char *name) {
    if (!vault || vault->is_locked || !name) {
        return -1;
    }

    const char *delete_sql = "DELETE FROM credentials WHERE name = ?;";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(vault->db, delete_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);

    return rc;
}

void credential_free(credential_t *cred) {
    if (!cred) {
        return;
    }

    if (cred->encrypted_value) {
        free(cred->encrypted_value);
    }

    if (cred->name) {
        free(cred->name);
    }

    if (cred->metadata) {
        free(cred->metadata);
    }

    free(cred);
}

/* ============================================================================
 * Import/Export
 * ============================================================================ */

int vault_export(vault_t *vault, const char *output_path) {
    if (!vault || !output_path) {
        return -1;
    }

    char *expanded = vault_expand_path(output_path);
    if (!expanded) {
        return -1;
    }

    /* Simple file copy (SQLite DB is already encrypted at rest) */
    FILE *src = fopen(vault->db_path, "rb");
    if (!src) {
        perror("fopen source");
        free(expanded);
        return -1;
    }

    FILE *dst = fopen(expanded, "wb");
    if (!dst) {
        perror("fopen destination");
        fclose(src);
        free(expanded);
        return -1;
    }

    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            perror("fwrite");
            fclose(src);
            fclose(dst);
            free(expanded);
            return -1;
        }
    }

    fclose(src);
    fclose(dst);

    fprintf(stderr, "Exported to: %s\n", expanded);
    free(expanded);
    return 0;
}

int vault_import(vault_t *vault, const char *input_path) {
    if (!vault || !input_path) {
        return -1;
    }

    char *expanded = vault_expand_path(input_path);
    if (!expanded) {
        return -1;
    }

    /* Close current DB */
    sqlite3_close(vault->db);
    vault->db = NULL;

    /* Backup current DB */
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.backup", vault->db_path);
    rename(vault->db_path, backup_path);

    /* Copy import to vault location */
    FILE *src = fopen(expanded, "rb");
    if (!src) {
        perror("fopen import");
        rename(backup_path, vault->db_path);  /* Restore backup */
        free(expanded);
        return -1;
    }

    FILE *dst = fopen(vault->db_path, "wb");
    if (!dst) {
        perror("fopen destination");
        fclose(src);
        rename(backup_path, vault->db_path);  /* Restore backup */
        free(expanded);
        return -1;
    }

    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            perror("fwrite");
            fclose(src);
            fclose(dst);
            unlink(vault->db_path);
            rename(backup_path, vault->db_path);  /* Restore backup */
            free(expanded);
            return -1;
        }
    }

    fclose(src);
    fclose(dst);

    /* Reopen database */
    if (sqlite3_open(vault->db_path, &vault->db) != SQLITE_OK) {
        fprintf(stderr, "Error: Failed to reopen vault after import\n");
        unlink(vault->db_path);
        rename(backup_path, vault->db_path);  /* Restore backup */
        free(expanded);
        return -1;
    }

    /* Success: remove backup */
    unlink(backup_path);

    fprintf(stderr, "Imported from: %s\n", expanded);
    vault->is_locked = 1;  /* Force re-unlock with new DB */
    free(expanded);
    return 0;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *vault_default_path(void) {
    return "~/.deadlight/vault.db";
}

const char *cred_type_to_string(cred_type_t type) {
    switch (type) {
        case CRED_TYPE_TOKEN:     return "token";
        case CRED_TYPE_PASSWORD:  return "password";
        case CRED_TYPE_SSH_KEY:   return "ssh_key";
        default:                  return "unknown";
    }
}

int string_to_cred_type(const char *str, cred_type_t *type) {
    if (!str || !type) {
        return -1;
    }

    if (strcmp(str, "token") == 0) {
        *type = CRED_TYPE_TOKEN;
        return 0;
    }
    if (strcmp(str, "password") == 0) {
        *type = CRED_TYPE_PASSWORD;
        return 0;
    }
    if (strcmp(str, "ssh_key") == 0) {
        *type = CRED_TYPE_SSH_KEY;
        return 0;
    }

    return -1;
}
