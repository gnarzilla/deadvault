/**
 * cli.c - Command-line interface for vault.deadlight
 * 
 * Implements: init, add, list, show, exec, delete, export, import
 */

 #define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include "cli.h"
#include "crypto_vault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <fcntl.h>

/* ============================================================================
 * Utilities
 * ============================================================================ */

int read_password(const char *prompt, char *buf, size_t buf_size) {
    if (!prompt || !buf || buf_size == 0) {
        return -1;
    }

    const char *pwd = getpass(prompt);
    if (!pwd) {
        fprintf(stderr, "Error: Failed to read password\n");
        return -1;
    }

    strncpy(buf, pwd, buf_size - 1);
    buf[buf_size - 1] = '\0';
    return 0;
}

int read_file(const char *path, uint8_t **value, size_t *value_len) {
    if (!path || !value || !value_len) {
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }

    /* Get file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        perror("ftell");
        fclose(f);
        return -1;
    }

    rewind(f);

    /* Allocate buffer */
    uint8_t *buf = malloc(size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    /* Read file */
    size_t n = fread(buf, 1, size, f);
    fclose(f);

    if (n != (size_t)size) {
        fprintf(stderr, "Error: Failed to read file\n");
        free(buf);
        return -1;
    }

    *value = buf;
    *value_len = size;
    return 0;
}

static int starts_with_at(const char *s, const char *needle) {
    size_t n = strlen(needle);
    return strncmp(s, needle, n) == 0;
}

static char *replace_credential_tokens(const char *orig, const char *cred_value) {
    if (!orig || !cred_value) {
        return NULL;
    }

    const char *tok1 = "{TOKEN}";
    const char *tok2 = "{PASSWORD}";

    size_t tok1_len = strlen(tok1);
    size_t tok2_len = strlen(tok2);
    size_t cred_len = strlen(cred_value);

    /*
     * First pass: calculate exact output length.
     */
    size_t out_len = 0;
    const char *p = orig;

    while (*p) {
        if (starts_with_at(p, tok1)) {
            out_len += cred_len;
            p += tok1_len;
        } else if (starts_with_at(p, tok2)) {
            out_len += cred_len;
            p += tok2_len;
        } else {
            out_len++;
            p++;
        }
    }

    char *out = malloc(out_len + 1);
    if (!out) {
        return NULL;
    }

    /*
     * Second pass: copy safely.
     */
    char *dst = out;
    p = orig;

    while (*p) {
        if (starts_with_at(p, tok1)) {
            memcpy(dst, cred_value, cred_len);
            dst += cred_len;
            p += tok1_len;
        } else if (starts_with_at(p, tok2)) {
            memcpy(dst, cred_value, cred_len);
            dst += cred_len;
            p += tok2_len;
        } else {
            *dst++ = *p++;
        }
    }

    *dst = '\0';
    return out;
}

/* ============================================================================
 * Command: init
 * ============================================================================ */

int cli_cmd_init(const char *path) {
    fprintf(stderr, "Initializing vault...\n");
    int rc = vault_init(path);
    if (rc == 0) {
        fprintf(stderr, "Success!\n");
    }
    return rc;
}

/* ============================================================================
 * Command: add
 * ============================================================================ */

int cli_cmd_add(vault_t *vault, int argc, char **argv) {
    if (!vault || vault_is_locked(vault)) {
        fprintf(stderr, "Error: Vault not unlocked\n");
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: vault add <name> --type <type> [--value <val> | --file <path>] [--metadata <json>]\n");
        fprintf(stderr, "Types: token, password, ssh_key\n");
        return -1;
    }

    const char *name = argv[1];
    const char *type_str = NULL;
    const char *value_str = NULL;
    const char *file_path = NULL;
    const char *metadata = NULL;
    cred_type_t type = CRED_TYPE_TOKEN;
    uint8_t *value = NULL;
    size_t value_len = 0;

    /* Parse arguments */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            type_str = argv[++i];
            if (string_to_cred_type(type_str, &type) != 0) {
                fprintf(stderr, "Error: Invalid type '%s'\n", type_str);
                return -1;
            }
        }
        else if (strcmp(argv[i], "--value") == 0 && i + 1 < argc) {
            value_str = argv[++i];
        }
        else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            file_path = argv[++i];
        }
        else if (strcmp(argv[i], "--metadata") == 0 && i + 1 < argc) {
            metadata = argv[++i];
        }
    }

    /* Get value from file or string */
    if (file_path) {
        if (read_file(file_path, &value, &value_len) != 0) {
            return -1;
        }
    }
    else if (value_str) {
        value = (uint8_t *)strdup(value_str);
        value_len = strlen(value_str);
    }
    else {
        /* Prompt for value */
        char buf[1024];
        if (read_password("Value: ", buf, sizeof(buf)) != 0) {
            return -1;
        }
        value = (uint8_t *)strdup(buf);
        value_len = strlen(buf);
        memset(buf, 0, sizeof(buf));
    }

    if (!value) {
        fprintf(stderr, "Error: No value provided\n");
        return -1;
    }

    /* Add credential */
    int rc = vault_add_credential(vault, name, type, value, value_len, metadata);

    /* Secure wipe value */
    secure_zero(value, value_len);
    free(value);

    if (rc == 0) {
        fprintf(stderr, "Added credential: %s (%s)\n", name, cred_type_to_string(type));
    }

    return rc;
}

/* ============================================================================
 * Command: list
 * ============================================================================ */

int cli_cmd_list(vault_t *vault) {
    if (!vault) {
        return -1;
    }

    char **names = NULL;
    int count = 0;

    if (vault_list_credentials(vault, &count) != 0) {
        return -1;
    }

    if (count == 0) {
        printf("No credentials stored.\n");
        return 0;
    }

    printf("Credentials:\n");
    for (int i = 0; i < count; i++) {
        /* Get metadata for type */
        credential_t *cred = vault_get_metadata(vault, names[i]);
        if (cred) {
            printf("  - %s (%s)\n", names[i], cred_type_to_string(cred->type));
            credential_free(cred);
        }
        else {
            printf("  - %s\n", names[i]);
        }
    }

    vault_list_free(names, count);
    return 0;
}

/* ============================================================================
 * Command: show
 * ============================================================================ */

int cli_cmd_show(vault_t *vault, int argc, char **argv) {
    if (!vault || argc < 2) {
        fprintf(stderr, "Usage: vault show <name>\n");
        return -1;
    }

    const char *name = argv[1];

    credential_t *cred = vault_get_metadata(vault, name);
    if (!cred) {
        fprintf(stderr, "Error: Credential not found\n");
        return -1;
    }

    printf("Credential: %s\n", cred->name);
    printf("  Type: %s\n", cred_type_to_string(cred->type));
    if (cred->metadata) {
        printf("  Metadata: %s\n", cred->metadata);
    }
    printf("  Created: %s", ctime(&cred->created_at));
    if (cred->last_used > 0) {
        printf("  Last used: %s", ctime(&cred->last_used));
    }

    credential_free(cred);
    return 0;
}

/* ============================================================================
 * Command: exec
 * 
 * Usage: vault exec <name> -- <command> [args...]
 * 
 * Replaces:
 * - {TOKEN} with credential value
 * - {PASSWORD} with credential value
 * ============================================================================ */

int cli_cmd_exec(vault_t *vault, int argc, char **argv) {
    if (!vault || vault_is_locked(vault)) {
        fprintf(stderr, "Error: Vault not unlocked\n");
        return -1;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: vault exec <name> -- <command> [args...]\n");
        return -1;
    }

    const char *cred_name = argv[1];

    /* Find the -- separator */
    int dash_idx = -1;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            dash_idx = i;
            break;
        }
    }

    if (dash_idx == -1 || dash_idx + 1 >= argc) {
        fprintf(stderr, "Error: Missing -- separator or command\n");
        return -1;
    }

    /* Get and decrypt credential */
    credential_t *cred = vault_get_credential(vault, cred_name);
    if (!cred) {
        fprintf(stderr, "Error: Credential not found\n");
        return -1;
    }

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    if (vault_decrypt_value(vault, cred, &plaintext, &plaintext_len) != 0) {
        fprintf(stderr, "Error: Failed to decrypt credential\n");
        credential_free(cred);
        return -1;
    }

    /* Null-terminate plaintext for string operations */
    char *cred_value = malloc(plaintext_len + 1);
    if (!cred_value) {
        secure_zero(plaintext, plaintext_len);
        free(plaintext);
        credential_free(cred);
        return -1;
    }

    memcpy(cred_value, plaintext, plaintext_len);
    cred_value[plaintext_len] = '\0';
    secure_zero(plaintext, plaintext_len);
    free(plaintext);

    credential_free(cred);

    /* Build command with substitutions */
    int cmd_argc = argc - dash_idx - 1;
    char **cmd_argv = malloc(sizeof(char *) * (cmd_argc + 1));
    if (!cmd_argv) {
        secure_zero(cred_value, strlen(cred_value));
        free(cred_value);
        return -1;
    }

        /* Copy and substitute arguments */
    for (int i = 0; i < cmd_argc; i++) {
        const char *orig = argv[dash_idx + 1 + i];

        if (strstr(orig, "{TOKEN}") || strstr(orig, "{PASSWORD}")) {
            cmd_argv[i] = replace_credential_tokens(orig, cred_value);
        } else {
            cmd_argv[i] = strdup(orig);
        }

        if (!cmd_argv[i]) {
            for (int j = 0; j < i; j++) {
                /*
                 * These argv strings may contain credential material.
                 */
                secure_zero(cmd_argv[j], strlen(cmd_argv[j]));
                free(cmd_argv[j]);
            }

            free(cmd_argv);
            secure_zero(cred_value, strlen(cred_value));
            free(cred_value);
            return -1;
        }
    }

    cmd_argv[cmd_argc] = NULL;

    /* Secure wipe credential value */
    secure_zero(cred_value, strlen(cred_value));
    free(cred_value);

    /* Fork and execute */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        for (int i = 0; i < cmd_argc; i++) {
            if (cmd_argv[i]) {
                /*
                * Some args may contain credential material.
                */
                secure_zero(cmd_argv[i], strlen(cmd_argv[i]));
                free(cmd_argv[i]);
            }
        }
        free(cmd_argv);
        return -1;
    }

    if (pid == 0) {
        /* Child process: execute command */
        execvp(cmd_argv[0], cmd_argv);
        perror("execvp");
        exit(127);
    }

    /* Parent process: wait for child */
    int status = 0;
    waitpid(pid, &status, 0);

    /* Cleanup */
    for (int i = 0; i < cmd_argc; i++) {
        free(cmd_argv[i]);
    }
    free(cmd_argv);

    return WEXITSTATUS(status);
}

/* ============================================================================
 * Command: delete
 * ============================================================================ */

int cli_cmd_delete(vault_t *vault, int argc, char **argv) {
    if (!vault || vault_is_locked(vault)) {
        fprintf(stderr, "Error: Vault not unlocked\n");
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: vault delete <name> [--force]\n");
        return -1;
    }

    const char *name = argv[1];
    int force = 0;

    /* Check for --force flag */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = 1;
            break;
        }
    }

    /* Confirm deletion unless --force */
    if (!force) {
        printf("Delete credential '%s'? (y/N) ", name);
        fflush(stdout);

        char buf[16];
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "Error: Failed to read confirmation\n");
            return -1;
        }

        if (buf[0] != 'y' && buf[0] != 'Y') {
            printf("Cancelled.\n");
            return 0;
        }
    }

    if (vault_delete_credential(vault, name) != 0) {
        fprintf(stderr, "Error: Failed to delete credential\n");
        return -1;
    }

    fprintf(stderr, "Deleted credential: %s\n", name);
    return 0;
}

/* ============================================================================
 * Command: export
 * ============================================================================ */

int cli_cmd_export(vault_t *vault, int argc, char **argv) {
    if (!vault) {
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: vault export --output <file>\n");
        return -1;
    }

    const char *output_path = NULL;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_path = argv[++i];
            break;
        }
    }

    if (!output_path) {
        fprintf(stderr, "Error: --output <file> required\n");
        return -1;
    }

    return vault_export(vault, output_path);
}

/* ============================================================================
 * Command: import
 * ============================================================================ */

int cli_cmd_import(vault_t *vault, int argc, char **argv) {
    if (!vault) {
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: vault import <file>\n");
        return -1;
    }

    const char *input_path = argv[1];

    /* Confirm import */
    printf("Import vault from '%s'? Current vault will be backed up. (y/N) ", input_path);
    fflush(stdout);

    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) {
        fprintf(stderr, "Error: Failed to read confirmation\n");
        return -1;
    }

    if (buf[0] != 'y' && buf[0] != 'Y') {
        printf("Cancelled.\n");
        return 0;
    }

    return vault_import(vault, input_path);
}
