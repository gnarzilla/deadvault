/**
 * cli.h - Command-line interface for vault.deadlight
 */

#ifndef CLI_H
#define CLI_H

#include "vault.h"

/**
 * Initialize new vault (interactive)
 * @param path Custom vault path (NULL = default)
 * @return 0 on success, -1 on error
 */
int cli_cmd_init(const char *path);

/**
 * Add credential command
 * @param vault Vault context
 * @param argc Argument count (including command)
 * @param argv Argument vector
 * @return 0 on success, -1 on error
 */
int cli_cmd_add(vault_t *vault, int argc, char **argv);

/**
 * List credentials command
 */
int cli_cmd_list(vault_t *vault);

/**
 * Show credential metadata
 */
int cli_cmd_show(vault_t *vault, int argc, char **argv);

/**
 * Execute command with injected credential
 */
int cli_cmd_exec(vault_t *vault, int argc, char **argv);

/**
 * Delete credential
 */
int cli_cmd_delete(vault_t *vault, int argc, char **argv);

/**
 * Export vault to encrypted file
 */
int cli_cmd_export(vault_t *vault, int argc, char **argv);

/**
 * Import vault from encrypted file
 */
int cli_cmd_import(vault_t *vault, int argc, char **argv);

/**
 * Utility: Read password from stdin without echo
 * @param prompt Prompt to display
 * @param buf Buffer to store password
 * @param buf_size Size of buffer
 * @return 0 on success, -1 on error
 */
int read_password(const char *prompt, char *buf, size_t buf_size);

/**
 * Utility: Read value from file
 * Caller must free returned buffer
 * @param path File path
 * @param value Output: file contents
 * @param value_len Output: content length
 * @return 0 on success, -1 on error
 */
int read_file(const char *path, uint8_t **value, size_t *value_len);

#endif /* CLI_H */
