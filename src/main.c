/**
 * vault.deadlight - main.c
 * 
 * Local credential store for CLI tools and proxies.
 * Minimal dependencies, offline-first design.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "vault.h"
#include "cli.h"

#define VERSION "0.1.0-mvp"

/* Global vault context */
static vault_t *g_vault = NULL;

/* Signal handler for cleanup */
static void signal_handler(int signo) {
    (void)signo;
    
    fprintf(stderr, "\nReceived interrupt, cleaning up...\n");
    
    if (g_vault) {
        vault_close(g_vault);
        g_vault = NULL;
    }
    
    exit(0);
}

/* Print version banner */
static void print_banner(void) {
    printf("\n");
    printf("vault.deadlight v%s\n", VERSION);
    printf("Local credential store for CLI/proxy workflows\n");
    printf("\n");
}

/* Print usage */
static void print_usage(const char *prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  init                     Initialize vault (creates DB)\n");
    printf("  unlock                   Verify master password (non-persistent MVP)\n");
    printf("  lock                     Lock vault (wipe master key)\n");
    printf("  add <name>               Add credential\n");
    printf("    --type <type>          Type: token, password, ssh_key\n");
    printf("    --value <val>          Value (prompt if omitted)\n");
    printf("    --file <path>          Read value from file\n");
    printf("    --metadata <json>      Optional metadata\n");
    printf("  list                     List credential names\n");
    printf("  show <name>              Show credential metadata\n");
    printf("  exec <name> -- <cmd>     Inject credential into command\n");
    printf("  delete <name>            Remove credential\n");
    printf("  export --output <file>   Export encrypted vault\n");
    printf("  import <file>            Import encrypted vault\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help               Show this help\n");
    printf("  -v, --version            Show version\n");
    printf("  --vault-path <path>      Custom vault location\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s init\n", prog);
    printf("  %s add github-api --type token --value ghp_xxx\n", prog);
    printf("  %s exec github-api -- curl -H \"Authorization: Bearer {TOKEN}\" https://api.github.com/user\n", prog);
    printf("\n");
}

int main(int argc, char **argv) {
    int ret = 0;
    const char *vault_path = NULL;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_banner();
            return 0;
        }

        if (strcmp(argv[i], "--vault-path") == 0 && i + 1 < argc) {
            vault_path = argv[++i];
        }
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    /*
     * init creates a vault. It must not open/unlock an existing vault.
     */
    if (strcmp(command, "init") == 0) {
        return cli_cmd_init(vault_path);
    }

    /*
     * Everything else needs an existing vault DB.
     */
    g_vault = vault_open(vault_path);
    if (!g_vault) {
        fprintf(stderr, "Error: Failed to open vault\n");
        fprintf(stderr, "Run '%s init' to create a new vault\n", argv[0]);
        return 1;
    }

    /*
     * Commands that do not need decryption.
     */
    if (strcmp(command, "list") == 0) {
        ret = cli_cmd_list(g_vault);
        goto cleanup;
    }

    /*
     * unlock is non-persistent in MVP. Treat it as password verification.
     */
    if (strcmp(command, "unlock") == 0) {
        ret = vault_unlock(g_vault, NULL);
        if (ret == 0) {
            fprintf(stderr, "Vault password verified. Note: unlock is non-persistent in MVP.\n");
        } else {
            fprintf(stderr, "Error: Failed to unlock vault\n");
        }
        goto cleanup;
    }

    /*
     * lock is mostly a no-op in one-shot CLI mode, but harmless.
     */
    if (strcmp(command, "lock") == 0) {
        ret = vault_lock(g_vault);
        if (ret == 0) {
            fprintf(stderr, "Vault locked.\n");
        }
        goto cleanup;
    }

    /*
     * All remaining commands need the master key.
     * For MVP, prompt each time.
     */
    if (vault_unlock(g_vault, NULL) != 0) {
        fprintf(stderr, "Error: Failed to unlock vault\n");
        ret = 1;
        goto cleanup;
    }

    if (strcmp(command, "add") == 0) {
        ret = cli_cmd_add(g_vault, argc - 1, &argv[1]);
    }
    else if (strcmp(command, "show") == 0) {
        ret = cli_cmd_show(g_vault, argc - 1, &argv[1]);
    }
    else if (strcmp(command, "exec") == 0) {
        ret = cli_cmd_exec(g_vault, argc - 1, &argv[1]);
    }
    else if (strcmp(command, "delete") == 0) {
        ret = cli_cmd_delete(g_vault, argc - 1, &argv[1]);
    }
    else if (strcmp(command, "export") == 0) {
        ret = cli_cmd_export(g_vault, argc - 1, &argv[1]);
    }
    else if (strcmp(command, "import") == 0) {
        ret = cli_cmd_import(g_vault, argc - 1, &argv[1]);
    }
    else {
        fprintf(stderr, "Error: Unknown command '%s'\n", command);
        print_usage(argv[0]);
        ret = 1;
    }

cleanup:
    if (g_vault) {
        vault_close(g_vault);
        g_vault = NULL;
    }

    return ret;
}