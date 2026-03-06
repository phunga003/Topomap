#include "command_engine.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

int registry_add(Session *s, const char *name, const char *usage,
                 const char *help, CommandFn fn) {
    if (s->command_count >= MAX_COMMANDS) {
        fprintf(stderr, "Command registry full\n");
        return -1;
    }

    Command *cmd = &s->commands[s->command_count];
    snprintf(cmd->name, sizeof(cmd->name), "%s", name);
    snprintf(cmd->usage, sizeof(cmd->usage), "%s", usage);
    snprintf(cmd->help, sizeof(cmd->help), "%s", help);
    cmd->fn = fn;
    s->command_count++;
    return 0;
}

Command *registry_find(Session *s, const char *name) {
    for (int i = 0; i < s->command_count; i++) {
        if (strcmp(s->commands[i].name, name) == 0)
            return &s->commands[i];
    }
    return NULL;
}

int parse_args(char *line, CommandArgs *args) {
    args->argc = 0;

    char *p = line;
    while (*p && args->argc < 16) {
        while (*p && isspace(*p)) p++;
        if (!*p) break;

        args->argv[args->argc++] = p;

        while (*p && !isspace(*p)) p++;
        if (*p) { *p = '\0'; p++; }
    }

    return args->argc;
}

static int cmd_help(Session *s, CommandArgs *args) {
    if (args->argc > 1) {
        Command *cmd = registry_find(s, args->argv[1]);
        if (!cmd) {
            fprintf(stderr, "Unknown command: %s\n", args->argv[1]);
            return -1;
        }
        printf("  %s\n  %s\n", cmd->usage, cmd->help);
        return 0;
    }

    printf("Available commands:\n\n");
    for (int i = 0; i < s->command_count; i++) {
        printf("  %-12s %s\n", s->commands[i].name, s->commands[i].help);
    }
    printf("\n  quit/exit    Exit the session\n");
    return 0;
}

int repl_run(Session *s) {
    registry_add(s, "help", "help [command]",
                 "List commands or show help for a specific command",
                 cmd_help);

    char line[1024];
    printf("surveyor> ");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';

        if (strlen(line) == 0) {
            printf("surveyor> ");
            fflush(stdout);
            continue;
        }

        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0)
            break;

        CommandArgs args;
        parse_args(line, &args);
        if (args.argc == 0) {
            printf("surveyor> ");
            fflush(stdout);
            continue;
        }

        Command *cmd = registry_find(s, args.argv[0]);
        if (!cmd) {
            fprintf(stderr, "Unknown command: %s (type 'help')\n", args.argv[0]);
            printf("surveyor> ");
            fflush(stdout);
            continue;
        }

        cmd->fn(s, &args);

        printf("surveyor> ");
        fflush(stdout);
    }

    return 0;
}