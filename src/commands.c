#include "session.h"
#include "command_engine.h"
#include <stdio.h>
#include <string.h>
#include "scanner.h"
#include "command_utils.h"

static int cmd_list(Session *s, CommandArgs *args) {
    (void)args;

    if (s->node_count == 0) {
        printf("No nodes enrolled\n");
        return 0;
    }

    printf("%-20s %-16s %-10s %s\n", "IP", "USER", "STATUS", "SERVICES");
    printf("%-20s %-16s %-10s %s\n", "---", "----", "------", "--------");

    for (int i = 0; i < s->node_count; i++) {
        EnrolledNode *n = &s->nodes[i];
        printf("%-20s %-16s %-10s %d\n",
            n->ip,
            n->user,
            n->has_snapshot ? "OK" : "NO DATA",
            n->has_snapshot ? n->snap.identity_count : 0);
    }

    return 0;
}

static int cmd_enroll(Session *s, CommandArgs *args) {
    if (args->argc < 2) {
        fprintf(stderr, "Usage: enroll <ip> [user]\n");
        return -1;
    }

    const char *ip = args->argv[1];
    const char *user = args->argc > 2 ? args->argv[2] : DEFAULT_USER;

    if (session_enroll(s, ip, user) != 0) return -1;

    printf("Enrolled %s (user: %s)\n", ip, user);
    return 0;
}

static int cmd_unenroll(Session *s, CommandArgs *args) {
    if (args->argc < 2) {
        fprintf(stderr, "Usage: unenroll <ip>\n");
        return -1;
    }

    const char *ip = args->argv[1];
    int idx = session_find_node(s, ip);
    if (idx < 0) {
        fprintf(stderr, "%s not enrolled\n", ip);
        return -1;
    }

    // dump final text report before removing
    if (s->nodes[idx].has_snapshot) {
        char path[512];
        session_report_path(s, ip, path, sizeof(path));
        FILE *f = fopen(path, "w");
        if (f) {
            print_node(f, &s->nodes[idx]);
            fclose(f);
            printf("Final report saved to %s\n", path);
        }
    }

    session_unenroll(s, ip);
    printf("Unenrolled %s\n", ip);
    return 0;
}

static int cmd_scan(Session *s, CommandArgs *args) {
    if (s->node_count == 0) {
        fprintf(stderr, "No nodes enrolled\n");
        return -1;
    }

    // scan single node
    if (args->argc > 1) {
        int idx = session_find_node(s, args->argv[1]);
        if (idx < 0) {
            fprintf(stderr, "%s not enrolled\n", args->argv[1]);
            return -1;
        }

        TargetCtx target = {
            .target = s->nodes[idx].ip,
            .user = s->nodes[idx].user,
            .success = 0
        };

        dispatch_scan(&target, 1);

        if (target.success) {
            if (s->nodes[idx].has_snapshot)
                free_snapshot(&s->nodes[idx].snap);
            s->nodes[idx].snap = target.snap;
            s->nodes[idx].has_snapshot = 1;
            session_save_snapshot(s, idx);
        }

        return 0;
    }

    // scan all enrolled nodes
    TargetCtx targets[s->node_count];
    memset(targets, 0, sizeof(TargetCtx) * s->node_count);

    for (int i = 0; i < s->node_count; i++) {
        targets[i].target = s->nodes[i].ip;
        targets[i].user = s->nodes[i].user;
    }

    dispatch_scan(targets, s->node_count);

    for (int i = 0; i < s->node_count; i++) {
        if (!targets[i].success) continue;

        if (s->nodes[i].has_snapshot)
            free_snapshot(&s->nodes[i].snap);
        s->nodes[i].snap = targets[i].snap;
        s->nodes[i].has_snapshot = 1;
        session_save_snapshot(s, i);
    }

    return 0;
}

static int cmd_report(Session *s, CommandArgs *args) {
    const char *outpath = args->argc > 2 ? args->argv[2] : NULL;
    FILE *out = open_output(outpath);
    if (!out) return -1;

    // single node
    if (args->argc > 1) {
        int idx = session_find_node(s, args->argv[1]);
        if (idx < 0) {
            fprintf(stderr, "%s not enrolled\n", args->argv[1]);
            close_output(out, outpath);
            return -1;
        }
        if (!s->nodes[idx].has_snapshot) {
            fprintf(stderr, "%s has no snapshot data\n", args->argv[1]);
            close_output(out, outpath);
            return -1;
        }
        print_node(out, &s->nodes[idx]);
        close_output(out, outpath);
        return 0;
    }

    // all nodes
    for (int i = 0; i < s->node_count; i++) {
        if (!s->nodes[i].has_snapshot) continue;
        print_node(out, &s->nodes[i]);
    }

    close_output(out, outpath);
    return 0;
}

typedef struct {
    char *name;
    char *usage;
    char *help;
    CommandFn fn;
} CommandDef;

static CommandDef commands[] = {
    { "list",    "list",               "Show all enrolled nodes",   cmd_list },
    { "enroll",  "enroll <ip> [user]", "Add a node for surveying",  cmd_enroll },
    { "unenroll","unenroll <ip>",      "Remove a node",             cmd_unenroll },
    { "scan",    "scan [ip]",          "Scan enrolled nodes",       cmd_scan },
    { "report",  "report [ip] [file]", "Print topology report",     cmd_report },
    //{ "map",     "map [file]",         "Print connection map",      cmd_map },
    //{ "exec",    "exec <ip> <cmd>",    "Run command on a node",     cmd_exec },
};

void register_commands(Session *s) {
    int count = sizeof(commands) / sizeof(commands[0]);
    for (int i = 0; i < count; i++) {
        registry_add(s, commands[i].name, commands[i].usage,
                    commands[i].help, commands[i].fn);
    }

}