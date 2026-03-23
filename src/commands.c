#include "session.h"
#include "command_engine.h"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include "scanner.h"
#include "command_utils.h"
#include "map.h"
#include "diff.h"

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

    if (session_setup_ssh(s, ip, user) != 0) return -1;
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

    // dump final text report
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

static FILE *start_scan_report(Session *s, const char *ip){
    char out_path[512];
    session_diff_path(s, ip, out_path, sizeof(out_path));

    FILE *out = fopen(out_path, "a");
    if (!out) { perror("fopen"); return stdout; }

    time_t now = time(NULL);
    fprintf(out, "[SCAN] %s", ctime(&now));

    return out;
}

static int cmd_scan(Session *s, CommandArgs *args) {
    if (s->node_count == 0) {
        fprintf(stderr, "No nodes enrolled\n");
        return -1;
    }

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
            if (s->nodes[idx].has_snapshot) {
                FILE *out = start_scan_report(s, s->nodes[idx].ip);
                diff_snapshots(out, s->nodes[idx].ip, &s->nodes[idx].snap, &target.snap);
                fclose(out);
                free_snapshot(&s->nodes[idx].snap);
            }
            s->nodes[idx].snap = target.snap;
            s->nodes[idx].has_snapshot = 1;
            session_save_snapshot(s, idx);
        }

        return 0;
    }

    TargetCtx targets[s->node_count];
    memset(targets, 0, sizeof(TargetCtx) * s->node_count);

    for (int i = 0; i < s->node_count; i++) {
        targets[i].target = s->nodes[i].ip;
        targets[i].user = s->nodes[i].user;
    }

    dispatch_scan(targets, s->node_count);

    for (int i = 0; i < s->node_count; i++) {
        if (!targets[i].success) continue;
        if (s->nodes[i].has_snapshot) {
            FILE *out = start_scan_report(s, s->nodes[i].ip);
            diff_snapshots(out, s->nodes[i].ip, &s->nodes[i].snap, &targets[i].snap);
            fclose(out);
            free_snapshot(&s->nodes[i].snap);
        }
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

static int cmd_map(Session *s, CommandArgs *args) {
    const char *outpath = args->argc > 1 ? args->argv[1] : NULL;

    FILE *out = open_output(outpath);
    if (!out) return -1;

    int nodes_with_data = 0;
    int total_svc = 0;
    for (int i = 0; i < s->node_count; i++) {
        if (!s->nodes[i].has_snapshot) continue;
        nodes_with_data++;
        total_svc += s->nodes[i].snap.identity_count;
    }

    if (nodes_with_data == 0) {
        fprintf(stderr, "No snapshot data. Run 'scan' first.\n");
        close_output(out, outpath);
        return -1;
    }

    TopologyMap map;
    ChainList chains;
    build_topology_map(s, &map, &chains);

    fprintf(out, "==============================================================\n");
    fprintf(out, "  NETWORK TOPOLOGY MAP\n");
    fprintf(out, "  Nodes: %d    Services: %d\n", nodes_with_data, total_svc);
    fprintf(out, "==============================================================\n");

    print_attack_surface(out, s);
    print_resolved_chains(out, s, &chains);

    print_edge_section(out, "CROSS-NODE CONNECTIONS (lateral movement paths)", &map.cross, 1);
    print_edge_section(out, "SAME-NODE CONNECTIONS", &map.local, 0);
    print_edge_section(out, "UNIX SOCKET CONNECTIONS", &map.unix_edges, 0);
    print_edge_section(out, "UNRESOLVED (external or down)", &map.unresolved, 1);
    print_hardening_checklist(out, s, &map.cross, &map.unresolved);

    fprintf(out, "\n==============================================================\n");

    close_output(out, outpath);
    topology_map_free(&map);
    chain_list_free(&chains);
    return 0;
}

static int cmd_exec(Session *s, CommandArgs *args) {
    if (args->argc < 3) {
        fprintf(stderr, "Usage: exec <ip> <binary>\n"
                        "       exec shell <ip> <command...>\n");
        return -1;
    }

    // exec shell <ip> <command...>
    if (strcmp(args->argv[1], "shell") == 0) {
        if (args->argc < 4) {
            fprintf(stderr, "Usage: exec shell <ip> <command...>\n");
            return -1;
        }

        const char *ip = args->argv[2];
        int idx = session_find_node(s, ip);
        if (idx < 0) {
            fprintf(stderr, "%s not enrolled\n", ip);
            return -1;
        }

        // rebuild command string from remaining args
        char remote_cmd[1024] = {0};
        for (int i = 3; i < args->argc; i++) {
            if (i > 3) strncat(remote_cmd, " ", sizeof(remote_cmd) - strlen(remote_cmd) - 1);
            strncat(remote_cmd, args->argv[i], sizeof(remote_cmd) - strlen(remote_cmd) - 1);
        }

        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
            "echo '#!/bin/sh\n%s' | ssh -i ~/.ssh/surveyor_key "
            "-o BatchMode=yes "
            "-o StrictHostKeyChecking=no "
            "%s@%s '"
            "cat > /dev/shm/.s && "
            "chmod +x /dev/shm/.s && "
            "sudo /dev/shm/.s && "
            "rm -f /dev/shm/.s'",
            remote_cmd, s->nodes[idx].user, ip);

        FILE *stream = popen(cmd, "r");
        if (!stream) {
            perror("popen");
            return -1;
        }

        char buf[4096];
        while (fgets(buf, sizeof(buf), stream))
            printf("%s", buf);

        int status = pclose(stream);
        printf("\n[exit: %d]\n", WEXITSTATUS(status));
        return 0;
    }

    // exec <ip> <binary>
    const char *ip = args->argv[1];
    const char *binary = args->argv[2];
    int idx = session_find_node(s, ip);
    if (idx < 0) {
        fprintf(stderr, "%s not enrolled\n", ip);
        return -1;
    }

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cat %s | ssh -i ~/.ssh/surveyor_key "
        "-o BatchMode=yes "
        "-o StrictHostKeyChecking=no "
        "%s@%s '"
        "cat > /dev/shm/.x && "
        "chmod +x /dev/shm/.x && "
        "sudo /dev/shm/.x && "
        "rm -f /dev/shm/.x'",
        binary, s->nodes[idx].user, ip);

    FILE *stream = popen(cmd, "r");
    if (!stream) {
        perror("popen");
        return -1;
    }

    char buf[4096];
    while (fgets(buf, sizeof(buf), stream))
        printf("%s", buf);

    int status = pclose(stream);
    printf("\n[exit: %d]\n", WEXITSTATUS(status));
    return 0;
}

typedef struct {
    char *name;
    char *usage;
    char *help;
    CommandFn fn;
} CommandDef;

static CommandDef commands[] = {
    { "list",    "list",                "Show all enrolled nodes",      cmd_list },
    { "enroll",  "enroll <ip> [user]",  "Add a node for surveying",     cmd_enroll },
    { "unenroll","unenroll <ip>",       "Remove a node",                cmd_unenroll },
    { "scan",    "scan [ip]",           "Scan enrolled nodes",          cmd_scan },
    { "report",  "report [ip] [file]",  "Print topology report",        cmd_report },
    { "map",     "map [file]",          "Print topology map",           cmd_map },
    { "exec", "exec <ip> <bin> | exec shell <ip> <cmd>", "Execute binary or shell command on node", cmd_exec },
};

void register_commands(Session *s) {
    int count = sizeof(commands) / sizeof(commands[0]);
    for (int i = 0; i < count; i++) {
        registry_add(s, commands[i].name, commands[i].usage,
                    commands[i].help, commands[i].fn);
    }

}