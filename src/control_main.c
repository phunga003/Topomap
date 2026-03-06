#include "session.h"
#include "scanner.h"
#include "command_engine.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "root";
    const char *workdir = argc > 2 ? argv[2] : NULL;

    Session session;
    if (session_init(&session, workdir, user) != 0) {
        fprintf(stderr, "Failed to initialize session\n");
        return 1;
    }

    if (session.node_count > 0) {
        printf("Loaded %d node(s) from previous session\n", session.node_count);
    }

    // enroll and scan targets from argv
    int target_count = argc > 2 ? argc - 2 : 0;
    if (target_count > 0) {
        TargetCtx targets[target_count];
        memset(targets, 0, sizeof(TargetCtx) * target_count);

        for (int i = 0; i < target_count; i++) {
            targets[i].target = argv[i + 2];
            targets[i].user = (char *)user;
            session_enroll(&session, argv[i + 2], user);
        }

        dispatch_scan(targets, target_count);

        for (int i = 0; i < target_count; i++) {
            if (!targets[i].success) continue;

            int idx = session_find_node(&session, targets[i].target);
            if (idx < 0) continue;

            if (session.nodes[idx].has_snapshot)
                free_snapshot(&session.nodes[idx].snap);

            session.nodes[idx].snap = targets[i].snap;
            session.nodes[idx].has_snapshot = 1;
            session_save_snapshot(&session, idx);
        }
    }

    register_commands(&session);
    repl_run(&session);

    session_destroy(&session);
    return 0;
}