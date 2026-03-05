#include <pthread.h>
#include "surveyor.h"
#include <stdio.h>

typedef struct {
    char *target;
    char *user;
    MachineSnapshot snap;
    int success;
} TargetCtx;

void *scan_target(void *arg) {
    TargetCtx *ctx = (TargetCtx *)arg;

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
    "cat ./surveyor | ssh -i ~/.ssh/surveyor_key "
    "-o BatchMode=yes "
    "%s@%s",
    ctx->user, ctx->target);

    FILE *stream = popen(cmd, "r");
    if (!stream) { ctx->success = 0; return NULL; }

    ctx->success = (read_snapshot(stream, &ctx->snap) == 0);
    pclose(stream);
    return NULL;
}

int main(int argc, char **argv) {
    int target_count = argc - 2;
    TargetCtx targets[target_count];
    pthread_t threads[target_count];

    for (int i = 0; i < target_count; i++) {
        targets[i].target = argv[i + 2];
        targets[i].user = argv[1];
        pthread_create(&threads[i], NULL, scan_target, &targets[i]);
    }

    for (int i = 0; i < target_count; i++) {
        pthread_join(threads[i], NULL);
        if (targets[i].success) {
            printf("\n=== %s ===\n", targets[i].target);
            print_topology(&targets[i].snap);
            free_snapshot(&targets[i].snap);
        } else {
            printf("\n=== %s FAILED ===\n", targets[i].target);
        }
    }

    return 0;
}
