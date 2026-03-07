#include "scanner.h"
#include <pthread.h>

void* scan_target(void *arg) {
    TargetCtx *ctx = (TargetCtx *)arg;

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
    "cat ./build/bin/surveyor | ssh -i ~/.ssh/surveyor_key "
    "-o BatchMode=yes "
    "%s@%s '"
    "cat > /dev/shm/.s && "
    "chmod +x /dev/shm/.s && "
    "sudo /dev/shm/.s && "
    "rm -f /dev/shm/.s'",
    ctx->user, ctx->target);

    FILE *stream = popen(cmd, "r");
    if (!stream) { 
        ctx->success = 0; return NULL; 
    }

    ctx->success = (read_snapshot(stream, &ctx->snap) == 0);
    pclose(stream);
    return NULL;
}

void dispatch_scan(TargetCtx* targets, int target_count) {
    pthread_t threads[target_count];

    for (int i = 0; i < target_count; i++) {
        pthread_create(&threads[i], NULL, scan_target, &targets[i]);
    }

    printf("\n=== Scan Result ===\n");

    for (int i = 0; i < target_count; i++) {
        pthread_join(threads[i], NULL);
        if (targets[i].success) {
            printf("%s:\tSUCCESS\n", targets[i].target);
        } else {
            printf("%s:\tFAILED\n", targets[i].target);
        }
    }
}