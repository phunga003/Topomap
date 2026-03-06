#include "session.h"
#include "scanner.h"
#include "command_engine.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "root";
    const char *workdir = argc > 2 ? argv[2] : NULL;

    Session *session = malloc(sizeof(Session));
    if (!session) {
        perror("malloc");
        return 1;
    }

    if (session_init(session, workdir, user) != 0) {
        fprintf(stderr, "Failed to initialize session\n");
        free(session);
        return 1;
    }

    if (session->node_count > 0) {
        printf("Loaded %d node(s) from previous session\n", session->node_count);
    }

    register_commands(session);
    repl_run(session);

    session_destroy(session);
    free(session);
    return 0;
}