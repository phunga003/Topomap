#ifndef SESSION_H
#define SESSION_H

#include "snapshot.h"
#include <pthread.h>

#define MAX_NODES 64
#define WORKDIR_PATH "./surveyor_workdir"
#define MAX_COMMANDS 32

#define DEFAULT_USER "root"

typedef struct {
    int argc;
    char *argv[16];
} CommandArgs;

typedef int (*CommandFn)(Session *s, CommandArgs *args);

typedef struct {
    char name[32];
    char usage[128];
    char help[256];
    CommandFn fn;
} Command;

typedef struct {
    char ip[64];
    char user[64];
    MachineSnapshot snap;
    int has_snapshot;
} EnrolledNode;

typedef struct {
    EnrolledNode nodes[MAX_NODES];
    int node_count;
    char workdir[256];
    pthread_mutex_t stdout_lock;
    Command commands[MAX_COMMANDS];
    int command_count;
} Session;


int session_init(Session *s, const char *workdir, const char *user);
void register_commands(Session *s);
void session_destroy(Session *s);

int session_enroll(Session *s, const char *ip, const char *user);
int session_unenroll(Session *s, const char *ip);
int session_find_node(Session *s, const char *ip);

int session_save_snapshot(Session *s, int node_idx);
int session_load_snapshot(Session *s, int node_idx);
int session_load_all(Session *s);

void session_snapshot_path(Session *s, const char *ip, char *buf, int bufsize);
void session_report_path(Session *s, const char *ip, char *buf, int bufsize);

#endif