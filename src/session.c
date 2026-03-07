#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>



void session_snapshot_path(Session *s, const char *ip, char *buf, int bufsize) {
    snprintf(buf, bufsize, "%s/%s.snap", s->workdir, ip);
}

void session_report_path(Session *s, const char *ip, char *buf, int bufsize) {
    snprintf(buf, bufsize, "%s/%s.report.txt", s->workdir, ip);
}

static int ensure_workdir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return 0;
    if (mkdir(path, 0755) != 0) {
        perror("mkdir workdir");
        return -1;
    }
    return 0;
}

int session_init(Session *s, const char *workdir) {
    memset(s, 0, sizeof(Session));
    snprintf(s->workdir, sizeof(s->workdir), "%s", workdir ? workdir : WORKDIR_PATH);
    pthread_mutex_init(&s->stdout_lock, NULL);

    if (ensure_workdir(s->workdir) != 0) return -1;

    return session_load_all(s);
}

void session_destroy(Session *s) {
    for (int i = 0; i < s->node_count; i++) {
        if (s->nodes[i].has_snapshot) {
            free_snapshot(&s->nodes[i].snap);
        }
    }
    pthread_mutex_destroy(&s->stdout_lock);
}

int session_find_node(Session *s, const char *ip) {
    for (int i = 0; i < s->node_count; i++) {
        if (strcmp(s->nodes[i].ip, ip) == 0) return i;
    }
    return -1;
}

static int resolve_script_path(char *buf, int bufsize, const char *script) {
    char exe_path[256];
    int n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n < 0) return -1;
    exe_path[n] = '\0';

    char *last_slash = strrchr(exe_path, '/');
    if (!last_slash) return -1;
    *last_slash = '\0';

    snprintf(buf, bufsize, "%s/../../scripts/%s", exe_path, script);
    return 0;
}

int session_setup_ssh(Session *s, const char *ip, const char *user) {
    char script_path[512];
    if (resolve_script_path(script_path, sizeof(script_path), "setup_keys.sh") != 0) {
        fprintf(stderr, "Cannot resolve script path\n");
        return -1;
    }
    
    printf("Setting up SSH for %s — password may be required\n", ip);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        execlp("bash", "bash", script_path, user, ip, NULL);
        perror("execlp");
        exit(1);
    }

    int status;
    wait(&status); // only use of multiprocessing so it's fine

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("SSH configured for %s\n", ip);
        return 0;
    }

    fprintf(stderr, "SSH setup failed for %s (exit: %d)\n", ip, WEXITSTATUS(status));
    return -1;
}

int session_enroll(Session *s, const char *ip, const char *user) {
    if (s->node_count >= MAX_NODES) {
        fprintf(stderr, "Warning: max nodes (%d) reached, cannot enroll\n", MAX_NODES);
        return -1;
    }
    if (session_find_node(s, ip) >= 0) {
        fprintf(stderr, "%s already enrolled\n", ip);
        return -1;
    }

    EnrolledNode *node = &s->nodes[s->node_count];
    memset(node, 0, sizeof(EnrolledNode));
    snprintf(node->ip, sizeof(node->ip), "%s", ip);
    snprintf(node->user, sizeof(node->user), "%s", user);
    s->node_count++;
    return 0;
}

int session_unenroll(Session *s, const char *ip) {
    int idx = session_find_node(s, ip);
    if (idx < 0) {
        fprintf(stderr, "%s not enrolled\n", ip);
        return -1;
    }

    if (s->nodes[idx].has_snapshot) {
        free_snapshot(&s->nodes[idx].snap);
    }

    char path[512];
    session_snapshot_path(s, ip, path, sizeof(path));
    remove(path);

    for (int i = idx; i < s->node_count - 1; i++) {
        s->nodes[i] = s->nodes[i + 1];
    }
    s->node_count--;

    return 0;
}

int session_save_snapshot(Session *s, int node_idx) {
    EnrolledNode *node = &s->nodes[node_idx];
    if (!node->has_snapshot) return -1;

    char path[512];
    session_snapshot_path(s, node->ip, path, sizeof(path));

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("save snapshot");
        return -1;
    }

    MachineSnapshot *snap = &node->snap;
    int magic = 0x534E4150;
    int version = 1;
    fwrite(&magic, sizeof(int), 1, f);
    fwrite(&version, sizeof(int), 1, f);
    fwrite(&snap->identity_count, sizeof(int), 1, f);

    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];
        fwrite(&id->pid, sizeof(int), 1, f);
        fwrite(&id->ppid, sizeof(int), 1, f);
        fwrite(id->exe, 256, 1, f);
        fwrite(id->cmdline, 512, 1, f);
        fwrite(id->cgroup, 256, 1, f);

        fwrite(&id->ingress_count, sizeof(int), 1, f);
        if (id->ingress_count > 0)
            fwrite(id->ingress, sizeof(Connection), id->ingress_count, f);

        fwrite(&id->egress_count, sizeof(int), 1, f);
        if (id->egress_count > 0)
            fwrite(id->egress, sizeof(Connection), id->egress_count, f);

        fwrite(&id->local_count, sizeof(int), 1, f);
        if (id->local_count > 0)
            fwrite(id->local, sizeof(Connection), id->local_count, f);

        fwrite(&id->unix_count, sizeof(int), 1, f);
        if (id->unix_count > 0)
            fwrite(id->unix_socks, sizeof(UnixSocket), id->unix_count, f);
    }

    fclose(f);
    return 0;
}

int session_load_snapshot(Session *s, int node_idx) {
    EnrolledNode *node = &s->nodes[node_idx];

    char path[512];
    session_snapshot_path(s, node->ip, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (node->has_snapshot) {
        free_snapshot(&node->snap);
        node->has_snapshot = 0;
    }

    if (read_snapshot(f, &node->snap) == 0) {
        node->has_snapshot = 1;
    }

    fclose(f);
    return node->has_snapshot ? 0 : -1;
}

int session_load_all(Session *s) {
    DIR *d = opendir(s->workdir);
    if (!d) return 0;

    struct dirent *entry;
    while ((entry = readdir(d))) {
        char *dot = strrchr(entry->d_name, '.');
        if (!dot || strcmp(dot, ".snap") != 0) continue;

        char ip[64];
        int len = dot - entry->d_name;
        if (len >= (int)sizeof(ip)) continue;
        memcpy(ip, entry->d_name, len);
        ip[len] = '\0';

        if (session_enroll(s, ip, "") == 0) {
            int idx = session_find_node(s, ip);
            if (idx >= 0) session_load_snapshot(s, idx);
        }
    }

    closedir(d);
    return 0;
}