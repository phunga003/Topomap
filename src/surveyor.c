#include "snapshot.h"
#include "hashmap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <pthread.h>

#define MAX_PIDS 4096
#define MAX_CONNS 16384
#define MAX_UNIX 4096
#define MAX_INODES 256
#define NUM_WORKERS 8

// --- private: linked list for collection ---

struct ConnNode {
    struct ConnNode *next;
    Connection data;
};

struct UnixNode {
    struct UnixNode *next;
    UnixSocket data;
};

// --- private: net file reading (threaded) ---

typedef struct {
    const char *path;
    int protocol;
    struct ConnNode *head;
    int count;
} NetReadCtx;

static int parse_connection(const char *line, Connection *conn, int protocol) {
    char lport[5], rport[5];
    int sl;
    char tx_rx[18], tr_when[12], retrnsmt[9];
    int uid, timeout;

    int matched = sscanf(line,
        " %d: %32[^:]:%4s %32[^:]:%4s %X %17s %11s %8s %d %d %lu",
        &sl, conn->local_addr, lport,
        conn->rem_addr, rport, &conn->state,
        tx_rx, tr_when, retrnsmt, &uid, &timeout, &conn->inode);

    if (matched != 12) return -1;

    sscanf(lport, "%X", &conn->local_port);
    sscanf(rport, "%X", &conn->rem_port);
    conn->protocol = protocol;
    return 0;
}

/*
 * read_net_file
 *
 * Threaded reader for /proc/net/{tcp,udp,tcp6,udp6}.
 * Collects into a linked list to avoid realloc contention.
 * Caller flattens into array after join.
 */
static void *read_net_file(void *arg) {
    NetReadCtx *ctx = (NetReadCtx *)arg;
    ctx->head = NULL;
    ctx->count = 0;

    FILE *f = fopen(ctx->path, "r");
    if (!f) return NULL;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        Connection conn;
        if (parse_connection(line, &conn, ctx->protocol) == 0) {
            struct ConnNode *node = malloc(sizeof(struct ConnNode));
            node->data = conn;
            node->next = ctx->head;
            ctx->head = node;
            ctx->count++;
        }
    }

    fclose(f);
    return NULL;
}

typedef struct {
    struct UnixNode *head;
    int count;
} UnixReadCtx;

static void *read_unix_file(void *arg) {
    UnixReadCtx *ctx = (UnixReadCtx *)arg;
    ctx->head = NULL;
    ctx->count = 0;

    FILE *f = fopen("/proc/net/unix", "r");
    if (!f) return NULL;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        UnixSocket sock = {0};
        int matched = sscanf(line, "%*s %*s %*s %*s %*s %*s %lu %255s",
            &sock.inode, sock.path);

        if (matched >= 1 && sock.inode > 0) {
            struct UnixNode *node = malloc(sizeof(struct UnixNode));
            node->data = sock;
            node->next = ctx->head;
            ctx->head = node;
            ctx->count++;
        }
    }

    fclose(f);
    return NULL;
}

/*
 * read_all_connections
 *
 * Spawns 5 threads: tcp, udp, tcp6, udp6, unix.
 * Each builds a linked list, then we flatten into arrays
 * and build inode -> index hashmaps.
 */
static int read_all_connections(MachineSnapshot *snap) {
    const char *net_files[] = {
        "/proc/net/tcp", "/proc/net/udp",
        "/proc/net/tcp6", "/proc/net/udp6"
    };
    const int protocols[] = {0, 1, 0, 1};

    pthread_t threads[5];
    NetReadCtx net_ctxs[4];
    UnixReadCtx unix_ctx;

    for (int i = 0; i < 4; i++) {
        net_ctxs[i].path = net_files[i];
        net_ctxs[i].protocol = protocols[i];
        pthread_create(&threads[i], NULL, read_net_file, &net_ctxs[i]);
    }
    pthread_create(&threads[4], NULL, read_unix_file, &unix_ctx);

    for (int i = 0; i < 5; i++) {
        pthread_join(threads[i], NULL);
    }

    // flatten tcp/udp into single array
    int total = 0;
    for (int i = 0; i < 4; i++) total += net_ctxs[i].count;

    snap->connections = malloc(sizeof(Connection) * total);
    snap->conn_count = 0;
    map_init(&snap->conn_map);

    for (int i = 0; i < 4; i++) {
        struct ConnNode *cur = net_ctxs[i].head;
        while (cur) {
            int idx = snap->conn_count;
            snap->connections[idx] = cur->data;
            map_put(&snap->conn_map, cur->data.inode, idx);
            snap->conn_count++;

            struct ConnNode *tmp = cur;
            cur = cur->next;
            free(tmp);
        }
    }

    // flatten unix sockets
    snap->unix_sockets = malloc(sizeof(UnixSocket) * unix_ctx.count);
    snap->unix_count = 0;
    map_init(&snap->unix_map);

    struct UnixNode *ucur = unix_ctx.head;
    while (ucur) {
        int idx = snap->unix_count;
        snap->unix_sockets[idx] = ucur->data;
        map_put(&snap->unix_map, ucur->data.inode, idx);
        snap->unix_count++;

        struct UnixNode *tmp = ucur;
        ucur = ucur->next;
        free(tmp);
    }

    return 0;
}

// --- private: PID scanning ---

static int grab_pids(int *pids, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) && count < max) {
        if (!isdigit(entry->d_name[0])) continue;
        pids[count++] = atoi(entry->d_name);
    }
    closedir(d);
    return count;
}

static void read_proc_field(int pid, const char *field, char *buf, int bufsize, int is_link) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, field);

    if (is_link) {
        ssize_t n = readlink(path, buf, bufsize - 1);
        if (n < 0) buf[0] = '\0';
        else buf[n] = '\0';
    } else {
        FILE *f = fopen(path, "r");
        if (!f) { buf[0] = '\0'; return; }
        int n = fread(buf, 1, bufsize - 1, f);
        fclose(f);
        buf[n] = '\0';
    }
}

static void read_cmdline(int pid, char *buf, int bufsize) {
    read_proc_field(pid, "cmdline", buf, bufsize, 0);
    for (int i = 0; i < bufsize && buf[i]; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
}

static void read_ppid(int pid, int *ppid) {
    char buf[512];
    read_proc_field(pid, "stat", buf, sizeof(buf), 0);
    char *p = strrchr(buf, ')');
    if (!p) { *ppid = -1; return; }
    int dummy;
    sscanf(p + 2, "%c %d", (char *)&dummy, ppid);
}

static int collect_socket_inodes(int pid, unsigned long *inodes, int max) {
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);

    DIR *d = opendir(fd_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) && count < max) {
        char fd_path[320];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, entry->d_name);

        char target[256];
        ssize_t n = readlink(fd_path, target, sizeof(target) - 1);
        if (n < 0) continue;
        target[n] = '\0';

        unsigned long inode;
        if (sscanf(target, "socket:[%lu]", &inode) == 1) {
            inodes[count++] = inode;
        }
    }
    closedir(d);
    return count;
}

typedef struct {
    int *pids;
    int pid_count;
    int worker_id;
    int num_workers;
    Identity *identities;   // pre-allocated, each worker writes to its own slots
    int *identity_count;     // per-worker count
} PidWorkerCtx;

static void *pid_worker(void *arg) {
    PidWorkerCtx *ctx = (PidWorkerCtx *)arg;
    int count = 0;

    for (int i = ctx->worker_id; i < ctx->pid_count; i += ctx->num_workers) {
        int pid = ctx->pids[i];
        unsigned long inodes[MAX_INODES];
        int inode_count = collect_socket_inodes(pid, inodes, MAX_INODES);

        if (inode_count == 0) continue;

        Identity *id = &ctx->identities[count];
        memset(id, 0, sizeof(Identity));

        id->pid = pid;
        read_proc_field(pid, "exe", id->exe, sizeof(id->exe), 1);
        read_cmdline(pid, id->cmdline, sizeof(id->cmdline));
        read_proc_field(pid, "cgroup", id->cgroup, sizeof(id->cgroup), 0);
        id->cgroup[strcspn(id->cgroup, "\n")] = '\0';
        read_ppid(pid, &id->ppid);

        id->sock_inodes = malloc(sizeof(unsigned long) * inode_count);
        memcpy(id->sock_inodes, inodes, sizeof(unsigned long) * inode_count);
        id->inode_count = inode_count;

        count++;
    }

    *ctx->identity_count = count;
    return NULL;
}

static int build_identities(MachineSnapshot *snap) {
    int pids[MAX_PIDS];
    int pid_count = grab_pids(pids, MAX_PIDS);

    int max_per_worker = pid_count / NUM_WORKERS + 1;
    Identity *worker_results[NUM_WORKERS];
    int worker_counts[NUM_WORKERS];
    pthread_t threads[NUM_WORKERS];
    PidWorkerCtx ctxs[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_results[i] = malloc(sizeof(Identity) * max_per_worker);
        worker_counts[i] = 0;
        ctxs[i] = (PidWorkerCtx){
            .pids = pids,
            .pid_count = pid_count,
            .worker_id = i,
            .num_workers = NUM_WORKERS,
            .identities = worker_results[i],
            .identity_count = &worker_counts[i]
        };
        pthread_create(&threads[i], NULL, pid_worker, &ctxs[i]);
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(threads[i], NULL);
    }

    int total = 0;
    for (int i = 0; i < NUM_WORKERS; i++) total += worker_counts[i];

    snap->identities = malloc(sizeof(Identity) * total);
    snap->identity_count = 0;

    for (int i = 0; i < NUM_WORKERS; i++) {
        memcpy(&snap->identities[snap->identity_count],
               worker_results[i],
               sizeof(Identity) * worker_counts[i]);
        snap->identity_count += worker_counts[i];
        free(worker_results[i]);
    }

    return 0;
}

// --- private: resolve inodes ---

static int is_loopback(const char *addr) {
    return (strcmp(addr, "0100007F") == 0 ||
            strcmp(addr, "00000000000000000000000001000000") == 0);
}

/*
 * resolve_topology
 *
 * For each identity, walk its socket inodes.
 * Use hashmap to O(1) lookup whether the inode belongs
 * to a tcp/udp connection or a unix socket.
 * Classify as ingress/egress/local/unix.
 */
static void resolve_topology(MachineSnapshot *snap) {
    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];

        // count pass
        int ing = 0, egr = 0, loc = 0, unx = 0;
        for (int k = 0; k < id->inode_count; k++) {
            int idx;
            if (map_get(&snap->conn_map, id->sock_inodes[k], &idx) == 0) {
                Connection *c = &snap->connections[idx];
                if (c->state == 0x0A || c->local_port < 1024)
                    ing++;
                else if (is_loopback(c->rem_addr))
                    loc++;
                else
                    egr++;
            } else if (map_get(&snap->unix_map, id->sock_inodes[k], &idx) == 0) {
                unx++;
            }
        }

        id->ingress = ing > 0 ? malloc(sizeof(Connection) * ing) : NULL;
        id->egress = egr > 0 ? malloc(sizeof(Connection) * egr) : NULL;
        id->local = loc > 0 ? malloc(sizeof(Connection) * loc) : NULL;
        id->unix_socks = unx > 0 ? malloc(sizeof(UnixSocket) * unx) : NULL;
        id->ingress_count = 0;
        id->egress_count = 0;
        id->local_count = 0;
        id->unix_count = 0;

        // fill pass
        for (int k = 0; k < id->inode_count; k++) {
            int idx;
            if (map_get(&snap->conn_map, id->sock_inodes[k], &idx) == 0) {
                Connection *c = &snap->connections[idx];
                if (c->state == 0x0A || c->local_port < 1024)
                    id->ingress[id->ingress_count++] = *c;
                else if (is_loopback(c->rem_addr))
                    id->local[id->local_count++] = *c;
                else
                    id->egress[id->egress_count++] = *c;
            } else if (map_get(&snap->unix_map, id->sock_inodes[k], &idx) == 0) {
                id->unix_socks[id->unix_count++] = snap->unix_sockets[idx];
            }
        }
    }
}

// --- public API ---

int snapshot_machine(MachineSnapshot *snap) {
    memset(snap, 0, sizeof(MachineSnapshot));
    if (read_all_connections(snap) != 0) return -1;
    if (build_identities(snap) != 0) return -1;
    resolve_topology(snap);
    return 0;
}

