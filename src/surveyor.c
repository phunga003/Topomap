#include "surveyor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_PIDS 4096
#define MAX_CONNS 8192
#define MAX_INODES 128

// --- private: connection reading ---

static int parse_connection(const char *line, Connection *conn, int protocol) {
    char lport[5], rport[5];
    int sl;
    char tx_rx[18], tr_when[12], retrnsmt[9];
    int uid, timeout;

    int matched = sscanf(line,
        " %d: %32[^:]:%4s %32[^:]:%4s %X %17s %11s %8s %d %d %lu",
        &sl,
        conn->local_addr, lport,
        conn->rem_addr, rport,
        &conn->state,
        tx_rx, tr_when, retrnsmt,
        &uid, &timeout,
        &conn->inode);

    if (matched != 12) return -1;

    sscanf(lport, "%X", &conn->local_port);
    sscanf(rport, "%X", &conn->rem_port);
    conn->protocol = protocol;
    return 0;
}

/*
 * read_all_connections
 *
 * Reads /proc/net/{tcp,udp,tcp6,udp6} once.
 * All processes in the same network namespace see the same data,
 * so one read captures everything.
 */
static int read_all_connections(MachineSnapshot *snap) {
    const char *files[] = {"/proc/net/tcp", "/proc/net/udp",
                           "/proc/net/tcp6", "/proc/net/udp6"};
    const int protocols[] = {0, 1, 0, 1};

    snap->connections = malloc(sizeof(Connection) * MAX_CONNS);
    snap->conn_count = 0;

    for (int f = 0; f < 4; f++) {
        FILE *fp = fopen(files[f], "r");
        if (!fp) continue;

        char line[512];
        while (fgets(line, sizeof(line), fp) && snap->conn_count < MAX_CONNS) {
            Connection conn;
            if (parse_connection(line, &conn, protocols[f]) == 0) {
                snap->connections[snap->conn_count++] = conn;
            }
        }
        fclose(fp);
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

static void read_exe(int pid, char *buf, int bufsize) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, buf, bufsize - 1);
    if (n < 0) buf[0] = '\0';
    else buf[n] = '\0';
}

static void read_cmdline(int pid, char *buf, int bufsize) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) { buf[0] = '\0'; return; }

    int n = fread(buf, 1, bufsize - 1, f);
    fclose(f);

    // replace null separators with spaces
    for (int i = 0; i < n; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[n] = '\0';
}

static void read_cgroup(int pid, char *buf, int bufsize) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f) { buf[0] = '\0'; return; }

    fgets(buf, bufsize, f);
    buf[strcspn(buf, "\n")] = '\0';
    fclose(f);
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

static int build_identities(MachineSnapshot *snap) {
    int pids[MAX_PIDS];
    int pid_count = grab_pids(pids, MAX_PIDS);

    snap->identities = malloc(sizeof(Identity) * pid_count);
    snap->identity_count = 0;

    for (int i = 0; i < pid_count; i++) {
        unsigned long inodes[MAX_INODES];
        int inode_count = collect_socket_inodes(pids[i], inodes, MAX_INODES);

        // skip processes with no sockets — not a network service
        if (inode_count == 0) continue;

        Identity *id = &snap->identities[snap->identity_count];
        memset(id, 0, sizeof(Identity));

        id->pid = pids[i];
        read_exe(pids[i], id->exe, sizeof(id->exe));
        read_cmdline(pids[i], id->cmdline, sizeof(id->cmdline));
        read_cgroup(pids[i], id->cgroup, sizeof(id->cgroup));

        id->sock_inodes = malloc(sizeof(unsigned long) * inode_count);
        memcpy(id->sock_inodes, inodes, sizeof(unsigned long) * inode_count);
        id->inode_count = inode_count;

        snap->identity_count++;
    }
    return 0;
}

// --- private: matching ---

static int pid_owns_inode(Identity *id, unsigned long inode) {
    for (int i = 0; i < id->inode_count; i++) {
        if (id->sock_inodes[i] == inode) return 1;
    }
    return 0;
}

/*
 * resolve_topology
 *
 * Matches connections to identities via inode.
 * Classifies as ingress (LISTEN or service port) 
 * vs egress (outbound, ephemeral local port).
 *
 * Heuristic: local port < 1024 or state==0A (LISTEN) -> ingress.
 * Otherwise -> egress.
 */
static void resolve_topology(MachineSnapshot *snap) {
    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];

        // count first
        int ing = 0, egr = 0;
        for (int c = 0; c < snap->conn_count; c++) {
            if (!pid_owns_inode(id, snap->connections[c].inode)) continue;
            if (snap->connections[c].state == 0x0A || snap->connections[c].local_port < 1024)
                ing++;
            else
                egr++;
        }

        id->ingress = ing > 0 ? malloc(sizeof(Connection) * ing) : NULL;
        id->egress = egr > 0 ? malloc(sizeof(Connection) * egr) : NULL;
        id->ingress_count = 0;
        id->egress_count = 0;

        // fill
        for (int c = 0; c < snap->conn_count; c++) {
            if (!pid_owns_inode(id, snap->connections[c].inode)) continue;
            if (snap->connections[c].state == 0x0A || snap->connections[c].local_port < 1024)
                id->ingress[id->ingress_count++] = snap->connections[c];
            else
                id->egress[id->egress_count++] = snap->connections[c];
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



