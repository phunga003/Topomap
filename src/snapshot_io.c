#include "snapshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/*
 * write_snapshot_binary
 *
 * Wire format:
 * [4 bytes magic "SNAP"]
 * [4 bytes version]
 * [4 bytes identity_count]
 * per identity:
 *   [4 bytes pid]
 *   [4 bytes ppid]
 *   [256 bytes exe]
 *   [512 bytes cmdline]
 *   [256 bytes cgroup]
 *   [4 bytes ingress_count]
 *   [sizeof(Connection) * ingress_count]
 *   [4 bytes egress_count]
 *   [sizeof(Connection) * egress_count]
 *   [4 bytes local_count]
 *   [sizeof(Connection) * local_count]
 *   [4 bytes unix_count]
 *   [sizeof(UnixSocket) * unix_count]
 */
void write_snapshot_binary(MachineSnapshot *snap) {
    int magic = SNAPSHOT_MAGIC;
    int version = SNAPSHOT_VERSION;
    write(STDOUT_FILENO, &magic, sizeof(int));
    write(STDOUT_FILENO, &version, sizeof(int));
    write(STDOUT_FILENO, &snap->identity_count, sizeof(int));

    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];
        write(STDOUT_FILENO, &id->pid, sizeof(int));
        write(STDOUT_FILENO, &id->ppid, sizeof(int));
        write(STDOUT_FILENO, id->exe, 256);
        write(STDOUT_FILENO, id->cmdline, 512);
        write(STDOUT_FILENO, id->cgroup, 256);

        write(STDOUT_FILENO, &id->ingress_count, sizeof(int));
        if (id->ingress_count > 0) {
            write(STDOUT_FILENO, id->ingress,
                sizeof(Connection) * id->ingress_count);
        }

        write(STDOUT_FILENO, &id->egress_count, sizeof(int));
        if (id->egress_count > 0) {
            write(STDOUT_FILENO, id->egress,
                sizeof(Connection) * id->egress_count);
        }

        write(STDOUT_FILENO, &id->local_count, sizeof(int));
        if (id->local_count > 0) {
            write(STDOUT_FILENO, id->local,
                sizeof(Connection) * id->local_count);
        }

        write(STDOUT_FILENO, &id->unix_count, sizeof(int));
        if (id->unix_count > 0) {
            write(STDOUT_FILENO, id->unix_socks,
                sizeof(UnixSocket) * id->unix_count);
        }
    }
}

static int safe_read(FILE *f, void *buf, size_t len) {
    size_t n = fread(buf, 1, len, f);
    if (n != len) return -1;
    return 0;
}

int read_snapshot(FILE *f, MachineSnapshot *snap) {
    memset(snap, 0, sizeof(MachineSnapshot));

    int magic;
    if (safe_read(f, &magic, sizeof(int)) != 0) return -1;
    if (magic != 0x534E4150) {
        fprintf(stderr, "Bad magic: %X\n", magic);
        return -1;
    }

    if (safe_read(f, &snap->identity_count, sizeof(int)) != 0) return -1;

    snap->identities = malloc(sizeof(Identity) * snap->identity_count);
    if (!snap->identities) return -1;

    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];
        memset(id, 0, sizeof(Identity));

        if (safe_read(f, &id->pid, sizeof(int)) != 0) return -1;
        if (safe_read(f, &id->ppid, sizeof(int)) != 0) return -1;
        if (safe_read(f, id->exe, 256) != 0) return -1;
        if (safe_read(f, id->cmdline, 512) != 0) return -1;
        if (safe_read(f, id->cgroup, 256) != 0) return -1;

        if (safe_read(f, &id->ingress_count, sizeof(int)) != 0) return -1;
        if (id->ingress_count > 0) {
            id->ingress = malloc(sizeof(Connection) * id->ingress_count);
            if (safe_read(f, id->ingress,
                sizeof(Connection) * id->ingress_count) != 0) return -1;
        }

        if (safe_read(f, &id->egress_count, sizeof(int)) != 0) return -1;
        if (id->egress_count > 0) {
            id->egress = malloc(sizeof(Connection) * id->egress_count);
            if (safe_read(f, id->egress,
                sizeof(Connection) * id->egress_count) != 0) return -1;
        }

        if (safe_read(f, &id->local_count, sizeof(int)) != 0) return -1;
        if (id->local_count > 0) {
            id->local = malloc(sizeof(Connection) * id->local_count);
            if (safe_read(f, id->local,
                sizeof(Connection) * id->local_count) != 0) return -1;
        }

        if (safe_read(f, &id->unix_count, sizeof(int)) != 0) return -1;
        if (id->unix_count > 0) {
            id->unix_socks = malloc(sizeof(UnixSocket) * id->unix_count);
            if (safe_read(f, id->unix_socks,
                sizeof(UnixSocket) * id->unix_count) != 0) return -1;
        }
    }

    return 0;
}

void print_topology(MachineSnapshot *snap) {
    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];

        printf("=== PID:%d PPID:%d ===\n", id->pid, id->ppid);
        printf("  EXE:    %s\n", id->exe);
        printf("  CMD:    %s\n", id->cmdline);
        printf("  CGROUP: %s\n", id->cgroup);

        for (int j = 0; j < id->ingress_count; j++) {
            Connection *c = &id->ingress[j];
            printf("  INGRESS: %s:%u [%s state:%X]\n",
                c->local_addr, c->local_port,
                c->protocol == 0 ? "tcp" : "udp", c->state);
        }

        for (int j = 0; j < id->egress_count; j++) {
            Connection *c = &id->egress[j];
            printf("  EGRESS:  -> %s:%u [%s state:%X]\n",
                c->rem_addr, c->rem_port,
                c->protocol == 0 ? "tcp" : "udp", c->state);
        }

        for (int j = 0; j < id->local_count; j++) {
            Connection *c = &id->local[j];
            printf("  LOCAL:   -> 127.0.0.1:%u [%s]\n",
                c->rem_port,
                c->protocol == 0 ? "tcp" : "udp");
        }

        for (int j = 0; j < id->unix_count; j++) {
            printf("  UNIX:    %s (inode:%lu)\n",
                id->unix_socks[j].path[0] ? id->unix_socks[j].path : "(unnamed)",
                id->unix_socks[j].inode);
        }

        printf("\n");
    }
}

void free_snapshot(MachineSnapshot *snap) {
    for (int i = 0; i < snap->identity_count; i++) {
        free(snap->identities[i].sock_inodes);
        free(snap->identities[i].ingress);
        free(snap->identities[i].egress);
        free(snap->identities[i].local);
        free(snap->identities[i].unix_socks);
    }
    free(snap->identities);
    free(snap->connections);
    free(snap->unix_sockets);
    map_free(&snap->conn_map);
    map_free(&snap->unix_map);
}