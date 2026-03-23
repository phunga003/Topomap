#include "snapshot_io.h"

#define WRITE_ARRAY(f, arr, count, schema, schema_count) do {       \
    fwrite(&(count), sizeof(int), 1, f);                            \
    for (int _j = 0; _j < (count); _j++)                           \
        wire_write(f, &(arr)[_j], schema, schema_count);            \
} while (0)

#define READ_ARRAY(f, arr, count, type, schema, schema_count) do {  \
    if (safe_read(f, &(count), sizeof(int)) != 0) goto fail;        \
    if ((count) > 0) {                                              \
        (arr) = malloc(sizeof(type) * (count));                     \
        if (!(arr)) goto fail;                                      \
        for (int _j = 0; _j < (count); _j++)                       \
            if (wire_read(f, &(arr)[_j], schema, schema_count) != 0) goto fail; \
    }                                                               \
} while (0)


int write_snapshot(FILE *f, MachineSnapshot *snap) {
    int magic = SNAPSHOT_MAGIC;
    int version = SNAPSHOT_VERSION;
    fwrite(&magic,               sizeof(int), 1, f);
    fwrite(&version,             sizeof(int), 1, f);
    fwrite(&snap->identity_count, sizeof(int), 1, f);

    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];
        wire_write(f, id, identity_schema, identity_schema_count);

        WRITE_ARRAY(f, id->ingress,    id->ingress_count, connection_schema,    connection_schema_count);
        WRITE_ARRAY(f, id->egress,     id->egress_count,  connection_schema,    connection_schema_count);
        WRITE_ARRAY(f, id->local,      id->local_count,   connection_schema,    connection_schema_count);
        WRITE_ARRAY(f, id->unix_socks, id->unix_count,    unix_socket_schema,   unix_socket_schema_count);
    }

    return 0;
}

void write_snapshot_binary(MachineSnapshot *snap) {
    write_snapshot(stdout, snap);
}

int safe_read(FILE *f, void *buf, size_t len) {
    size_t n = fread(buf, 1, len, f);
    if (n != len) return -1;
    return 0;
}

int read_snapshot(FILE *f, MachineSnapshot *snap) {
    memset(snap, 0, sizeof(MachineSnapshot));

    int magic;
    if (safe_read(f, &magic, sizeof(int)) != 0) return -1;
    if (magic != SNAPSHOT_MAGIC) {
        fprintf(stderr, "Bad magic: %X\n", magic);
        return -1;
    }

    int version;
    if (safe_read(f, &version, sizeof(int)) != 0) return -1;
    if (version != SNAPSHOT_VERSION) return -1;

    if (safe_read(f, &snap->identity_count, sizeof(int)) != 0) return -1;
    if (snap->identity_count <= 0 || snap->identity_count > MAX_IDENTITIES) return -1;

    snap->identities = malloc(sizeof(Identity) * snap->identity_count);
    if (!snap->identities) return -1;
    // zero all entries upfront so free_snapshot is safe on partial reads
    memset(snap->identities, 0, sizeof(Identity) * snap->identity_count);

    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];

        if (wire_read(f, id, identity_schema, identity_schema_count) != 0) goto fail;

        READ_ARRAY(f, id->ingress,    id->ingress_count, Connection,  connection_schema,  connection_schema_count);
        READ_ARRAY(f, id->egress,     id->egress_count,  Connection,  connection_schema,  connection_schema_count);
        READ_ARRAY(f, id->local,      id->local_count,   Connection,  connection_schema,  connection_schema_count);
        READ_ARRAY(f, id->unix_socks, id->unix_count,    UnixSocket,  unix_socket_schema, unix_socket_schema_count);
    }

    return 0;

fail:
    free_snapshot(snap);
    return -1;
}

static void print_utc(uint64_t starttime) {
    time_t t = (time_t)starttime;
    struct tm *tm = gmtime(&t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm);
    printf("  START_TIME:\t%s\n", buf);
}

void print_topology(MachineSnapshot *snap) {
    for (int i = 0; i < snap->identity_count; i++) {
        Identity *id = &snap->identities[i];

        printf("=== PID:%d PPID:%d ===\n", id->pid, id->ppid);
        printf("  EXE:\t%s\n", id->exe);
        printf("  CMD:\t%s\n", id->cmdline);
        printf("  CGROUP:\t%s\n", id->cgroup);
        print_utc(id->starttime);
        printf("  LOGINUID:\t%u\n", id->loginuid);

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