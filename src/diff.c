#include "diff.h"
#include "command_utils.h"
#include <stdio.h>
#include <string.h>

static int conn_match(Connection *a, Connection *b) {
    return a->local_port == b->local_port &&
           a->rem_port == b->rem_port &&
           a->protocol == b->protocol &&
           strcmp(a->local_addr, b->local_addr) == 0 &&
           strcmp(a->rem_addr, b->rem_addr) == 0;
}

static int unix_match(UnixSocket *a, UnixSocket *b) {
    return a->inode == b->inode;
}

typedef struct {
    int new_snap_conn;
    int dropped_conn;
    int state_change;
    int new_snap_unix;
    int dropped_unix;
} DiffStats;

static void diff_conn_list( FILE *out,
                            const char *label, 
                            Connection *old_snap, int old_snap_count,
                            Connection *new_snap, int new_snap_count,
                            DiffStats *stats) {
    // new_snap connections
    for (int i = 0; i < new_snap_count; i++) {
        int found = 0;
        for (int j = 0; j < old_snap_count; j++) {
            if (conn_match(&new_snap[i], &old_snap[j])) { found = 1; break; }
        }
        if (!found) {
            fprintf(out, "  + %s :%u/%s -> %s:%u %s\n", label,
                new_snap[i].local_port, proto_str(new_snap[i].protocol),
                new_snap[i].rem_addr, new_snap[i].rem_port,
                state_str(new_snap[i].state));
            stats->new_snap_conn++;
        }
    }

    // dropped connections
    for (int i = 0; i < old_snap_count; i++) {
        int found = 0;
        for (int j = 0; j < new_snap_count; j++) {
            if (conn_match(&old_snap[i], &new_snap[j])) { found = 1; break; }
        }
        if (!found) {
            fprintf(out, "  - %s :%u/%s -> %s:%u %s\n", label,
                old_snap[i].local_port, proto_str(old_snap[i].protocol),
                old_snap[i].rem_addr, old_snap[i].rem_port,
                state_str(old_snap[i].state));
            stats->dropped_conn++;
        }
    }

    // state changes
    for (int i = 0; i < new_snap_count; i++) {
        for (int j = 0; j < old_snap_count; j++) {
            if (!conn_match(&new_snap[i], &old_snap[j])) continue;
            if (new_snap[i].state != old_snap[j].state) {
                fprintf(out, "  ~ %s :%u/%s -> %s:%u %s => %s\n", label,
                    new_snap[i].local_port, proto_str(new_snap[i].protocol),
                    new_snap[i].rem_addr, new_snap[i].rem_port,
                    state_str(old_snap[j].state), state_str(new_snap[i].state));
                stats->state_change++;
            }
            break;
        }
    }
}

static void diff_unix_list( FILE *out,
                            UnixSocket *old_snap, int old_snap_count,
                            UnixSocket *new_snap, int new_snap_count,
                            DiffStats *stats) {
    for (int i = 0; i < new_snap_count; i++) {
        int found = 0;
        for (int j = 0; j < old_snap_count; j++) {
            if (unix_match(&new_snap[i], &old_snap[j])) { found = 1; break; }
        }
        if (!found) {
            fprintf(out, "  + UNIX %s (inode:%lu)\n",
                new_snap[i].path[0] ? new_snap[i].path : "(unnamed)",
                new_snap[i].inode);
            stats->new_snap_unix++;
        }
    }

    for (int i = 0; i < old_snap_count; i++) {
        int found = 0;
        for (int j = 0; j < new_snap_count; j++) {
            if (unix_match(&old_snap[i], &new_snap[j])) { found = 1; break; }
        }
        if (!found) {
            fprintf(out, "  - UNIX %s (inode:%lu)\n",
                old_snap[i].path[0] ? old_snap[i].path : "(unnamed)",
                old_snap[i].inode);
            stats->dropped_unix++;
        }
    }
}

void diff_snapshots(FILE *out, const char *ip, MachineSnapshot *old_snap, MachineSnapshot *new_snap) {
    DiffStats stats = {0};

    for (int i = 0; i < new_snap->identity_count; i++) {
        Identity *nid = &new_snap->identities[i];

        // find matching old_snap identity by exe, loginuid, and starttime
        Identity *oid = NULL;
        for (int j = 0; j < old_snap->identity_count; j++) {
            if (strcmp(old_snap->identities[j].exe, nid->exe) == 0 
                && old_snap->identities[j].loginuid == nid->loginuid
                && old_snap->identities[j].starttime == nid->starttime) 
            {
                oid = &old_snap->identities[j];
                break;
            }
        }

        if (!oid) {
            fprintf(out, "  + new_snap SERVICE %s (PID:%d)\n", basename_exe(nid->exe), nid->pid);
            stats.new_snap_conn += nid->ingress_count + nid->egress_count + nid->local_count;
            stats.new_snap_unix += nid->unix_count;
            continue;
        }

        diff_conn_list(out, "INGRESS", oid->ingress, oid->ingress_count,
                       nid->ingress, nid->ingress_count, &stats);
        diff_conn_list(out, "EGRESS", oid->egress, oid->egress_count,
                       nid->egress, nid->egress_count, &stats);
        diff_conn_list(out, "LOCAL", oid->local, oid->local_count,
                       nid->local, nid->local_count, &stats);
        diff_unix_list(out, oid->unix_socks, oid->unix_count,
                       nid->unix_socks, nid->unix_count, &stats);
    }

    // check for disappeared services
    for (int i = 0; i < old_snap->identity_count; i++) {
        int found = 0;
        for (int j = 0; j < new_snap->identity_count; j++) {
            if (strcmp(old_snap->identities[i].exe, new_snap->identities[j].exe) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(out, "  - SERVICE DOWN %s (was PID:%d)\n",
                basename_exe(old_snap->identities[i].exe),
                old_snap->identities[i].pid);
            stats.dropped_conn += old_snap->identities[i].ingress_count +
                                  old_snap->identities[i].egress_count +
                                  old_snap->identities[i].local_count;
            stats.dropped_unix += old_snap->identities[i].unix_count;
        }
    }

    int total = stats.new_snap_conn + stats.dropped_conn + stats.state_change +
                stats.new_snap_unix + stats.dropped_unix;

    if (total == 0) {
        printf("  [%s] no changes\n", ip);
        fprintf(out, "  no changes\n");
    } else {
        printf("  [%s] +%d -%d ~%d\n", ip,
            stats.new_snap_conn + stats.new_snap_unix,
            stats.dropped_conn + stats.dropped_unix,
            stats.state_change);
    }
}