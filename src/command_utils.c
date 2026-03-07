#include "command_utils.h"
#include <string.h>

const char *proto_str(int protocol) {
    return protocol == 0 ? "tcp" : "udp";
}

const char *fmt_addr(const char *hex_addr, char *buf, int bufsize) {
    int len = strlen(hex_addr);

    // IPv4
    if (len == 8) {
        unsigned int raw;
        sscanf(hex_addr, "%X", &raw);
        snprintf(buf, bufsize, "%u.%u.%u.%u",
            raw & 0xFF,
            (raw >> 8) & 0xFF,
            (raw >> 16) & 0xFF,
            (raw >> 24) & 0xFF);
        return buf;
    }

    // IPv6
    if (len == 32) {
        if (strncmp(hex_addr, "0000000000000000FFFF0000", 24) == 0) {
            unsigned int raw;
            sscanf(hex_addr + 24, "%X", &raw);
            snprintf(buf, bufsize, "%u.%u.%u.%u",
                raw & 0xFF,
                (raw >> 8) & 0xFF,
                (raw >> 16) & 0xFF,
                (raw >> 24) & 0xFF);
            return buf;
        }

        snprintf(buf, bufsize, "%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c:%c%c%c%c",
            hex_addr[6],hex_addr[7],hex_addr[4],hex_addr[5],
            hex_addr[2],hex_addr[3],hex_addr[0],hex_addr[1],
            hex_addr[14],hex_addr[15],hex_addr[12],hex_addr[13],
            hex_addr[10],hex_addr[11],hex_addr[8],hex_addr[9],
            hex_addr[22],hex_addr[23],hex_addr[20],hex_addr[21],
            hex_addr[18],hex_addr[19],hex_addr[16],hex_addr[17],
            hex_addr[30],hex_addr[31],hex_addr[28],hex_addr[29],
            hex_addr[26],hex_addr[27],hex_addr[24],hex_addr[25]);
        return buf;
    }

    // fallback: return as-is
    snprintf(buf, bufsize, "%s", hex_addr);
    return buf;
}

const char *basename_exe(const char *exe) {
    const char *slash = strrchr(exe, '/');
    return slash ? slash + 1 : exe;
}

const char *state_str(int state) {
    switch (state) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x06: return "TIME_WAIT";
        case 0x08: return "CLOSE_WAIT";
        case 0x0A: return "LISTEN";
        default:   return "OTHER";
    }
}

FILE *open_output(const char *path) {
    if (!path) return stdout;
    FILE *f = fopen(path, "w");
    if (!f) perror("fopen");
    return f;
}

void close_output(FILE *out, const char *path) {
    if (out == stdout) return;
    fclose(out);
    printf("Saved to %s\n", path);
}

void print_separator(FILE *out) {
    fprintf(out, "  ---------------------------------------------------------------\n");
}

void print_connection(FILE *out, Connection *c, const char *label) {
    char local[64], remote[64];

    if (c->state == 0x0A) {
        fprintf(out, "    %-8s %s:%u/%s\n", label,
            fmt_addr(c->local_addr, local, sizeof(local)),
            c->local_port, proto_str(c->protocol));
        return;
    }
    fprintf(out, "    %-8s %s:%u -> %s:%u/%s %s\n", label,
        fmt_addr(c->local_addr, local, sizeof(local)), c->local_port,
        fmt_addr(c->rem_addr, remote, sizeof(remote)), c->rem_port,
        proto_str(c->protocol), state_str(c->state));
}

void print_unix_sock(FILE *out, UnixSocket *sock) {
    fprintf(out, "    UNIX     %s (inode:%lu)\n",
        sock->path[0] ? sock->path : "(unnamed)",
        sock->inode);
}

void print_identity(FILE *out, Identity *id) {
    fprintf(out, "  PID:%-8d PPID:%-8d %s\n", id->pid, id->ppid, id->exe);
    fprintf(out, "  CMD: %s\n", id->cmdline);
    if (strlen(id->cgroup) > 1)
        fprintf(out, "  CGROUP: %s\n", id->cgroup);

    for (int i = 0; i < id->ingress_count; i++)
        print_connection(out, &id->ingress[i], "INGRESS");
    for (int i = 0; i < id->egress_count; i++)
        print_connection(out, &id->egress[i], "EGRESS");
    for (int i = 0; i < id->local_count; i++)
        print_connection(out, &id->local[i], "LOCAL");
    for (int i = 0; i < id->unix_count; i++)
        print_unix_sock(out, &id->unix_socks[i]);

    fprintf(out, "\n");
}

void print_node(FILE *out, EnrolledNode *node) {
    fprintf(out, "[NODE: %s]\n\n", node->ip);
    for (int i = 0; i < node->snap.identity_count; i++)
        print_identity(out, &node->snap.identities[i]);
}

void print_attack_surface(FILE *out, Session *s) {
    fprintf(out, "\n  ATTACK SURFACE (exposed listeners)\n");
    print_separator(out);

    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            for (int j = 0; j < id->ingress_count; j++) {
                if (id->ingress[j].state != 0x0A) continue;
                int is_wildcard =
                    strcmp(id->ingress[j].local_addr, "00000000") == 0 ||
                    strcmp(id->ingress[j].local_addr, "00000000000000000000000000000000") == 0;

                fprintf(out, "  %-16s %-30s :%u/%s %s\n",
                    s->nodes[n].ip,
                    basename_exe(id->exe),
                    id->ingress[j].local_port,
                    proto_str(id->ingress[j].protocol),
                    is_wildcard ? "[EXPOSED 0.0.0.0]" : "[bound]");
            }
        }
    }
}

void print_edge_section(FILE *out, const char *title, MapEdgeList *list, int show_node) {
    if (list->count == 0) return;

    fprintf(out, "\n  %s\n", title);
    print_separator(out);

    for (int i = 0; i < list->count; i++) {
        MapEdge *e = &list->edges[i];
        if (e->is_unix) {
            fprintf(out, "  [%s] %-20s <==%s==> %-20s",
                e->from_node, basename_exe(e->from_exe),
                e->unix_path, basename_exe(e->to_exe));
        } else if (show_node) {
            fprintf(out, "  %-16s/%-20s ---:%u/%s--> %-16s/%-20s",
                e->from_node, basename_exe(e->from_exe),
                e->port, proto_str(e->protocol),
                e->to_node, basename_exe(e->to_exe));
        } else {
            fprintf(out, "  [%s] %-20s ---:%u/%s--> %-20s",
                e->from_node, basename_exe(e->from_exe),
                e->port, proto_str(e->protocol),
                basename_exe(e->to_exe));
        }
        if (e->count > 1) fprintf(out, " (x%d)", e->count);
        fprintf(out, "\n");
    }
}

void print_resolved_chains(FILE *out, Session *s, ChainList *chains) {
    if (chains->count == 0) return;

    fprintf(out, "\n  RESOLVED SERVICE PATHS (proxy chains collapsed)\n");
    print_separator(out);

    for (int i = 0; i < chains->count; i++) {
        ResolvedChain *c = &chains->chains[i];

        fprintf(out, "  %s/%-20s ---:%u/%s--> %s/%-20s  (via %s)\n",
            s->nodes[c->source_node].ip,
            basename_exe(c->source->exe),
            c->port,
            proto_str(c->protocol),
            s->nodes[c->dest_node].ip,
            basename_exe(c->dest->exe),
            basename_exe(c->proxy->exe));
    }
}

void print_hardening_checklist(FILE *out, Session *s,
                                MapEdgeList *cross, MapEdgeList *unresolved) {
    fprintf(out, "\n  HARDENING CHECKLIST\n");
    print_separator(out);

    fprintf(out, "\n  Ports to capture traffic on:\n");
    unsigned int seen_ports[256];
    int seen_count = 0;

    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;
        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            for (int j = 0; j < id->ingress_count; j++) {
                if (id->ingress[j].state != 0x0A) continue;
                unsigned int p = id->ingress[j].local_port;
                int dup = 0;
                for (int k = 0; k < seen_count; k++) {
                    if (seen_ports[k] == p) { dup = 1; break; }
                }
                if (dup) continue;
                seen_ports[seen_count++] = p;
                fprintf(out, "    :%u/%s  (%s)\n", p,
                    proto_str(id->ingress[j].protocol),
                    basename_exe(id->exe));
            }
        }
    }

    if (cross->count > 0) {
        fprintf(out, "\n  Cross-node paths to firewall/log:\n");
        for (int i = 0; i < cross->count; i++) {
            MapEdge *e = &cross->edges[i];
            fprintf(out, "    %s -> %s :%u/%s\n",
                e->from_node, e->to_node,
                e->port, proto_str(e->protocol));
        }
    }

    if (unresolved->count > 0) {
        fprintf(out, "\n  UNKNOWN DESTINATIONS:\n");
        for (int i = 0; i < unresolved->count; i++) {
            MapEdge *e = &unresolved->edges[i];
            fprintf(out, "    %s/%-20s -> %s\n",
                e->from_node, basename_exe(e->from_exe),
                e->to_node);
        }
    }
}