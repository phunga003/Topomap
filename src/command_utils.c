#include <command_utils.h>

void print_connection(FILE *out, Connection *c, const char *label) {
    if (c->state == 0x0A) {
        fprintf(out, "    %-8s :%u %s\n", label, c->local_port,
            c->protocol == 0 ? "tcp" : "udp");
        return;
    }
    fprintf(out, "    %-8s -> %s:%u %s state:%X\n", label,
        c->rem_addr, c->rem_port,
        c->protocol == 0 ? "tcp" : "udp",
        c->state);
}

void print_unix(FILE *out, UnixSocket *sock) {
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
        print_unix(out, &id->unix_socks[i]);

    fprintf(out, "\n");
}

void print_node(FILE *out, EnrolledNode *node) {
    fprintf(out, "[NODE: %s]\n\n", node->ip);
    for (int i = 0; i < node->snap.identity_count; i++)
        print_identity(out, &node->snap.identities[i]);
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
    printf("Report saved to %s\n", path);
}

