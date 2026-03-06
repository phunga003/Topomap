#ifndef COMMAND_UTILS_H
#define COMMAND_UTILS_H

#include <stdio.h>
#include "snapshot.h"
#include "map.h"
#include "session.h"

const char *proto_str(int protocol);
const char *basename_exe(const char *exe);
const char *state_str(int state);

FILE *open_output(const char *path) ;
void close_output(FILE *out, const char *path);

void print_separator(FILE *out);
void print_connection(FILE *out, Connection *c, const char *label);
void print_unix(FILE *out, UnixSocket *sock);
void print_identity(FILE *out, Identity *id);
void print_node(FILE *out, EnrolledNode *node);

void print_attack_surface(FILE *out, Session *s);
void print_edge_section(FILE *out, const char *title, MapEdgeList *list, int show_node);
void print_hardening_checklist(FILE *out, Session *s, MapEdgeList *cross, MapEdgeList *unresolved);


#endif