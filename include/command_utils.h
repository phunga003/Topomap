#ifndef COMMAND_UTILS_H
#define COMMAND_UTILS_H

#include <stdio.h>
#include <snapshot.h>
#include <session.h>

void print_connection(FILE *out, Connection *c, const char *label);
void print_unix(FILE *out, UnixSocket *sock);
void print_identity(FILE *out, Identity *id);
void print_node(FILE *out, EnrolledNode *node);
FILE *open_output(const char *path) ;
void close_output(FILE *out, const char *path);

#endif