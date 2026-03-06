
#ifndef COMMAND_ENGINE_H
#define COMMAND_ENGINE_H

#include "session.h"

int registry_add(Session *s, const char *name, const char *usage,
                 const char *help, CommandFn fn);
Command *registry_find(Session *s, const char *name);

int parse_args(char *line, CommandArgs *args);
int repl_run(Session *s);

#endif