#pragma once
#ifndef SNAPSHOT_IO_H
#define SNAPSHOT_IO_H

#include <stdio.h>
#include "snapshot.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <schemas.h>
#include "command_utils.h"

/*
 * Snapshot wire format:
 *
 * [4 bytes]  magic (SNAPSHOT_MAGIC)
 * [4 bytes]  version (SNAPSHOT_VERSION)
 * [4 bytes]  identity_count
 *
 * per identity:
 *   [4 bytes]  pid
 *   [4 bytes]  ppid
 *   [4 bytes]  loginuid
 *   [8 bytes]  starttime
 *   [256 bytes] exe
 *   [512 bytes] cmdline
 *   [256 bytes] cgroup
 *   [4 bytes]  ingress_count
 *   [ingress_count x Connection]
 *   [4 bytes]  egress_count
 *   [egress_count x Connection]
 *   [4 bytes]  local_count
 *   [local_count x Connection]
 *   [4 bytes]  unix_count
 *   [unix_count x UnixSocket]
 *
 * Connection layout: see connection_schema in schemas.c
 * UnixSocket layout: see unix_socket_schema in schemas.c
 *
 * Field order is defined by schemas in wire/schemas.c.
 * To add or modify fields, update the relevant schema table there.
 */

int write_snapshot(FILE *f, MachineSnapshot *snap);
void write_snapshot_binary(MachineSnapshot *snap);
int read_snapshot(FILE *f, MachineSnapshot *snap);
void print_topology(MachineSnapshot *snap);
int safe_read(FILE *f, void *buf, size_t len);

#endif