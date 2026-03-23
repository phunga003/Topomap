#ifndef SNAPSHOT_H
#define SNAPSHOT_H

#include <stdio.h>
#include "hashmap.h"

// --- Constants ---
#define SNAPSHOT_VERSION 1
#define SNAPSHOT_MAGIC 0x534E4150

// --- Connections ---

typedef struct {
    char local_addr[33];
    unsigned int local_port;
    char rem_addr[33];
    unsigned int rem_port;
    int state;
    int protocol;       // 0=tcp, 1=udp
    unsigned long inode;
} Connection;

typedef struct {
    unsigned long inode;
    char path[256];
} UnixSocket;

// --- Identity ---

typedef struct {
    int pid;
    int ppid;
    unsigned int loginuid;
    long starttime;
    char exe[256];
    char cmdline[512];
    char cgroup[256];

    Connection *ingress;
    int ingress_count;
    Connection *egress;
    int egress_count;
    Connection *local;
    int local_count;
    UnixSocket *unix_socks;
    int unix_count;

    unsigned long *sock_inodes;
    int inode_count;
} Identity;

typedef struct {
    Connection *connections;
    int conn_count;
    HashMap conn_map;       // inode -> index in connections[]

    UnixSocket *unix_sockets;
    int unix_count;
    HashMap unix_map;       // inode -> index in unix_sockets[]

    Identity *identities;
    int identity_count;
} MachineSnapshot;

int snapshot_machine(MachineSnapshot *snap);
void write_snapshot_binary(MachineSnapshot *snap);
int read_snapshot(FILE *f, MachineSnapshot *snap);
void print_topology(MachineSnapshot *snap);
void free_snapshot(MachineSnapshot *snap);

#endif