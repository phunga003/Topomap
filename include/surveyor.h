#include <stdio.h>

#ifndef SURVEYOR_H
#define SURVEYOR_H

typedef struct {
    char local_addr[33];
    unsigned int local_port;
    char rem_addr[33];
    unsigned int rem_port;
    int state;
    int protocol;           // 0=tcp, 1=udp
    unsigned long inode;
} Connection;

typedef struct {
    int pid;
    char exe[256];
    char cmdline[512];
    char cgroup[256];

    Connection *ingress;    // LISTEN or inbound established
    int ingress_count;

    Connection *egress;     // outbound established
    int egress_count;

    unsigned long *sock_inodes;
    int inode_count;
} Identity;

typedef struct {
    Connection *connections;
    int conn_count;

    Identity *identities;
    int identity_count;
} MachineSnapshot;

int snapshot_machine(MachineSnapshot *snap);
void print_topology(MachineSnapshot *snap);
void free_snapshot(MachineSnapshot *snap);
void write_snapshot_binary(MachineSnapshot *snap);
int read_snapshot(FILE *f, MachineSnapshot *snap);


#endif