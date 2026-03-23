#pragma once
#ifndef SCANNER_H
#define SCANNER_H
#include "snapshot.h"
#include "snapshot_io.h"

typedef struct {
    char *target;
    char *user;
    MachineSnapshot snap;
    int success;
} TargetCtx;

void* scan_target(void *arg);
void dispatch_scan(TargetCtx* targets, int target_count);

#endif