#pragma once
#ifndef DIFF_H
#define DIFF_H

#include "snapshot.h"

void diff_snapshots(FILE *out, const char *ip, MachineSnapshot *old_snap, MachineSnapshot *new_snap);

#endif