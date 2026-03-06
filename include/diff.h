#ifndef DIFF_H
#define DIFF_H

#include "snapshot.h"

void diff_snapshots(const char *ip, MachineSnapshot *old_snap, MachineSnapshot *new_snap);

#endif