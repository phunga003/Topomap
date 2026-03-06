#include "snapshot.h"
#include <stdio.h>

int main() {
    MachineSnapshot snap;

    if (snapshot_machine(&snap) != 0) return 1;
    write_snapshot_binary(&snap);
    
    // print_topology(&snap); 

    free_snapshot(&snap);
    return 0;
}