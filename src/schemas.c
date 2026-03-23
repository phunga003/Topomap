/*
 * schemas.c — wire field descriptors for snapshot serialization
 *
 * Implements the per-identity and connection layouts described in snapshot_io.h.
 * Field order here must stay in sync with the wire format documented there.
 */
#include "schemas.h"

// { type,        offsetof(struct, field),           bytes (WIRE_BYTES only) }

const WireField identity_schema[] = {
    { WIRE_INT,    offsetof(Identity, pid),           0   },
    { WIRE_INT,    offsetof(Identity, ppid),          0   },
    { WIRE_UINT,   offsetof(Identity, loginuid),      0   },
    { WIRE_UINT64, offsetof(Identity, starttime),     0   },
    { WIRE_BYTES,  offsetof(Identity, exe),           256 },
    { WIRE_BYTES,  offsetof(Identity, cmdline),       512 },
    { WIRE_BYTES,  offsetof(Identity, cgroup),        256 },
};
const int identity_schema_count = sizeof(identity_schema) / sizeof(identity_schema[0]);

const WireField connection_schema[] = {
    { WIRE_BYTES,  offsetof(Connection, local_addr),  33  },
    { WIRE_UINT,   offsetof(Connection, local_port),  0   },
    { WIRE_BYTES,  offsetof(Connection, rem_addr),    33  },
    { WIRE_UINT,   offsetof(Connection, rem_port),    0   },
    { WIRE_INT,    offsetof(Connection, state),       0   },
    { WIRE_INT,    offsetof(Connection, protocol),    0   },
    { WIRE_UINT64, offsetof(Connection, inode),       0   },
};
const int connection_schema_count = sizeof(connection_schema) / sizeof(connection_schema[0]);

const WireField unix_socket_schema[] = {
    { WIRE_UINT64, offsetof(UnixSocket, inode),       0   },
    { WIRE_BYTES,  offsetof(UnixSocket, path),        256 },
};
const int unix_socket_schema_count = sizeof(unix_socket_schema) / sizeof(unix_socket_schema[0]);
