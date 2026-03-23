#pragma once
#ifndef SCHEMAS_H
#define SCHEMAS_H

#include "wire.h"
#include "snapshot.h"
#include "stddef.h"

extern const WireField identity_schema[];
extern const int identity_schema_count;

extern const WireField connection_schema[];
extern const int connection_schema_count;

extern const WireField unix_socket_schema[];
extern const int unix_socket_schema_count;
#endif 