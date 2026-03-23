#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * wire.h — generic binary serialization engine
 *
 * Schemas are defined in schemas.c as WireField tables.
 * To add a field: add a row to the relevant schema in schemas.c.
 * To add a new struct: define a new schema table and declare it in schemas.h.
 * Dynamic or variable-length fields must be handled manually around wire_read/wire_write.
 */

typedef enum {
    WIRE_INT,       // int           (4 bytes)
    WIRE_UINT,      // unsigned int  (4 bytes)
    WIRE_UINT64,    // uint64_t      (8 bytes)
    WIRE_BYTES,     // fixed-length byte buffer (size field required)
} WireType;

typedef struct {
    WireType type;
    size_t   offset;    // offsetof() into the struct
    size_t   size;      // byte count for WIRE_BYTES, 0 for scalar types
} WireField;

int wire_write(FILE *f, void *base, const WireField *schema, int count);
int wire_read(FILE *f, void *base, const WireField *schema, int count);