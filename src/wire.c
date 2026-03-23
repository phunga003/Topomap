#include "wire.h"
#include <string.h>
#include "snapshot_io.h"

int wire_write(FILE *f, void *base, const WireField *schema, int count) {
    for (int i = 0; i < count; i++) {
        void *field = (char *)base + schema[i].offset;
        size_t sz;
        switch (schema[i].type) {
            case WIRE_INT:    sz = sizeof(int);          break;
            case WIRE_UINT:   sz = sizeof(unsigned int); break;
            case WIRE_UINT64: sz = sizeof(uint64_t);     break;
            case WIRE_BYTES:  sz = schema[i].size;       break;
            default: return -1;
        }
        if (fwrite(field, sz, 1, f) != 1) return -1;
    }
    return 0;
}

int wire_read(FILE *f, void *base, const WireField *schema, int count) {
    for (int i = 0; i < count; i++) {
        void *field = (char *)base + schema[i].offset;
        size_t sz;
        switch (schema[i].type) {
            case WIRE_INT:    sz = sizeof(int);          break;
            case WIRE_UINT:   sz = sizeof(unsigned int); break;
            case WIRE_UINT64: sz = sizeof(uint64_t);     break;
            case WIRE_BYTES:  sz = schema[i].size;       break;
            default: return -1;
        }
        if (safe_read(f, field, sz) != 0) return -1;
    }
    return 0;
}