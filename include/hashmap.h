#include <stdint.h>
#include <string.h>

#ifndef HASHMAP_H
#define HASHMAP_H

#define MAP_BUCKETS 8192
#define MAP_MASK (MAP_BUCKETS - 1)

typedef struct MapEntry {
    unsigned long key;
    int value;
    struct MapEntry *next;
} MapEntry;

typedef struct {
    MapEntry *buckets[MAP_BUCKETS];
} HashMap;

uint64_t fnv1a(const void *data, size_t len);
void map_init(HashMap *map);
void map_put(HashMap *map, unsigned long key, int value);
int map_get(HashMap *map, unsigned long key, int *value);
void map_free(HashMap *map);

#endif