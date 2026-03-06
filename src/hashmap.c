#include "snapshot.h"
#include <stdlib.h>
#include <string.h>

uint64_t fnv1a(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

void map_init(HashMap *map) {
    memset(map->buckets, 0, sizeof(map->buckets));
}

void map_put(HashMap *map, unsigned long key, int value) {
    int b = fnv1a(&key, sizeof(key)) & MAP_MASK;
    MapEntry *e = malloc(sizeof(MapEntry));
    e->key = key;
    e->value = value;
    e->next = map->buckets[b];
    map->buckets[b] = e;
}

int map_get(HashMap *map, unsigned long key, int *value) {
    int b = fnv1a(&key, sizeof(key)) & MAP_MASK;
    MapEntry *e = map->buckets[b];
    while (e) {
        if (e->key == key) {
            *value = e->value;
            return 0;
        }
        e = e->next;
    }
    return -1;
}

void map_free(HashMap *map) {
    for (int i = 0; i < MAP_BUCKETS; i++) {
        MapEntry *e = map->buckets[i];
        while (e) {
            MapEntry *tmp = e;
            e = e->next;
            free(tmp);
        }
        map->buckets[i] = NULL;
    }
}