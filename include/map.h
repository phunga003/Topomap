#ifndef MAP_H
#define MAP_H

#include "session.h"

typedef struct {
    char from_node[64];
    char from_exe[256];
    char to_node[64];
    char to_exe[256];
    unsigned int port;
    int protocol;
    int is_local;
    int is_unix;
    char unix_path[256];
    int count;
} MapEdge;

typedef struct {
    MapEdge *edges;
    int count;
    int cap;
} MapEdgeList;

typedef struct {
    MapEdgeList cross;
    MapEdgeList local;
    MapEdgeList unix_edges;
    MapEdgeList unresolved;
} TopologyMap;

void edge_list_init(MapEdgeList *list);
void edge_list_free(MapEdgeList *list);
void edge_list_add(MapEdgeList *list, MapEdge edge);

void topology_map_init(TopologyMap *map);
void topology_map_free(TopologyMap *map);

/*
 * build_topology_map
 *
 * Walks all enrolled nodes and resolves edges between identities.
 *
 * Current approach: For each egress connection, linear scan all nodes
 * and identities to find the matching listener. O(E * N * I) where
 * E = total egress connections, N = nodes, I = identities per node.
 *
 * Optimization path: Build a hashmap keyed on (addr, port) -> identity
 * before the edge walk. Reduces listener lookup to O(1), making the
 * overall build O(E) + O(L) where L = total listeners.
 * Same approach applies to unix socket inode matching.
 */
void build_topology_map(Session *s, TopologyMap *map);

#endif