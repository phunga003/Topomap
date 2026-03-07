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

typedef struct {
    Identity *source;
    int source_node;
    Identity *dest;
    int dest_node;
    Identity *proxy;
    int proxy_node;
    unsigned int port;
    int protocol;
} ResolvedChain;

typedef struct {
    ResolvedChain *chains;
    int count;
    int cap;
} ChainList;

void chain_list_init(ChainList *list);
void chain_list_free(ChainList *list);
void build_topology_map(Session *s, TopologyMap *map, ChainList *chains);

void edge_list_init(MapEdgeList *list);
void edge_list_free(MapEdgeList *list);
void edge_list_add(MapEdgeList *list, MapEdge edge);

void topology_map_init(TopologyMap *map);
void topology_map_free(TopologyMap *map);


#endif