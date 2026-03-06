#include "map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void edge_list_init(MapEdgeList *list) {
    list->edges = NULL;
    list->count = 0;
    list->cap = 0;
}

void edge_list_free(MapEdgeList *list) {
    free(list->edges);
    list->edges = NULL;
    list->count = 0;
    list->cap = 0;
}

static MapEdge *edge_list_find(MapEdgeList *list, MapEdge *candidate) {
    for (int i = 0; i < list->count; i++) {
        MapEdge *e = &list->edges[i];
        if (e->port == candidate->port &&
            e->is_unix == candidate->is_unix &&
            strcmp(e->from_node, candidate->from_node) == 0 &&
            strcmp(e->from_exe, candidate->from_exe) == 0 &&
            strcmp(e->to_node, candidate->to_node) == 0 &&
            strcmp(e->to_exe, candidate->to_exe) == 0)
            return e;
    }
    return NULL;
}

void edge_list_add(MapEdgeList *list, MapEdge edge) {
    MapEdge *existing = edge_list_find(list, &edge);
    if (existing) {
        existing->count++;
        return;
    }

    if (list->count >= list->cap) {
        list->cap = list->cap ? list->cap * 2 : 64;
        list->edges = realloc(list->edges, sizeof(MapEdge) * list->cap);
    }
    edge.count = 1;
    list->edges[list->count++] = edge;
}

void topology_map_init(TopologyMap *map) {
    edge_list_init(&map->cross);
    edge_list_init(&map->local);
    edge_list_init(&map->unix_edges);
    edge_list_init(&map->unresolved);
}

void topology_map_free(TopologyMap *map) {
    edge_list_free(&map->cross);
    edge_list_free(&map->local);
    edge_list_free(&map->unix_edges);
    edge_list_free(&map->unresolved);
}

/*
 * find_listener
 *
 * Linear scan across all nodes/identities for a matching listener.
 * TODO: Replace with hashmap keyed on (addr_hash ^ port) for O(1) lookup.
 */
static Identity *find_listener(Session *s, const char *addr,
                                unsigned int port, int *out_node) {
    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            for (int j = 0; j < id->ingress_count; j++) {
                if (id->ingress[j].local_port != port) continue;
                int match =
                    strcmp(id->ingress[j].local_addr, "00000000") == 0 ||
                    strcmp(id->ingress[j].local_addr, "00000000000000000000000000000000") == 0 ||
                    strcmp(id->ingress[j].local_addr, addr) == 0;
                if (match) {
                    *out_node = n;
                    return id;
                }
            }
        }
    }
    return NULL;
}

static void make_edge(MapEdge *edge, const char *from_node, const char *from_exe,
                      const char *to_node, const char *to_exe,
                      unsigned int port, int protocol) {
    memset(edge, 0, sizeof(MapEdge));
    snprintf(edge->from_node, 64, "%s", from_node);
    snprintf(edge->from_exe, 256, "%s", from_exe);
    snprintf(edge->to_node, 64, "%s", to_node);
    snprintf(edge->to_exe, 256, "%s", to_exe);
    edge->port = port;
    edge->protocol = protocol;
}

static void resolve_egress(Session *s, int node_idx, Identity *id, TopologyMap *map) {
    for (int e = 0; e < id->egress_count; e++) {
        Connection *c = &id->egress[e];
        int dest_node;
        Identity *dest = find_listener(s, c->rem_addr, c->rem_port, &dest_node);

        MapEdge edge;
        make_edge(&edge, s->nodes[node_idx].ip, id->exe,
                  dest ? s->nodes[dest_node].ip : "???",
                  dest ? dest->exe : "???",
                  c->rem_port, c->protocol);

        if (!dest) {
            snprintf(edge.to_node, 64, "%s:%u", c->rem_addr, c->rem_port);
            edge_list_add(&map->unresolved, edge);
        } else if (strcmp(edge.from_node, edge.to_node) == 0) {
            edge_list_add(&map->local, edge);
        } else {
            edge_list_add(&map->cross, edge);
        }
    }
}

static void resolve_local(Session *s, int node_idx, Identity *id, TopologyMap *map) {
    for (int l = 0; l < id->local_count; l++) {
        Connection *c = &id->local[l];
        int dest_node;
        Identity *dest = find_listener(s, "0100007F", c->rem_port, &dest_node);
        if (!dest) continue;

        MapEdge edge;
        make_edge(&edge, s->nodes[node_idx].ip, id->exe,
                  s->nodes[node_idx].ip, dest->exe,
                  c->rem_port, c->protocol);
        edge.is_local = 1;
        edge_list_add(&map->local, edge);
    }
}

static void resolve_unix(Session *s, int node_idx, Identity *id,
                          MachineSnapshot *snap, int id_idx, TopologyMap *map) {
    for (int u = 0; u < id->unix_count; u++) {
        for (int j = id_idx + 1; j < snap->identity_count; j++) {
            Identity *peer = &snap->identities[j];
            for (int pu = 0; pu < peer->unix_count; pu++) {
                if (peer->unix_socks[pu].inode != id->unix_socks[u].inode) continue;

                MapEdge edge;
                make_edge(&edge, s->nodes[node_idx].ip, id->exe,
                          s->nodes[node_idx].ip, peer->exe, 0, 0);
                edge.is_unix = 1;
                snprintf(edge.unix_path, 256, "%s",
                    id->unix_socks[u].path[0] ? id->unix_socks[u].path : "(unnamed)");
                edge_list_add(&map->unix_edges, edge);
            }
        }
    }
}

void build_topology_map(Session *s, TopologyMap *map) {
    topology_map_init(map);

    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            resolve_egress(s, n, id, map);
            resolve_local(s, n, id, map);
            resolve_unix(s, n, id, snap, i, map);
        }
    }
}