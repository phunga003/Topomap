#include "map.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "command_utils.h"

static const char *known_proxies[] = {
    "envoy", "nginx", "haproxy", "pgbouncer",
    "flanneld", "kube-proxy", "traefik", "istio-proxy", "squid",
    NULL
};

static int is_proxy(const char *exe) {
    const char *name = strrchr(exe, '/');
    name = name ? name + 1 : exe;
    for (int i = 0; known_proxies[i]; i++) {
        if (strstr(name, known_proxies[i])) return 1;
    }
    return 0;
}

/*
 * Listener index: packed (node_idx << 16 | identity_idx)
 * Allows single int to recover both node and identity from session.
 */
static unsigned long listener_key(unsigned int port, int protocol) {
    return ((unsigned long)port << 16) | (protocol & 0xFFFF);
}

static int pack_index(int node_idx, int identity_idx) {
    return (node_idx << 16) | (identity_idx & 0xFFFF);
}

static void unpack_index(int packed, int *node_idx, int *identity_idx) {
    *node_idx = (packed >> 16) & 0xFFFF;
    *identity_idx = packed & 0xFFFF;
}

/*
 * Build listener hashmap: key = (port, protocol) -> packed(node, identity)
 * Build proxy hashmap: key = packed(node, identity) -> 1 if proxy
 * Both O(N*I) to build, O(1) to query.
 */
typedef struct {
    HashMap listeners;  // port+protocol -> packed index
    HashMap proxies;    // packed index -> 1 if proxy
} MapIndex;

static void build_index(Session *s, MapIndex *idx) {
    map_init(&idx->listeners);
    map_init(&idx->proxies);

    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            int packed = pack_index(n, i);

            if (is_proxy(id->exe))
                map_put(&idx->proxies, (unsigned long)packed, 1);

            for (int j = 0; j < id->ingress_count; j++) {
                if (id->ingress[j].state != 0x0A) continue;
                unsigned long key = listener_key(id->ingress[j].local_port,
                                                  id->ingress[j].protocol);
                map_put(&idx->listeners, key, packed);
            }
        }
    }
}

static void free_index(MapIndex *idx) {
    map_free(&idx->listeners);
    map_free(&idx->proxies);
}

static Identity *lookup_listener(Session *s, MapIndex *idx,
                                  unsigned int port, int protocol,
                                  int *out_node) {
    int packed;
    unsigned long key = listener_key(port, protocol);
    if (map_get(&idx->listeners, key, &packed) != 0) return NULL;

    int ni, ii;
    unpack_index(packed, &ni, &ii);
    *out_node = ni;
    return &s->nodes[ni].snap.identities[ii];
}

static int is_proxy_identity(MapIndex *idx, int node_idx, int identity_idx) {
    int val;
    int packed = pack_index(node_idx, identity_idx);
    return map_get(&idx->proxies, (unsigned long)packed, &val) == 0;
}

// --- edge building ---

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

void chain_list_init(ChainList *list) {
    list->chains = NULL;
    list->count = 0;
    list->cap = 0;
}

void chain_list_free(ChainList *list) {
    free(list->chains);
    list->chains = NULL;
    list->count = 0;
    list->cap = 0;
}

static void chain_list_add(ChainList *list, ResolvedChain chain) {
    list->count ++;
    if (list->count >= list->cap) {
        list->cap = list->cap ? list->cap * 2 : 32;
        list->chains = realloc(list->chains, sizeof(ResolvedChain) * list->cap);
    }
    list->chains[list->count++] = chain;
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

static void resolve_egress(Session *s, MapIndex *idx, int node_idx,
                           Identity *id, TopologyMap *map) {
    for (int e = 0; e < id->egress_count; e++) {
        Connection *c = &id->egress[e];
        int dest_node;
        Identity *dest = lookup_listener(s, idx, c->rem_port,
                                          c->protocol, &dest_node);

        MapEdge edge;
        make_edge(&edge, s->nodes[node_idx].ip, id->exe,
                  dest ? s->nodes[dest_node].ip : "???",
                  dest ? dest->exe : "???",
                  c->rem_port, c->protocol);

        if (!dest) {
            char addr_buf[64];
            snprintf(edge.to_node, 64, "%s:%u", 
                fmt_addr(c->rem_addr, addr_buf, sizeof(addr_buf)),
                c->rem_port);
            edge_list_add(&map->unresolved, edge);
        } else if (strcmp(edge.from_node, edge.to_node) == 0) {
            edge_list_add(&map->local, edge);
        } else {
            edge_list_add(&map->cross, edge);
        }
    }
}

static void resolve_local(Session *s, MapIndex *idx, int node_idx,
                          Identity *id, TopologyMap *map) {
    for (int l = 0; l < id->local_count; l++) {
        Connection *c = &id->local[l];
        int dest_node;
        Identity *dest = lookup_listener(s, idx, c->rem_port,
                                          c->protocol, &dest_node);
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

/*
 * resolve_proxy_chains
 *
 * For each non-proxy identity with local connections to a proxy,
 * trace the proxy's egress via hashmap lookup to find real destination.
 * O(L * P_egress) where L = local connections to proxies.
 */
static void resolve_proxy_chains(Session *s, MapIndex *idx, ChainList *chains) {
    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            if (is_proxy_identity(idx, n, i)) continue;

            for (int l = 0; l < id->local_count; l++) {
                Connection *lc = &id->local[l];
                int proxy_node;
                Identity *proxy = lookup_listener(s, idx, lc->rem_port,
                                                   lc->protocol, &proxy_node);

                if (!proxy) continue;
                if (proxy_node != n) continue;

                int proxy_idx = -1;
                for (int j = 0; j < snap->identity_count; j++) {
                    if (&snap->identities[j] == proxy) { proxy_idx = j; break; }
                }
                if (proxy_idx < 0) continue;
                if (!is_proxy_identity(idx, n, proxy_idx)) continue;

                for (int e = 0; e < proxy->egress_count; e++) {
                    Connection *ec = &proxy->egress[e];
                    int dest_node;
                    Identity *dest = lookup_listener(s, idx, ec->rem_port,
                                                      ec->protocol, &dest_node);
                    if (!dest) continue;

                    ResolvedChain chain = {
                        .source = id,
                        .source_node = n,
                        .dest = dest,
                        .dest_node = dest_node,
                        .proxy = proxy,
                        .proxy_node = n,
                        .port = ec->rem_port,
                        .protocol = ec->protocol
                    };
                    chain_list_add(chains, chain);
                }
            }
        }
    }
}

void build_topology_map(Session *s, TopologyMap *map, ChainList *chains) {
    topology_map_init(map);
    chain_list_init(chains);

    MapIndex idx;
    build_index(s, &idx);

    for (int n = 0; n < s->node_count; n++) {
        if (!s->nodes[n].has_snapshot) continue;
        MachineSnapshot *snap = &s->nodes[n].snap;

        for (int i = 0; i < snap->identity_count; i++) {
            Identity *id = &snap->identities[i];
            resolve_egress(s, &idx, n, id, map);
            resolve_local(s, &idx, n, id, map);
            resolve_unix(s, n, id, snap, i, map);
        }
    }

    resolve_proxy_chains(s, &idx, chains);
    free_index(&idx);
}