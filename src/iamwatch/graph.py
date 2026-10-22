"""Directed multigraph + incremental, k-bounded "hops to ADMIN" table.

Edges are stored as   out[src][(dst, tech, target)] = conditional(bool)
and a predecessor index  pred[dst][src] = number of parallel edges.

dist[n] = minimum number of hops from n to ADMIN, kept only when <= k (so the table is
"k-bounded"; a missing node means "ADMIN is not reachable within k hops").

Incremental update (see update_dist): when the out-edges of a set S of nodes change, only
nodes that can reach S within k hops can have a different distance.  We recompute exactly
those nodes with a small Dijkstra seeded from the unaffected successors.  Cost is
proportional to the size of that k-hop backward neighbourhood, not to the whole graph.
"""
import heapq
from collections import deque

from .model import ADMIN

INF = 10 ** 9


class Graph:
    def __init__(self, k=5):
        self.k = k
        self.out = {}      # src -> {(dst, tech, target): cond}
        self.pred = {}     # dst -> {src: count}
        self.dist = {ADMIN: 0}

    # ------------------------------------------------------------------ edge storage
    def _index_add(self, src, dst):
        d = self.pred.setdefault(dst, {})
        d[src] = d.get(src, 0) + 1

    def _index_del(self, src, dst):
        d = self.pred.get(dst)
        if not d or src not in d:
            return
        d[src] -= 1
        if d[src] <= 0:
            del d[src]
        if not d:
            del self.pred[dst]

    def set_out(self, src, edges):
        """Replace ALL out-edges of src. `edges`: {(dst, tech, target): cond}. True if changed."""
        old = self.out.get(src, {})
        if old == edges:
            return False
        for key in old:
            self._index_del(src, key[0])
        for key in edges:
            self._index_add(src, key[0])
        if edges:
            self.out[src] = dict(edges)
        else:
            self.out.pop(src, None)
        return True

    def set_pair(self, src, dst, edges):
        """Replace the edges src->dst. `edges`: {(dst, tech, target): cond}. True if changed."""
        old = self.out.get(src, {})
        old_pair = {k: v for k, v in old.items() if k[0] == dst}
        if old_pair == edges:
            return False
        new = {k: v for k, v in old.items() if k[0] != dst}
        new.update(edges)
        for key in old_pair:
            self._index_del(src, dst)
        for key in edges:
            self._index_add(src, dst)
        if new:
            self.out[src] = new
        else:
            self.out.pop(src, None)
        return True

    def remove_node(self, node):
        """Delete a node. Returns the set of other nodes whose out-edges changed."""
        changed = set()
        for src in list(self.pred.get(node, {})):
            if src == node:
                continue
            new = {k: v for k, v in self.out.get(src, {}).items() if k[0] != node}
            self.set_out(src, new)
            changed.add(src)
        self.set_out(node, {})
        self.pred.pop(node, None)
        self.dist.pop(node, None)
        changed.discard(node)
        return changed

    def edge_set(self):
        return {(s, k[0], k[1], k[2], c) for s, es in self.out.items() for k, c in es.items()}

    # ------------------------------------------------------------------ distances
    def rebuild_dist(self):
        """Full reverse BFS from ADMIN (the oracle; also used at bootstrap)."""
        dist = {ADMIN: 0}
        q = deque([ADMIN])
        while q:
            v = q.popleft()
            if dist[v] >= self.k:
                continue
            for u in self.pred.get(v, ()):
                if u not in dist:
                    dist[u] = dist[v] + 1
                    q.append(u)
        self.dist = dist

    def update_dist_ball(self, changed):
        """Coarse repair: recompute EVERY node within k hops (backward) of a changed node.

        Kept only as a benchmark comparison for update_dist (the exact algorithm below).
        Incrementally repair dist after the out-edges of `changed` nodes were modified.

        Returns (improved, worsened, affected_size):
          improved  - nodes whose hop-distance to ADMIN decreased (new/shorter path exists)
          worsened  - nodes whose distance increased or became unreachable
        """
        k = self.k
        changed = {n for n in changed if n != ADMIN}
        affected = set()
        frontier = deque()
        for s in changed:
            affected.add(s)
            frontier.append((s, 0))
        while frontier:
            v, d = frontier.popleft()
            if d >= k:
                continue
            for u in self.pred.get(v, ()):
                if u not in affected and u != ADMIN:
                    affected.add(u)
                    frontier.append((u, d + 1))
        old = {n: self.dist.get(n, INF) for n in affected}
        for n in affected:
            self.dist.pop(n, None)
        heap = []
        for n in affected:
            best = INF
            for (dst, _t, _g) in self.out.get(n, {}):
                dd = self.dist.get(dst)
                if dd is not None and dd + 1 < best:
                    best = dd + 1
            if best <= k:
                heapq.heappush(heap, (best, n))
        done = set()
        while heap:
            d, n = heapq.heappop(heap)
            if n in done:
                continue
            done.add(n)
            self.dist[n] = d
            if d + 1 > k:
                continue
            for u in self.pred.get(n, ()):
                if u in affected and u not in done:
                    heapq.heappush(heap, (d + 1, u))
        improved = {n for n in affected if self.dist.get(n, INF) < old[n]}
        worsened = {n for n in affected if self.dist.get(n, INF) > old[n]}
        return improved, worsened, len(affected)


    def update_dist(self, changed):
        """Exact incremental repair of dist after the out-edges of `changed` nodes were modified.

        Dynamic single-sink shortest paths in the style of Ramalingam & Reps (1996), restricted to k hops:
          1. find the nodes that LOSE their support: a node x with dist[x]=d is supported while some
             successor y (not itself unsupported) has dist[y]=d-1.  Propagate along "tight" edges.
          2. recompute those nodes with a small Dijkstra seeded from the supported successors.
          3. propagate IMPROVEMENTS (new/shorter paths) backwards from every node whose out-edges changed.
        Only nodes whose distance really changes (plus their tight predecessors) are touched - far
        fewer than the whole k-hop neighbourhood, and independent of the total graph size.

        Returns (improved, worsened, touched):
          improved - nodes whose hop-distance to ADMIN decreased (new/shorter path exists)
          worsened - nodes whose distance increased or became unreachable
        """
        k = self.k
        dist = self.dist
        changed = {n for n in changed if n != ADMIN}
        old = {}                                   # snapshot of every node we touch
        touched = set()

        def snap(n):
            if n not in old:
                old[n] = dist.get(n, INF)

        def best_via(n, excluded=None):
            best = INF
            for (dst, _t, _g) in self.out.get(n, {}):
                if excluded is not None and dst in excluded:
                    continue
                dd = dist.get(dst)
                if dd is not None and dd + 1 < best:
                    best = dd + 1
            return best

        # ---- phase 1: nodes that lose their current shortest-path support
        unsupported = set()
        work = deque(changed)
        queued = set(changed)
        while work:
            x = work.popleft()
            queued.discard(x)
            dx = dist.get(x)
            if dx is None or dx == 0 or x in unsupported:
                continue
            supported = False
            for (dst, _t, _g) in self.out.get(x, {}):
                if dst in unsupported:
                    continue
                dd = dist.get(dst)
                if dd is not None and dd + 1 == dx:
                    supported = True
                    break
            if supported:
                continue
            unsupported.add(x)
            for p in self.pred.get(x, ()):
                dp = dist.get(p)
                if dp is not None and dp == dx + 1 and p not in unsupported and p not in queued:
                    work.append(p)
                    queued.add(p)
        # ---- phase 2: recompute the unsupported nodes
        for x in unsupported:
            snap(x)
            dist.pop(x, None)
        heap = []
        for x in unsupported:
            b = best_via(x)
            if b <= k:
                heapq.heappush(heap, (b, x))
        done = set()
        while heap:
            d, x = heapq.heappop(heap)
            if x in done:
                continue
            done.add(x)
            dist[x] = d
            if d + 1 > k:
                continue
            for p in self.pred.get(x, ()):
                if p in unsupported and p not in done:
                    heapq.heappush(heap, (d + 1, p))
        touched |= unsupported
        # ---- phase 3: improvements propagate backwards from every changed / recomputed node
        heap = []
        for u in changed:
            b = best_via(u)
            if b <= k and b < dist.get(u, INF):
                heapq.heappush(heap, (b, u))
        for u in changed | unsupported:          # a recomputed node may now offer its predecessors a shorter way
            du = dist.get(u)
            if du is None or du + 1 > k:
                continue
            for p in self.pred.get(u, ()):
                if p != ADMIN and du + 1 < dist.get(p, INF):
                    heapq.heappush(heap, (du + 1, p))
        while heap:
            d, x = heapq.heappop(heap)
            if d >= dist.get(x, INF):
                continue
            snap(x)
            dist[x] = d
            touched.add(x)
            if d + 1 > k:
                continue
            for p in self.pred.get(x, ()):
                if p != ADMIN and d + 1 < dist.get(p, INF):
                    heapq.heappush(heap, (d + 1, p))
        touched |= changed
        improved = {n for n in old if dist.get(n, INF) < old[n]}
        worsened = {n for n in old if dist.get(n, INF) > old[n]}
        return improved, worsened, len(touched)

    # ------------------------------------------------------------------ paths
    def paths_from(self, src, max_paths=100):
        """Enumerate simple paths src -> ADMIN of length <= k, shortest first.

        Each path is a list of hops (src, dst, tech, target, conditional).
        """
        results = []
        if self.dist.get(src, INF) > self.k:
            return results
        queue = deque([(src, (), frozenset([src]))])
        while queue and len(results) < max_paths:
            node, path, visited = queue.popleft()
            remaining = self.k - len(path)
            if remaining <= 0:
                continue
            for (dst, tech, target), cond in sorted(self.out.get(node, {}).items()):
                hop = (node, dst, tech, target, cond)
                if dst == ADMIN:
                    results.append(list(path) + [hop])
                    if len(results) >= max_paths:
                        break
                elif dst not in visited and self.dist.get(dst, INF) + 1 <= remaining:
                    queue.append((dst, path + (hop,), visited | {dst}))
        results.sort(key=len)
        return results

    # ------------------------------------------------------------------ (de)serialisation
    def to_dict(self):
        return {
            "k": self.k,
            "edges": [[s, k[0], k[1], k[2], c] for s, es in self.out.items() for k, c in es.items()],
            "dist": self.dist,
        }

    @classmethod
    def from_dict(cls, d):
        g = cls(d["k"])
        for s, dst, tech, target, cond in d["edges"]:
            g.out.setdefault(s, {})[(dst, tech, target)] = cond
            g._index_add(s, dst)
        g.dist = dict(d["dist"])
        g.dist[ADMIN] = 0
        return g
