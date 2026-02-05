"""
Call Graph Analysis Module

Builds function call graphs and extracts reentrancy indicators.

Why Graph Analysis?
- Reentrancy requires a CYCLE: 
  Contract → External Call → Callback → Contract (state corrupted)
- Static analysis alone can't detect multi-function reentrancy
- Graph cycles + external calls = high-confidence reentrancy signal

Graph Metrics:
1. Cycle Detection
   - Does call graph contain cycles?
   - Are external calls present within cycles?
   
2. Call Depth
   - Maximum path length from entry point
   - Deep call chains = higher complexity = higher risk
   
3. Centrality Analysis
   - Which functions are called most frequently?
   - Critical functions = higher impact if vulnerable
"""

from typing import Dict, List, Set, Tuple
from dataclasses import dataclass


@dataclass
class CallGraphMetrics:
    """
    Graph-based metrics for reentrancy detection.
    
    Attributes:
        has_cycles: Whether call graph contains any cycles
        cycle_count: Number of distinct cycles
        max_call_depth: Longest path in call graph
        functions_in_cycles: Set of function names in cycles
        external_calls_in_cycles: Number of external calls within cycles
    """
    has_cycles: bool
    cycle_count: int
    max_call_depth: int
    functions_in_cycles: Set[str]
    external_calls_in_cycles: int


class CallGraphBuilder:
    """
    Constructs and analyzes function call graphs using NetworkX.
    
    Graph Structure:
        - Nodes: Functions
        - Edges: Function calls (A → B means "A calls B")
        - Edge attributes: call type (internal, external, library)
    
    Usage:
        builder = CallGraphBuilder(slither_instance)
        graph = builder.build()
        metrics = builder.analyze()
    """
    
    def __init__(self, slither_instance):
        """
        Initialize with Slither analysis result.
        
        Args:
            slither_instance: Slither object containing contract info
        """
        self.slither = slither_instance
        # adjacency list representation: node -> set(successors)
        self.adj: Dict[str, Set[str]] = {}
        # external call counts per node
        self.external_calls: Dict[str, int] = {}
        self._built = False
        
    def build(self) -> Dict[str, Set[str]]:
        """
        Build directed call graph from contract.
        
        Returns:
            NetworkX DiGraph with functions as nodes, calls as edges
        """
        if self._built:
            return self.adj

        def fn_id(contract, function) -> str:
            try:
                return f"{contract.name}.{function.name}"
            except Exception:
                return str(function)

        for contract in self.slither.contracts:
            if contract.is_interface or contract.is_library:
                continue
            for function in contract.functions:
                node = fn_id(contract, function)
                self.adj.setdefault(node, set())

                # count external calls in this function
                ext_calls = 0
                if hasattr(function, 'external_calls_as_expressions'):
                    try:
                        ext_calls += len(function.external_calls_as_expressions)
                    except Exception:
                        pass
                if hasattr(function, 'internal_calls'):
                    try:
                        for call in function.internal_calls:
                            name = str(getattr(call, 'name', ''))
                            if 'call' in name.lower() or 'delegatecall' in name.lower():
                                ext_calls += 1
                    except Exception:
                        pass

                self.external_calls[node] = ext_calls

                # add edges for high_level_calls
                if hasattr(function, 'high_level_calls'):
                    try:
                        for hl in function.high_level_calls:
                            if isinstance(hl, (list, tuple)) and len(hl) >= 2:
                                called = hl[1]
                                try:
                                    called_node = f"{called.contract.name}.{called.name}"
                                    self.adj[node].add(called_node)
                                except Exception:
                                    self.adj[node].add(str(called))
                    except Exception:
                        pass

                # add edges for internal_calls fallback
                if hasattr(function, 'internal_calls'):
                    try:
                        for call in function.internal_calls:
                            called_fn = getattr(call, 'function', None)
                            if called_fn is not None:
                                try:
                                    called_node = f"{called_fn.contract.name}.{called_fn.name}"
                                    self.adj[node].add(called_node)
                                except Exception:
                                    self.adj[node].add(str(called_fn))
                    except Exception:
                        pass

        self._built = True
        return self.adj
    
    def analyze(self) -> CallGraphMetrics:
        """
        Extract graph-based security metrics.
        
        Returns:
            CallGraphMetrics object
        """
        # Ensure graph is built
        self.build()

        # compute max depth using DFS with memoization
        memo: Dict[str, int] = {}

        def dfs_depth(u: str, visiting: Set[str]) -> int:
            if u in memo:
                return memo[u]
            visiting.add(u)
            best = 0
            for v in self.adj.get(u, set()):
                if v in visiting:
                    # cycle encountered; don't follow into infinite recursion
                    continue
                d = 1 + dfs_depth(v, visiting)
                if d > best:
                    best = d
            visiting.remove(u)
            memo[u] = best
            return best

        max_depth = 0
        for node in list(self.adj.keys()):
            d = dfs_depth(node, set())
            if d > max_depth:
                max_depth = d

        # detect cycles
        cycles: List[List[str]] = []
        visited: Set[str] = set()
        stack: List[str] = []
        onstack: Set[str] = set()

        def dfs_cycles(u: str):
            visited.add(u)
            stack.append(u)
            onstack.add(u)
            for v in self.adj.get(u, set()):
                if v not in visited:
                    dfs_cycles(v)
                elif v in onstack:
                    try:
                        idx = stack.index(v)
                        cycles.append(stack[idx:].copy())
                    except ValueError:
                        pass
            stack.pop()
            onstack.remove(u)

        for n in list(self.adj.keys()):
            if n not in visited:
                dfs_cycles(n)

        has_cycles = len(cycles) > 0
        cycle_count = len(cycles)

        # count external calls in cycles
        functions_in_cycles: Set[str] = set()
        for cyc in cycles:
            for fn in cyc:
                functions_in_cycles.add(fn)

        external_calls_in_cycles = 0
        for fn in functions_in_cycles:
            external_calls_in_cycles += self.external_calls.get(fn, 0)

        return CallGraphMetrics(
            has_cycles=has_cycles,
            cycle_count=cycle_count,
            max_call_depth=max_depth,
            functions_in_cycles=functions_in_cycles,
            external_calls_in_cycles=external_calls_in_cycles,
        )
    
    def _detect_cycles(self) -> Tuple[bool, int]:
        """
        Detect cycles using DFS-based algorithm.
        
        Returns:
            (has_cycles: bool, cycle_count: int)
        """
        try:
            # NetworkX provides cycle detection
            cycles = list(nx.simple_cycles(self.graph))
            return len(cycles) > 0, len(cycles)
        except:
            return False, 0
    
    def _calculate_max_depth(self) -> int:
        """
        Calculate maximum call depth.
        
        Returns:
            Max depth (0 if no functions)
        """
        if len(self.graph.nodes) == 0:
            return 0
        
        # Find longest path from any entry point
        max_depth = 0
        for node in self.graph.nodes:
            if self.graph.in_degree(node) == 0:  # Entry point
                try:
                    depths = nx.single_source_shortest_path_length(self.graph, node)
                    max_depth = max(max_depth, max(depths.values()) if depths else 0)
                except:
                    pass
        
        return max_depth
    
    def _identify_external_calls_in_cycles(self) -> int:
        """
        Count external calls within cycle nodes.
        
        This is the KEY reentrancy indicator:
        Cycle + External Call = Potential Reentrancy
        
        Returns:
            Count of external calls in cycle nodes
        """
        metrics = self.analyze()
        return metrics.external_calls_in_cycles
