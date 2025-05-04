"""
Domain entities for the Knowledge Graph component of the Digital Twin.
Pure domain models with no external dependencies.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4


class EdgeType(Enum):
    """Types of edges in the knowledge graph."""
    CAUSES = "causes"  # A causes B
    CORRELATES_WITH = "correlates_with"  # A correlates with B
    ALLEVIATES = "alleviates"  # A alleviates B
    EXACERBATES = "exacerbates"  # A exacerbates B
    PART_OF = "part_of"  # A is part of B
    PRECEDES = "precedes"  # A happens before B
    HAS_SYMPTOM = "has_symptom"  # A has symptom B
    TREATED_BY = "treated_by"  # A is treated by B
    INDICATES = "indicates"  # A indicates B
    CONTRAINDICATES = "contraindicates"  # A contraindicates B
    AFFECTS = "affects"  # A affects B


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""
    SYMPTOM = "symptom"
    DIAGNOSIS = "diagnosis"
    MEDICATION = "medication"
    THERAPY = "therapy"
    BEHAVIOR = "behavior"
    BIOMARKER = "biomarker"
    BRAIN_REGION = "brain_region"
    NEUROTRANSMITTER = "neurotransmitter"
    LIFE_EVENT = "life_event"
    COGNITIVE_PATTERN = "cognitive_pattern"
    PHYSIOLOGICAL_STATE = "physiological_state"


def ensure_enum_value(value, enum_class):
    """Convert string to enum value if necessary, or keep as enum value."""
    if isinstance(value, str):
        try:
            return enum_class(value)
        except ValueError:
            # If the string doesn't match any enum value, try matching by name
            try:
                return enum_class[value]
            except KeyError:
                # Return the original string if all conversions fail
                return value
    return value


@dataclass
class KnowledgeGraphNode:
    """A node in the knowledge graph."""
    id: UUID
    label: str
    node_type: NodeType
    properties: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0  # 0.0 to 1.0
    source: str | None = None  # e.g., "PAT", "MentalLLaMA", "XGBoost", "clinician"
    
    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.node_type = ensure_enum_value(self.node_type, NodeType)
    
    @classmethod
    def create(cls, label: str, node_type: NodeType, properties: dict = None, source: str = None, confidence: float = 1.0):
        """Factory method to create a new node."""
        return cls(
            id=uuid4(),
            label=label,
            node_type=node_type,
            properties=properties or {},
            source=source,
            confidence=confidence
        )


@dataclass
class KnowledgeGraphEdge:
    """An edge in the knowledge graph connecting two nodes."""
    id: UUID
    source_id: UUID
    target_id: UUID
    edge_type: EdgeType
    properties: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0  # 0.0 to 1.0
    source: str | None = None  # e.g., "PAT", "MentalLLaMA", "XGBoost", "clinician"
    temporal_constraints: dict | None = None  # Temporal constraints on this edge
    
    def __post_init__(self):
        """Ensure proper enum conversion after initialization."""
        self.edge_type = ensure_enum_value(self.edge_type, EdgeType)
    
    @classmethod
    def create(cls, source_id: UUID, target_id: UUID, edge_type: EdgeType, properties: dict = None, 
               source: str = None, confidence: float = 1.0, temporal_constraints: dict = None):
        """Factory method to create a new edge."""
        return cls(
            id=uuid4(),
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            properties=properties or {},
            source=source,
            confidence=confidence,
            temporal_constraints=temporal_constraints
        )


@dataclass
class TemporalKnowledgeGraph:
    """A temporal knowledge graph representing the patient's state over time."""
    patient_id: UUID
    nodes: dict[UUID, KnowledgeGraphNode] = field(default_factory=dict)
    edges: dict[UUID, KnowledgeGraphEdge] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def add_node(self, node: KnowledgeGraphNode) -> UUID:
        """Add a node to the graph."""
        self.nodes[node.id] = node
        self.last_updated = datetime.now()
        return node.id
    
    def add_edge(self, edge: KnowledgeGraphEdge) -> UUID:
        """Add an edge to the graph."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError("Both source and target nodes must exist in the graph")
        self.edges[edge.id] = edge
        self.last_updated = datetime.now()
        return edge.id
    
    def get_nodes_by_type(self, node_type: NodeType) -> list[KnowledgeGraphNode]:
        """Get all nodes of a specific type."""
        return [node for node in self.nodes.values() if node.node_type == node_type]
    
    def get_edges_by_type(self, edge_type: EdgeType) -> list[KnowledgeGraphEdge]:
        """Get all edges of a specific type."""
        return [edge for edge in self.edges.values() if edge.edge_type == edge_type]
    
    def get_node_neighbors(self, node_id: UUID) -> dict[EdgeType, list[KnowledgeGraphNode]]:
        """Get all neighboring nodes grouped by edge type."""
        if node_id not in self.nodes:
            raise ValueError(f"Node {node_id} not found in graph")
        
        neighbors = {}
        
        # Outgoing edges (source -> target)
        for edge in self.edges.values():
            if edge.source_id == node_id:
                if edge.edge_type not in neighbors:
                    neighbors[edge.edge_type] = []
                neighbors[edge.edge_type].append(self.nodes[edge.target_id])
        
        # Incoming edges (target <- source)
        for edge in self.edges.values():
            if edge.target_id == node_id:
                # Create a "reverse" edge type for incoming edges
                reverse_edge_type = EdgeType(f"reverse_{edge.edge_type.value}")
                if reverse_edge_type not in neighbors:
                    neighbors[reverse_edge_type] = []
                neighbors[reverse_edge_type].append(self.nodes[edge.source_id])
                
        return neighbors
    
    def get_temporal_subgraph(self, start_time: datetime, end_time: datetime) -> 'TemporalKnowledgeGraph':
        """Extract a subgraph containing only nodes and edges within a time range."""
        subgraph = TemporalKnowledgeGraph(patient_id=self.patient_id)
        
        # Add nodes within the time range
        for node_id, node in self.nodes.items():
            if start_time <= node.created_at <= end_time:
                subgraph.add_node(node)
        
        # Add edges within the time range
        for edge_id, edge in self.edges.items():
            if start_time <= edge.created_at <= end_time:
                # Only add the edge if both connected nodes exist in the subgraph
                if edge.source_id in subgraph.nodes and edge.target_id in subgraph.nodes:
                    subgraph.add_edge(edge)
        
        return subgraph
    
    def extract_patterns(self) -> list[dict]:
        """Extract temporal and causal patterns from the graph."""
        patterns = []
        
        # Find causal chains (A causes B causes C)
        causal_edges = self.get_edges_by_type(EdgeType.CAUSES)
        causal_chains = self._extract_chains(causal_edges)
        
        for chain in causal_chains:
            patterns.append({
                "type": "causal_chain",
                "nodes": [self.nodes[edge.source_id].label for edge in chain] + 
                         [self.nodes[chain[-1].target_id].label],
                "confidence": min(edge.confidence for edge in chain)
            })
        
        # Find temporal sequences (A precedes B precedes C)
        temporal_edges = self.get_edges_by_type(EdgeType.PRECEDES)
        temporal_chains = self._extract_chains(temporal_edges)
        
        for chain in temporal_chains:
            patterns.append({
                "type": "temporal_sequence",
                "nodes": [self.nodes[edge.source_id].label for edge in chain] + 
                         [self.nodes[chain[-1].target_id].label],
                "confidence": min(edge.confidence for edge in chain)
            })
        
        # Find symptom clusters (symptoms connected to the same diagnosis)
        for node in self.get_nodes_by_type(NodeType.DIAGNOSIS):
            symptom_edges = [e for e in self.edges.values() 
                              if e.target_id == node.id and e.edge_type == EdgeType.HAS_SYMPTOM]
            if len(symptom_edges) >= 3:  # At least 3 symptoms to form a cluster
                patterns.append({
                    "type": "symptom_cluster",
                    "diagnosis": node.label,
                    "symptoms": [self.nodes[edge.source_id].label for edge in symptom_edges],
                    "confidence": min(edge.confidence for edge in symptom_edges)
                })
        
        return patterns
    
    def _extract_chains(self, edges: list[KnowledgeGraphEdge]) -> list[list[KnowledgeGraphEdge]]:
        """Helper method to extract chains of connected edges."""
        # Build an adjacency list representation
        adjacency = {}
        for edge in edges:
            if edge.source_id not in adjacency:
                adjacency[edge.source_id] = []
            adjacency[edge.source_id].append(edge)
        
        chains = []
        for edge in edges:
            # Start a chain from each edge
            self._dfs_chain(edge, [], chains, adjacency)
        
        # Filter to keep only chains with at least 2 edges
        return [chain for chain in chains if len(chain) >= 2]
    
    def _dfs_chain(self, current_edge: KnowledgeGraphEdge, current_chain: list[KnowledgeGraphEdge], 
                   chains: list[list[KnowledgeGraphEdge]], adjacency: dict[UUID, list[KnowledgeGraphEdge]]):
        """Depth-first search to find chains of edges."""
        current_chain.append(current_edge)
        
        # If there are no outgoing edges from the target node, we've reached the end of a chain
        if current_edge.target_id not in adjacency:
            if len(current_chain) >= 2:
                chains.append(current_chain.copy())
            current_chain.pop()
            return
        
        # Explore all outgoing edges from the target node
        for next_edge in adjacency[current_edge.target_id]:
            self._dfs_chain(next_edge, current_chain, chains, adjacency)
        
        current_chain.pop()


@dataclass
class BayesianBeliefNetwork:
    """A Bayesian belief network for probabilistic reasoning about patient state."""
    patient_id: UUID
    variables: dict[str, dict] = field(default_factory=dict)  # Variable name -> properties
    conditional_probabilities: dict[str, dict] = field(default_factory=dict)  # Variable -> parent configurations -> probabilities
    evidence: dict[str, float] = field(default_factory=dict)  # Current evidence (variable -> value)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def add_variable(self, name: str, states: list[str], description: str | None = None) -> None:
        """Add a variable (node) to the network."""
        self.variables[name] = {
            "states": states,
            "description": description or name,
            "parents": []
        }
    
    def add_dependency(self, child: str, parent: str) -> None:
        """Add a dependency between variables (parent -> child)."""
        if child not in self.variables or parent not in self.variables:
            raise ValueError(f"Both child ({child}) and parent ({parent}) must exist in the network")
        
        self.variables[child]["parents"].append(parent)
    
    def set_conditional_probability(self, variable: str, parent_values: dict[str, str], probabilities: dict[str, float]) -> None:
        """Set the conditional probability for a variable given its parents' values."""
        if variable not in self.variables:
            raise ValueError(f"Variable {variable} not found in network")
        
        # Validate that all specified parents are actually parents of this variable
        for parent in parent_values:
            if parent not in self.variables[variable]["parents"]:
                raise ValueError(f"{parent} is not a parent of {variable}")
        
        # Validate that all parents are specified
        if len(parent_values) != len(self.variables[variable]["parents"]):
            raise ValueError(f"All parents of {variable} must be specified")
        
        # Validate that probabilities sum to approximately 1.0 (allowing for floating point errors)
        prob_sum = sum(probabilities.values())
        if not 0.99 <= prob_sum <= 1.01:
            raise ValueError(f"Probabilities for {variable} must sum to 1.0, got {prob_sum}")
        
        # Create parent configuration string
        config = self._parent_config_to_string(parent_values)
        
        if variable not in self.conditional_probabilities:
            self.conditional_probabilities[variable] = {}
        
        self.conditional_probabilities[variable][config] = probabilities
    
    def update_beliefs(self, evidence: dict[str, str]) -> None:
        """Update the network with new evidence."""
        for var, value in evidence.items():
            if var not in self.variables:
                raise ValueError(f"Variable {var} not found in network")
            if value not in self.variables[var]["states"]:
                raise ValueError(f"Value {value} is not a valid state for variable {var}")
            
            self.evidence[var] = value
        
        self.last_updated = datetime.now()
    
    def get_belief_state(self) -> dict[str, dict[str, float]]:
        """Get the current belief state (probability distribution for each variable)."""
        # This is a simplified approximation; a real implementation would use 
        # proper Bayesian inference algorithms like variable elimination
        beliefs = {}
        
        # Start with variables that have evidence
        for var, value in self.evidence.items():
            beliefs[var] = {state: 1.0 if state == value else 0.0 
                            for state in self.variables[var]["states"]}
        
        # Process variables in topological order (parents before children)
        ordered_vars = self._topological_sort()
        
        for var in ordered_vars:
            if var in beliefs:  # Already processed (has evidence)
                continue
                
            # Get parents and their values
            parents = self.variables[var]["parents"]
            
            # If any parent doesn't have a belief yet, skip for now
            if any(parent not in beliefs for parent in parents):
                continue
            
            # Initialize belief for this variable
            beliefs[var] = dict.fromkeys(self.variables[var]["states"], 0.0)
            
            # For each possible parent configuration
            for parent_config in self._generate_parent_configs(var, beliefs):
                config_str = self._parent_config_to_string(parent_config)
                
                # If we don't have this configuration, use uniform distribution
                if var not in self.conditional_probabilities or config_str not in self.conditional_probabilities[var]:
                    prob = 1.0 / len(self.variables[var]["states"])
                    for state in self.variables[var]["states"]:
                        beliefs[var][state] += prob * self._parent_config_probability(parent_config, beliefs)
                else:
                    # Use the defined conditional probabilities
                    for state, prob in self.conditional_probabilities[var][config_str].items():
                        beliefs[var][state] += prob * self._parent_config_probability(parent_config, beliefs)
        
        return beliefs
    
    def _parent_config_to_string(self, parent_values: dict[str, str]) -> str:
        """Convert parent configuration to a string key."""
        return ",".join(f"{parent}={value}" for parent, value in sorted(parent_values.items()))
    
    def _topological_sort(self) -> list[str]:
        """Sort variables so that parents come before children."""
        result = []
        visited = set()
        temp = set()
        
        def visit(node):
            if node in temp:
                raise ValueError("Cycle detected in Bayesian network")
            if node in visited:
                return
            
            temp.add(node)
            for parent in self.variables[node]["parents"]:
                visit(parent)
            
            temp.remove(node)
            visited.add(node)
            result.append(node)
        
        for node in self.variables:
            if node not in visited:
                visit(node)
        
        return result
    
    def _generate_parent_configs(self, var: str, beliefs: dict[str, dict[str, float]]) -> list[dict[str, str]]:
        """Generate all possible parent configurations for a variable."""
        parents = self.variables[var]["parents"]
        
        if not parents:
            return [{}]
        
        configs = [{}]
        for parent in parents:
            new_configs = []
            for config in configs:
                for state in self.variables[parent]["states"]:
                    new_config = config.copy()
                    new_config[parent] = state
                    new_configs.append(new_config)
            configs = new_configs
        
        return configs
    
    def _parent_config_probability(self, config: dict[str, str], beliefs: dict[str, dict[str, float]]) -> float:
        """Calculate the probability of a specific parent configuration."""
        prob = 1.0
        for parent, value in config.items():
            prob *= beliefs[parent][value]
        return prob