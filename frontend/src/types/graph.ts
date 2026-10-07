export interface GraphNode {
  id: string;
  type: string;
  label?: string;
  [key: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  confidence?: number;
  [key: string]: unknown;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
