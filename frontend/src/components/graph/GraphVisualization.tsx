'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Target,
  AlertTriangle,
  Globe,
  Server,
  Shield,
  Cpu,
  Network,
} from 'lucide-react';

// Dynamically import ForceGraph2D to avoid SSR issues
const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center">
      <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  ),
});

export interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'ip' | 'port' | 'service' | 'technology' | 'vulnerability' | 'cve' | 'cwe';
  properties?: Record<string, any>;
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
  properties?: Record<string, any>;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

interface GraphVisualizationProps {
  data: GraphData;
  onNodeClick?: (node: GraphNode) => void;
  onNodeHover?: (node: GraphNode | null) => void;
  selectedNodeId?: string | null;
  highlightPath?: string[];
  loading?: boolean;
  height?: number;
}

// Node colors by type
const NODE_COLORS: Record<string, string> = {
  domain: '#3b82f6',      // blue
  subdomain: '#60a5fa',   // light blue
  ip: '#8b5cf6',          // purple
  port: '#f59e0b',        // amber
  service: '#10b981',     // emerald
  technology: '#06b6d4',  // cyan
  vulnerability: '#ef4444', // red
  cve: '#dc2626',         // dark red
  cwe: '#f97316',         // orange
};

// Node icons by type
const NODE_ICONS: Record<string, React.ElementType> = {
  domain: Globe,
  subdomain: Globe,
  ip: Server,
  port: Network,
  service: Cpu,
  technology: Cpu,
  vulnerability: AlertTriangle,
  cve: Shield,
  cwe: AlertTriangle,
};

export function GraphVisualization({
  data,
  onNodeClick,
  onNodeHover,
  selectedNodeId,
  highlightPath = [],
  loading = false,
  height = 600,
}: GraphVisualizationProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height });
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: height,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [height]);

  // Node paint function
  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = 12 / globalScale;
      const nodeSize = 8;
      
      const isSelected = selectedNodeId === node.id;
      const isHighlighted = highlightPath.includes(node.id);
      const isHovered = hoveredNode?.id === node.id;

      // Draw node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeSize, 0, 2 * Math.PI);
      ctx.fillStyle = NODE_COLORS[node.type] || '#6b7280';
      
      if (isSelected || isHighlighted) {
        ctx.shadowColor = NODE_COLORS[node.type] || '#6b7280';
        ctx.shadowBlur = 15;
      }
      
      ctx.fill();
      ctx.shadowBlur = 0;

      // Draw border for selected/hovered nodes
      if (isSelected || isHovered) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2 / globalScale;
        ctx.stroke();
      }

      // Draw label
      ctx.font = `${fontSize}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#e5e7eb';
      
      // Truncate label if too long
      const maxLength = 20;
      const displayLabel = label.length > maxLength ? label.substring(0, maxLength) + '...' : label;
      ctx.fillText(displayLabel, node.x, node.y + nodeSize + fontSize);
    },
    [selectedNodeId, highlightPath, hoveredNode]
  );

  // Link paint function
  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;
      
      const isHighlighted = highlightPath.includes(sourceId) && highlightPath.includes(targetId);
      
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);
      
      ctx.strokeStyle = isHighlighted ? '#ef4444' : '#4b5563';
      ctx.lineWidth = isHighlighted ? 2 / globalScale : 1 / globalScale;
      ctx.stroke();
    },
    [highlightPath]
  );

  // Zoom controls
  const handleZoomIn = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom * 1.3, 300);
    }
  };

  const handleZoomOut = () => {
    if (graphRef.current) {
      const currentZoom = graphRef.current.zoom();
      graphRef.current.zoom(currentZoom / 1.3, 300);
    }
  };

  const handleFitToScreen = () => {
    if (graphRef.current) {
      graphRef.current.zoomToFit(400, 50);
    }
  };

  const handleCenterOnNode = (nodeId: string) => {
    if (graphRef.current) {
      const node = data.nodes.find(n => n.id === nodeId);
      if (node && node.x !== undefined && node.y !== undefined) {
        graphRef.current.centerAt(node.x, node.y, 500);
        graphRef.current.zoom(2, 500);
      }
    }
  };

  // Center on selected node when it changes
  useEffect(() => {
    if (selectedNodeId) {
      handleCenterOnNode(selectedNodeId);
    }
  }, [selectedNodeId]);

  return (
    <div className="relative" ref={containerRef}>
      {/* Controls */}
      <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
        <Button
          variant="secondary"
          size="icon"
          onClick={handleZoomIn}
          className="bg-background/80 backdrop-blur"
        >
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          onClick={handleZoomOut}
          className="bg-background/80 backdrop-blur"
        >
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button
          variant="secondary"
          size="icon"
          onClick={handleFitToScreen}
          className="bg-background/80 backdrop-blur"
        >
          <Maximize2 className="h-4 w-4" />
        </Button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 bg-background/80 backdrop-blur rounded-lg p-3">
        <div className="text-xs font-medium mb-2">Node Types</div>
        <div className="grid grid-cols-3 gap-2 text-xs">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="capitalize">{type}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Hovered node info */}
      {hoveredNode && (
        <div className="absolute top-4 left-4 z-10 bg-background/95 backdrop-blur rounded-lg p-3 max-w-xs">
          <div className="flex items-center gap-2 mb-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: NODE_COLORS[hoveredNode.type] }}
            />
            <span className="font-medium text-sm">{hoveredNode.label}</span>
          </div>
          <Badge variant="outline" className="text-xs capitalize">
            {hoveredNode.type}
          </Badge>
          {hoveredNode.properties && Object.keys(hoveredNode.properties).length > 0 && (
            <div className="mt-2 text-xs text-muted-foreground space-y-1">
              {Object.entries(hoveredNode.properties).slice(0, 5).map(([key, value]) => (
                <div key={key}>
                  <span className="font-medium">{key}:</span> {String(value).substring(0, 50)}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Loading overlay */}
      {loading && (
        <div className="absolute inset-0 bg-background/50 flex items-center justify-center z-20">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
        </div>
      )}

      {/* Graph */}
      {data.nodes.length > 0 ? (
        <ForceGraph2D
          ref={graphRef}
          graphData={data}
          width={dimensions.width}
          height={dimensions.height}
          nodeCanvasObject={paintNode}
          linkCanvasObject={paintLink}
          nodeLabel={() => ''}
          onNodeClick={(node: any) => onNodeClick?.(node as GraphNode)}
          onNodeHover={(node: any) => {
            setHoveredNode(node as GraphNode | null);
            onNodeHover?.(node as GraphNode | null);
          }}
          cooldownTicks={100}
          onEngineStop={() => graphRef.current?.zoomToFit(400, 50)}
          enableNodeDrag={true}
          backgroundColor="transparent"
        />
      ) : (
        <div
          className="flex items-center justify-center text-muted-foreground"
          style={{ height: dimensions.height }}
        >
          <div className="text-center">
            <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No graph data available</p>
            <p className="text-sm mt-2">Sync data from PostgreSQL to Neo4j first</p>
          </div>
        </div>
      )}
    </div>
  );
}

// Stats card for graph overview
interface GraphStatsProps {
  stats: {
    total_nodes: number;
    total_relationships: number;
    node_types: Record<string, number>;
    relationship_types: Record<string, number>;
  };
}

export function GraphStats({ stats }: GraphStatsProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{stats.total_nodes}</div>
          <div className="text-sm text-muted-foreground">Total Nodes</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{stats.total_relationships}</div>
          <div className="text-sm text-muted-foreground">Relationships</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{Object.keys(stats.node_types).length}</div>
          <div className="text-sm text-muted-foreground">Node Types</div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="pt-4">
          <div className="text-2xl font-bold">{Object.keys(stats.relationship_types).length}</div>
          <div className="text-sm text-muted-foreground">Relationship Types</div>
        </CardContent>
      </Card>
    </div>
  );
}
