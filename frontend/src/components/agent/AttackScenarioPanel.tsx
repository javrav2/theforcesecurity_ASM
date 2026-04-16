'use client';

import { useCallback, useEffect, useRef, useState, useMemo } from 'react';
import dynamic from 'next/dynamic';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ZoomIn, ZoomOut, Maximize2, ChevronRight, ChevronDown,
  CheckCircle, XCircle, AlertTriangle, Target, Loader2,
  Shield, Crosshair, Eye, ChevronLeft,
} from 'lucide-react';

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  ),
});

export interface ScenarioNode {
  id: string;
  label: string;
  type: string;
  properties?: Record<string, any>;
  x?: number;
  y?: number;
}

export interface ScenarioEdge {
  source: string;
  target: string;
  type: string;
}

export interface AttackPath {
  assets?: string[];
  relationships?: string[];
  target_cve?: string;
  severity?: string;
  nodes?: { properties?: { value?: string }; labels?: string[] }[];
}

export interface ChainData {
  nodes: ScenarioNode[];
  edges: ScenarioEdge[];
  meta?: {
    session_id?: string;
    objective?: string;
    status?: string;
    step_count?: number;
    final_phase?: string;
  };
  attack_paths?: AttackPath[];
}

interface AttackScenarioPanelProps {
  chainData: ChainData | null;
  loading?: boolean;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

const NODE_COLORS: Record<string, string> = {
  chain: '#3b82f6',
  step: '#8b5cf6',
  finding: '#10b981',
  finding_info: '#06b6d4',
  finding_low: '#22c55e',
  finding_medium: '#f59e0b',
  finding_high: '#ef4444',
  finding_critical: '#dc2626',
  failure: '#ef4444',
};

const PHASE_COLORS: Record<string, string> = {
  informational: '#3b82f6',
  reconnaissance: '#8b5cf6',
  enumeration: '#06b6d4',
  vulnerability_analysis: '#f59e0b',
  exploitation: '#ef4444',
  post_exploitation: '#dc2626',
  reporting: '#10b981',
};

export function AttackScenarioPanel({
  chainData,
  loading = false,
  collapsed = false,
  onToggleCollapse,
}: AttackScenarioPanelProps) {
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 400, height: 300 });
  const [selectedNode, setSelectedNode] = useState<ScenarioNode | null>(null);
  const [viewMode, setViewMode] = useState<'graph' | 'timeline'>('timeline');
  const [hoveredNode, setHoveredNode] = useState<ScenarioNode | null>(null);

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: 300,
        });
      }
    };
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, [collapsed]);

  const graphData = useMemo(() => {
    if (!chainData) return { nodes: [], links: [] };
    return {
      nodes: chainData.nodes.map(n => ({ ...n })),
      links: chainData.edges.map(e => ({ ...e })),
    };
  }, [chainData]);

  const steps = useMemo(() => {
    if (!chainData) return [];
    return chainData.nodes
      .filter(n => n.type !== 'chain' && !n.type.startsWith('finding'))
      .sort((a, b) => (a.properties?.iteration || 0) - (b.properties?.iteration || 0));
  }, [chainData]);

  const findings = useMemo(() => {
    if (!chainData) return [];
    return chainData.nodes.filter(n => n.type.startsWith('finding'));
  }, [chainData]);

  const phases = useMemo(() => {
    const seen = new Set<string>();
    return steps
      .map(s => s.properties?.phase)
      .filter((p): p is string => !!p && !seen.has(p) && (seen.add(p), true));
  }, [steps]);

  const paintNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const label = node.label || node.id;
      const fontSize = 10 / globalScale;
      const isSelected = selectedNode?.id === node.id;
      const isHovered = hoveredNode?.id === node.id;

      let nodeSize = 6;
      if (node.type === 'chain') nodeSize = 10;
      if (node.type.startsWith('finding_critical') || node.type.startsWith('finding_high')) nodeSize = 8;

      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeSize, 0, 2 * Math.PI);
      ctx.fillStyle = NODE_COLORS[node.type] || '#6b7280';

      if (isSelected || isHovered) {
        ctx.shadowColor = ctx.fillStyle;
        ctx.shadowBlur = 12;
      }
      ctx.fill();
      ctx.shadowBlur = 0;

      if (isSelected || isHovered) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5 / globalScale;
        ctx.stroke();
      }

      ctx.font = `${fontSize}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#d1d5db';
      const maxLen = 18;
      const display = label.length > maxLen ? label.substring(0, maxLen) + '...' : label;
      ctx.fillText(display, node.x, node.y + nodeSize + fontSize);
    },
    [selectedNode, hoveredNode]
  );

  const paintLink = useCallback(
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      ctx.beginPath();
      ctx.moveTo(link.source.x, link.source.y);
      ctx.lineTo(link.target.x, link.target.y);

      const isProduced = link.type === 'PRODUCED';
      ctx.strokeStyle = isProduced ? '#ef4444' : '#4b5563';
      ctx.lineWidth = (isProduced ? 1.5 : 0.8) / globalScale;
      ctx.stroke();

      // Arrow
      const dx = link.target.x - link.source.x;
      const dy = link.target.y - link.source.y;
      const angle = Math.atan2(dy, dx);
      const arrowLen = 4 / globalScale;
      const tx = link.target.x - Math.cos(angle) * 8;
      const ty = link.target.y - Math.sin(angle) * 8;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(tx - arrowLen * Math.cos(angle - Math.PI / 6), ty - arrowLen * Math.sin(angle - Math.PI / 6));
      ctx.lineTo(tx - arrowLen * Math.cos(angle + Math.PI / 6), ty - arrowLen * Math.sin(angle + Math.PI / 6));
      ctx.closePath();
      ctx.fillStyle = ctx.strokeStyle;
      ctx.fill();
    },
    []
  );

  const handleFitToScreen = () => {
    if (graphRef.current) graphRef.current.zoomToFit(300, 30);
  };

  if (collapsed) {
    return (
      <div className="w-10 shrink-0">
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggleCollapse}
          className="h-full w-10 p-0 flex flex-col items-center gap-1 text-muted-foreground hover:text-foreground"
          title="Show Attack Scenario"
        >
          <ChevronLeft className="h-4 w-4" />
          <span className="text-[10px] writing-mode-vertical" style={{ writingMode: 'vertical-lr' }}>
            Attack Scenario
          </span>
        </Button>
      </div>
    );
  }

  const isEmpty = !chainData || chainData.nodes.length === 0;

  return (
    <Card className="w-[420px] shrink-0 flex flex-col max-h-[calc(100vh-200px)]">
      <CardHeader className="pb-2 px-3 pt-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-1.5">
            <Crosshair className="h-4 w-4 text-red-500" />
            Attack Scenario
          </CardTitle>
          <div className="flex items-center gap-1">
            {chainData?.meta?.status && (
              <Badge
                variant="outline"
                className={`text-[10px] ${chainData.meta.status === 'running' ? 'text-yellow-500 border-yellow-500' : 'text-green-500 border-green-500'}`}
              >
                {chainData.meta.status}
              </Badge>
            )}
            <div className="flex border rounded-md overflow-hidden">
              <Button
                variant={viewMode === 'timeline' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('timeline')}
                className="h-6 px-2 rounded-none text-[10px]"
              >
                Timeline
              </Button>
              <Button
                variant={viewMode === 'graph' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('graph')}
                className="h-6 px-2 rounded-none text-[10px]"
              >
                Graph
              </Button>
            </div>
            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onToggleCollapse}>
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
        {chainData?.meta?.objective && (
          <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2">
            {chainData.meta.objective}
          </p>
        )}
      </CardHeader>

      <CardContent className="p-0 flex-1 overflow-hidden flex flex-col">
        {/* Stats bar */}
        {!isEmpty && (
          <div className="flex gap-3 px-3 py-1.5 border-b text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <Target className="h-3 w-3" /> {steps.length} steps
            </span>
            <span className="flex items-center gap-1">
              <Shield className="h-3 w-3 text-emerald-500" /> {findings.length} findings
            </span>
            <span className="flex items-center gap-1">
              <Eye className="h-3 w-3" /> {phases.length} phases
            </span>
          </div>
        )}

        {/* Phase progress */}
        {phases.length > 0 && (
          <div className="flex gap-1 px-3 py-1.5 border-b overflow-x-auto">
            {phases.map((phase, i) => (
              <Badge
                key={phase}
                variant="outline"
                className="text-[9px] shrink-0"
                style={{ borderColor: PHASE_COLORS[phase] || '#6b7280', color: PHASE_COLORS[phase] || '#6b7280' }}
              >
                {phase.replace(/_/g, ' ')}
              </Badge>
            ))}
          </div>
        )}

        {isEmpty && !loading && (
          <div className="flex-1 flex items-center justify-center text-muted-foreground p-6">
            <div className="text-center">
              <Crosshair className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-xs">No attack scenario yet</p>
              <p className="text-[10px] mt-1">
                The agent will build an attack graph as it tests resources
              </p>
            </div>
          </div>
        )}

        {loading && isEmpty && (
          <div className="flex-1 flex items-center justify-center p-6">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        )}

        {/* Graph view */}
        {viewMode === 'graph' && !isEmpty && (
          <div className="relative flex-1 min-h-[300px]" ref={containerRef}>
            <div className="absolute top-2 right-2 z-10 flex gap-1">
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() * 1.3, 300)}>
                <ZoomIn className="h-3 w-3" />
              </Button>
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={() => graphRef.current?.zoom(graphRef.current.zoom() / 1.3, 300)}>
                <ZoomOut className="h-3 w-3" />
              </Button>
              <Button variant="secondary" size="icon" className="h-6 w-6 bg-background/80" onClick={handleFitToScreen}>
                <Maximize2 className="h-3 w-3" />
              </Button>
            </div>
            {graphData.nodes.length > 0 && (
              <ForceGraph2D
                ref={graphRef}
                graphData={graphData}
                width={dimensions.width}
                height={dimensions.height}
                nodeCanvasObject={paintNode}
                linkCanvasObject={paintLink}
                nodeLabel={() => ''}
                onNodeClick={(node: any) => setSelectedNode(node)}
                onNodeHover={(node: any) => setHoveredNode(node)}
                cooldownTicks={80}
                onEngineStop={() => graphRef.current?.zoomToFit(300, 30)}
                enableNodeDrag={true}
                backgroundColor="transparent"
                dagMode="td"
                dagLevelDistance={40}
              />
            )}
          </div>
        )}

        {/* Timeline view */}
        {viewMode === 'timeline' && !isEmpty && (
          <div className="flex-1 overflow-y-auto">
            <div className="px-3 py-2 space-y-0.5">
              {steps.map((step, idx) => {
                const props = step.properties || {};
                const isSuccess = props.success === true;
                const isFail = props.success === false;
                const stepFindings = (props.findings || []).filter((f: any) => f.type);
                const stepFailures = (props.failures || []).filter((f: any) => f.tool);
                const isExpanded = selectedNode?.id === step.id;

                return (
                  <div key={step.id}>
                    <div
                      className={`flex items-start gap-2 rounded-md px-2 py-1.5 cursor-pointer transition-colors hover:bg-muted/60 ${isExpanded ? 'bg-muted' : ''}`}
                      onClick={() => setSelectedNode(isExpanded ? null : step)}
                    >
                      {/* Timeline connector */}
                      <div className="flex flex-col items-center pt-0.5 shrink-0">
                        <div
                          className="w-2 h-2 rounded-full border-2"
                          style={{
                            borderColor: PHASE_COLORS[props.phase] || '#6b7280',
                            backgroundColor: isSuccess ? (PHASE_COLORS[props.phase] || '#6b7280') : 'transparent',
                          }}
                        />
                        {idx < steps.length - 1 && (
                          <div className="w-px h-full min-h-[16px] bg-border mt-0.5" />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          {isSuccess && <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />}
                          {isFail && <XCircle className="h-3 w-3 text-red-500 shrink-0" />}
                          {!isSuccess && !isFail && <Loader2 className="h-3 w-3 text-muted-foreground shrink-0 animate-spin" />}
                          <code className="text-[11px] font-medium truncate">{step.label}</code>
                          <Badge variant="outline" className="text-[9px] ml-auto shrink-0" style={{ color: PHASE_COLORS[props.phase] || '#6b7280', borderColor: PHASE_COLORS[props.phase] || '#6b7280' }}>
                            {(props.phase || '').replace(/_/g, ' ')}
                          </Badge>
                        </div>
                        {props.thought && (
                          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">
                            {props.thought}
                          </p>
                        )}
                        {stepFindings.length > 0 && (
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            {stepFindings.map((f: any, fi: number) => (
                              <Badge key={fi} variant="outline" className={`text-[9px] ${f.severity === 'critical' || f.severity === 'high' ? 'text-red-500 border-red-500' : 'text-emerald-500 border-emerald-500'}`}>
                                <AlertTriangle className="h-2.5 w-2.5 mr-0.5" /> {f.type}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      {isExpanded ? <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground mt-0.5" /> : <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground mt-0.5" />}
                    </div>

                    {isExpanded && (
                      <div className="ml-6 pl-2 border-l border-border mb-1 space-y-1">
                        {props.tool_args && (
                          <div className="text-[10px]">
                            <span className="text-muted-foreground font-medium">Args: </span>
                            <code className="text-[10px] bg-muted px-1 rounded break-all">{typeof props.tool_args === 'string' ? props.tool_args : JSON.stringify(props.tool_args)}</code>
                          </div>
                        )}
                        {props.output_summary && (
                          <div className="text-[10px]">
                            <span className="text-muted-foreground font-medium">Output: </span>
                            <span className="text-muted-foreground">{props.output_summary}</span>
                          </div>
                        )}
                        {stepFindings.map((f: any, fi: number) => (
                          <div key={fi} className="text-[10px] bg-red-500/5 border border-red-500/20 rounded p-1.5">
                            <span className="font-medium text-red-500">[{f.severity}] {f.type}: </span>
                            <span className="text-muted-foreground">{f.description}</span>
                          </div>
                        ))}
                        {stepFailures.map((f: any, fi: number) => (
                          <div key={fi} className="text-[10px] bg-amber-500/5 border border-amber-500/20 rounded p-1.5">
                            <span className="font-medium text-amber-500">Lesson: </span>
                            <span className="text-muted-foreground">{f.lesson || f.error}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Findings summary */}
              {findings.length > 0 && (
                <div className="pt-2 border-t mt-2">
                  <p className="text-[10px] font-medium text-muted-foreground mb-1">Findings ({findings.length})</p>
                  {findings.map((f) => (
                    <div key={f.id} className="text-[10px] flex items-center gap-1 py-0.5">
                      <AlertTriangle className={`h-3 w-3 shrink-0 ${f.type.includes('critical') || f.type.includes('high') ? 'text-red-500' : 'text-emerald-500'}`} />
                      <span className="truncate">{f.label}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Neo4j Attack Paths */}
              {chainData?.attack_paths && chainData.attack_paths.length > 0 && (
                <div className="pt-2 border-t mt-2">
                  <p className="text-[10px] font-medium text-muted-foreground mb-1 flex items-center gap-1">
                    <Shield className="h-3 w-3" /> Attack Paths from Graph ({chainData.attack_paths.length})
                  </p>
                  {chainData.attack_paths.map((path, idx) => (
                    <div key={idx} className="text-[10px] bg-muted/50 rounded p-1.5 mb-1">
                      <div className="flex items-center gap-1 mb-0.5">
                        <Badge variant="outline" className="text-[9px]">Path {idx + 1}</Badge>
                        {path.target_cve && (
                          <Badge variant="outline" className="text-[9px] text-red-500 border-red-500">{path.target_cve}</Badge>
                        )}
                        {path.severity && (
                          <Badge variant="outline" className={`text-[9px] ${path.severity === 'critical' || path.severity === 'high' ? 'text-red-500 border-red-500' : 'text-amber-500 border-amber-500'}`}>{path.severity}</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-0.5 flex-wrap">
                        {(path.assets || path.nodes?.map(n => n.properties?.value || n.labels?.[0] || '?') || []).map((asset, ai) => (
                          <span key={ai} className="flex items-center gap-0.5">
                            <Badge variant="secondary" className="text-[9px]">{typeof asset === 'string' ? asset : String(asset)}</Badge>
                            {ai < ((path.assets || path.nodes || []).length - 1) && <span className="text-muted-foreground">→</span>}
                          </span>
                        ))}
                      </div>
                      {path.relationships && (
                        <p className="text-[9px] text-muted-foreground mt-0.5">
                          via: {path.relationships.join(' → ')}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
