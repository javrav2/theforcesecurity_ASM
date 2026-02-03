declare module 'react-force-graph-2d' {
  import { Component, RefObject } from 'react';

  interface NodeObject {
    id?: string | number;
    x?: number;
    y?: number;
    vx?: number;
    vy?: number;
    fx?: number;
    fy?: number;
    [key: string]: any;
  }

  interface LinkObject {
    source?: string | number | NodeObject;
    target?: string | number | NodeObject;
    [key: string]: any;
  }

  interface GraphData {
    nodes: NodeObject[];
    links: LinkObject[];
  }

  interface ForceGraph2DProps {
    graphData?: GraphData;
    width?: number;
    height?: number;
    backgroundColor?: string;
    nodeRelSize?: number;
    nodeId?: string;
    nodeLabel?: string | ((node: NodeObject) => string);
    nodeVal?: number | string | ((node: NodeObject) => number);
    nodeColor?: string | ((node: NodeObject) => string);
    nodeAutoColorBy?: string | ((node: NodeObject) => string | null);
    nodeCanvasObject?: (node: NodeObject, ctx: CanvasRenderingContext2D, globalScale: number) => void;
    nodeCanvasObjectMode?: string | ((node: NodeObject) => string);
    linkSource?: string;
    linkTarget?: string;
    linkLabel?: string | ((link: LinkObject) => string);
    linkColor?: string | ((link: LinkObject) => string);
    linkAutoColorBy?: string | ((link: LinkObject) => string | null);
    linkWidth?: number | string | ((link: LinkObject) => number);
    linkCanvasObject?: (link: LinkObject, ctx: CanvasRenderingContext2D, globalScale: number) => void;
    linkCanvasObjectMode?: string | ((link: LinkObject) => string);
    linkDirectionalArrowLength?: number | string | ((link: LinkObject) => number);
    linkDirectionalArrowColor?: string | ((link: LinkObject) => string);
    linkDirectionalArrowRelPos?: number | string | ((link: LinkObject) => number);
    linkDirectionalParticles?: number | string | ((link: LinkObject) => number);
    linkDirectionalParticleSpeed?: number | string | ((link: LinkObject) => number);
    linkDirectionalParticleWidth?: number | string | ((link: LinkObject) => number);
    linkDirectionalParticleColor?: string | ((link: LinkObject) => string);
    dagMode?: 'td' | 'bu' | 'lr' | 'rl' | 'radialout' | 'radialin' | null;
    dagLevelDistance?: number | null;
    d3AlphaDecay?: number;
    d3VelocityDecay?: number;
    warmupTicks?: number;
    cooldownTicks?: number;
    cooldownTime?: number;
    onEngineTick?: () => void;
    onEngineStop?: () => void;
    onNodeClick?: (node: NodeObject, event: MouseEvent) => void;
    onNodeRightClick?: (node: NodeObject, event: MouseEvent) => void;
    onNodeHover?: (node: NodeObject | null, previousNode: NodeObject | null) => void;
    onNodeDrag?: (node: NodeObject, translate: { x: number; y: number }) => void;
    onNodeDragEnd?: (node: NodeObject, translate: { x: number; y: number }) => void;
    onLinkClick?: (link: LinkObject, event: MouseEvent) => void;
    onLinkRightClick?: (link: LinkObject, event: MouseEvent) => void;
    onLinkHover?: (link: LinkObject | null, previousLink: LinkObject | null) => void;
    onBackgroundClick?: (event: MouseEvent) => void;
    onBackgroundRightClick?: (event: MouseEvent) => void;
    enableNodeDrag?: boolean;
    enableZoomInteraction?: boolean;
    enablePanInteraction?: boolean;
    enablePointerInteraction?: boolean;
    minZoom?: number;
    maxZoom?: number;
    ref?: RefObject<any>;
  }

  interface ForceGraph2DInstance {
    zoom: (k?: number, duration?: number) => number;
    centerAt: (x?: number, y?: number, duration?: number) => void;
    zoomToFit: (duration?: number, padding?: number, nodeFilterFn?: (node: NodeObject) => boolean) => void;
    pauseAnimation: () => void;
    resumeAnimation: () => void;
    d3Force: (forceName: string, forceFn?: any) => any;
    d3ReheatSimulation: () => void;
    refresh: () => void;
  }

  export default class ForceGraph2D extends Component<ForceGraph2DProps> {
    zoom(k?: number, duration?: number): number;
    centerAt(x?: number, y?: number, duration?: number): void;
    zoomToFit(duration?: number, padding?: number, nodeFilterFn?: (node: NodeObject) => boolean): void;
    pauseAnimation(): void;
    resumeAnimation(): void;
    d3Force(forceName: string, forceFn?: any): any;
    d3ReheatSimulation(): void;
    refresh(): void;
  }
}
