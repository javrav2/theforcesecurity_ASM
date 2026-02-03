'use client';

import { useEffect, useState, useCallback } from 'react';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  GraphVisualization,
  GraphStats,
  GraphNode,
  GraphData,
} from '@/components/graph/GraphVisualization';
import {
  RefreshCw,
  GitBranch,
  Database,
  AlertTriangle,
  Search,
  Target,
  Route,
  Shield,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface GraphStatus {
  connected: boolean;
  enabled: boolean;
  uri?: string;
  node_count?: number;
  relationship_count?: number;
}

interface Organization {
  id: number;
  name: string;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  asset_type: string;
}

export default function GraphPage() {
  const [status, setStatus] = useState<GraphStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [graphLoading, setGraphLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [highlightPath, setHighlightPath] = useState<string[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('all');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [attackPathSource, setAttackPathSource] = useState<string>('');
  const [attackPathTarget, setAttackPathTarget] = useState<string>('');
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState('explorer');
  const { toast } = useToast();

  // Fetch graph status
  const fetchStatus = async () => {
    try {
      const data = await api.getGraphStatus();
      setStatus(data);
    } catch (error) {
      console.error('Failed to fetch graph status:', error);
      setStatus({ connected: false, enabled: false });
    } finally {
      setLoading(false);
    }
  };

  // Fetch organizations
  const fetchOrganizations = async () => {
    try {
      const data = await api.getOrganizations();
      setOrganizations(data);
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    }
  };

  // Fetch assets for dropdown
  const fetchAssets = async () => {
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const data = await api.getAssets({ 
        organization_id: orgId, 
        limit: 500,
        asset_type: 'domain'
      });
      setAssets(data.items || data || []);
    } catch (error) {
      console.error('Failed to fetch assets:', error);
    }
  };

  // Sync graph data
  const handleSync = async () => {
    setSyncing(true);
    try {
      const orgId = selectedOrg !== 'all' ? parseInt(selectedOrg) : undefined;
      const result = await api.syncGraph(orgId);
      toast({
        title: 'Graph Synced',
        description: `Synced ${result.assets_synced || 0} assets to Neo4j`,
      });
      await fetchStatus();
      // Refresh graph visualization if we have an asset selected
      if (selectedAssetId) {
        await loadAssetRelationships(parseInt(selectedAssetId));
      }
    } catch (error: any) {
      toast({
        title: 'Sync Failed',
        description: error?.response?.data?.detail || 'Failed to sync graph data',
        variant: 'destructive',
      });
    } finally {
      setSyncing(false);
    }
  };

  // Load asset relationships
  const loadAssetRelationships = async (assetId: number) => {
    setGraphLoading(true);
    setHighlightPath([]);
    try {
      const data = await api.getAssetRelationships(assetId, 3);
      
      // Transform to graph format
      const nodes: GraphNode[] = data.nodes?.map((n: any) => ({
        id: n.id || n.element_id,
        label: n.properties?.value || n.properties?.name || n.labels?.[0] || 'Unknown',
        type: mapNeo4jLabelToType(n.labels?.[0]),
        properties: n.properties,
      })) || [];
      
      const links = data.relationships?.map((r: any) => ({
        source: r.start_node || r.source,
        target: r.end_node || r.target,
        type: r.type,
        properties: r.properties,
      })) || [];
      
      setGraphData({ nodes, links });
    } catch (error: any) {
      toast({
        title: 'Failed to load relationships',
        description: error?.response?.data?.detail || 'Could not fetch asset relationships',
        variant: 'destructive',
      });
      setGraphData({ nodes: [], links: [] });
    } finally {
      setGraphLoading(false);
    }
  };

  // Find attack paths
  const findAttackPaths = async () => {
    if (!attackPathSource || !attackPathTarget) {
      toast({
        title: 'Select Assets',
        description: 'Please select both source and target assets',
        variant: 'destructive',
      });
      return;
    }

    setGraphLoading(true);
    try {
      const data = await api.getAttackPaths({
        source_id: parseInt(attackPathSource),
        target_id: parseInt(attackPathTarget),
        max_paths: 5,
      });
      
      setAttackPaths(data.paths || []);
      
      // Highlight first path if available
      if (data.paths && data.paths.length > 0) {
        const pathNodeIds = data.paths[0].nodes?.map((n: any) => n.id || n.element_id) || [];
        setHighlightPath(pathNodeIds);
        
        // Also update graph data to show the path
        const nodes: GraphNode[] = data.paths[0].nodes?.map((n: any) => ({
          id: n.id || n.element_id,
          label: n.properties?.value || n.properties?.name || 'Unknown',
          type: mapNeo4jLabelToType(n.labels?.[0]),
          properties: n.properties,
        })) || [];
        
        const links = data.paths[0].relationships?.map((r: any) => ({
          source: r.start_node || r.source,
          target: r.end_node || r.target,
          type: r.type,
        })) || [];
        
        setGraphData({ nodes, links });
      }
      
      toast({
        title: 'Attack Paths Found',
        description: `Found ${data.paths?.length || 0} potential attack paths`,
      });
    } catch (error: any) {
      toast({
        title: 'Search Failed',
        description: error?.response?.data?.detail || 'Could not find attack paths',
        variant: 'destructive',
      });
    } finally {
      setGraphLoading(false);
    }
  };

  // Map Neo4j labels to our node types
  const mapNeo4jLabelToType = (label: string): GraphNode['type'] => {
    const mapping: Record<string, GraphNode['type']> = {
      Asset: 'domain',
      Domain: 'domain',
      Subdomain: 'subdomain',
      IP: 'ip',
      Port: 'port',
      Service: 'service',
      Technology: 'technology',
      Vulnerability: 'vulnerability',
      CVE: 'cve',
      CWE: 'cwe',
    };
    return mapping[label] || 'domain';
  };

  // Handle node click
  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
  };

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchOrganizations();
  }, []);

  // Fetch assets when org changes
  useEffect(() => {
    fetchAssets();
  }, [selectedOrg]);

  // Load relationships when asset is selected
  useEffect(() => {
    if (selectedAssetId) {
      loadAssetRelationships(parseInt(selectedAssetId));
    }
  }, [selectedAssetId]);

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center h-screen">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Header 
        title="Asset Relationship Graph" 
        subtitle="Visualize connections between assets, vulnerabilities, and attack paths"
      />

      <div className="p-6 space-y-6">
        {/* Status Card */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-lg flex items-center gap-2">
                <Database className="h-5 w-5" />
                Neo4j Graph Database
              </CardTitle>
              <CardDescription>
                Relationship mapping for attack surface analysis
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant={status?.connected ? 'default' : 'destructive'}>
                {status?.connected ? (
                  <><CheckCircle className="h-3 w-3 mr-1" /> Connected</>
                ) : (
                  <><XCircle className="h-3 w-3 mr-1" /> Disconnected</>
                )}
              </Badge>
              <Button onClick={handleSync} disabled={syncing || !status?.connected}>
                {syncing ? (
                  <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Syncing...</>
                ) : (
                  <><RefreshCw className="h-4 w-4 mr-2" /> Sync Data</>
                )}
              </Button>
            </div>
          </CardHeader>
          {status?.connected && (
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{status.node_count || 0}</div>
                  <div className="text-sm text-muted-foreground">Total Nodes</div>
                </div>
                <div className="p-3 bg-muted/50 rounded-lg">
                  <div className="text-2xl font-bold">{status.relationship_count || 0}</div>
                  <div className="text-sm text-muted-foreground">Relationships</div>
                </div>
              </div>
            </CardContent>
          )}
        </Card>

        {!status?.connected && (
          <Card className="border-yellow-500/50 bg-yellow-500/10">
            <CardContent className="pt-6">
              <div className="flex items-start gap-4">
                <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold text-yellow-500">Neo4j Not Connected</h3>
                  <p className="text-sm text-muted-foreground mt-1">
                    The graph database is not connected. To enable graph visualization:
                  </p>
                  <ol className="list-decimal list-inside text-sm text-muted-foreground mt-2 space-y-1">
                    <li>Set NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD environment variables</li>
                    <li>Start Neo4j with: <code className="bg-muted px-1 rounded">docker compose --profile graph up -d</code></li>
                    <li>Refresh this page and click "Sync Data"</li>
                  </ol>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {status?.connected && (
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="explorer" className="flex items-center gap-2">
                <GitBranch className="h-4 w-4" />
                Relationship Explorer
              </TabsTrigger>
              <TabsTrigger value="attack-paths" className="flex items-center gap-2">
                <Route className="h-4 w-4" />
                Attack Paths
              </TabsTrigger>
              <TabsTrigger value="impact" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Vulnerability Impact
              </TabsTrigger>
            </TabsList>

            {/* Relationship Explorer Tab */}
            <TabsContent value="explorer" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Select Asset to Explore</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-4">
                    <Select value={selectedOrg} onValueChange={setSelectedOrg}>
                      <SelectTrigger className="w-[200px]">
                        <SelectValue placeholder="All Organizations" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Organizations</SelectItem>
                        {organizations.map((org) => (
                          <SelectItem key={org.id} value={org.id.toString()}>
                            {org.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <Select value={selectedAssetId} onValueChange={setSelectedAssetId}>
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Select an asset to explore..." />
                      </SelectTrigger>
                      <SelectContent>
                        {assets.map((asset) => (
                          <SelectItem key={asset.id} value={asset.id.toString()}>
                            {asset.value} ({asset.asset_type})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                {/* Graph Visualization */}
                <Card className="lg:col-span-3">
                  <CardContent className="p-0">
                    <GraphVisualization
                      data={graphData}
                      onNodeClick={handleNodeClick}
                      selectedNodeId={selectedNode?.id}
                      highlightPath={highlightPath}
                      loading={graphLoading}
                      height={600}
                    />
                  </CardContent>
                </Card>

                {/* Selected Node Details */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Node Details</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {selectedNode ? (
                      <div className="space-y-4">
                        <div>
                          <div className="text-sm text-muted-foreground">Label</div>
                          <div className="font-medium break-all">{selectedNode.label}</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground">Type</div>
                          <Badge variant="outline" className="capitalize">
                            {selectedNode.type}
                          </Badge>
                        </div>
                        {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                          <div>
                            <div className="text-sm text-muted-foreground mb-2">Properties</div>
                            <div className="space-y-2 text-sm">
                              {Object.entries(selectedNode.properties).map(([key, value]) => (
                                <div key={key} className="flex justify-between">
                                  <span className="text-muted-foreground">{key}</span>
                                  <span className="font-medium truncate max-w-[150px]">
                                    {String(value)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center text-muted-foreground py-8">
                        <Target className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p>Click a node to view details</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            {/* Attack Paths Tab */}
            <TabsContent value="attack-paths" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Find Attack Paths</CardTitle>
                  <CardDescription>
                    Discover potential attack paths between assets
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-4 items-end">
                    <div className="flex-1">
                      <label className="text-sm text-muted-foreground mb-2 block">
                        Source Asset (Entry Point)
                      </label>
                      <Select value={attackPathSource} onValueChange={setAttackPathSource}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select source asset..." />
                        </SelectTrigger>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id.toString()}>
                              {asset.value}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex-1">
                      <label className="text-sm text-muted-foreground mb-2 block">
                        Target Asset (Goal)
                      </label>
                      <Select value={attackPathTarget} onValueChange={setAttackPathTarget}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select target asset..." />
                        </SelectTrigger>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id.toString()}>
                              {asset.value}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <Button onClick={findAttackPaths} disabled={graphLoading}>
                      {graphLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <><Search className="h-4 w-4 mr-2" /> Find Paths</>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {attackPaths.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">
                      Found {attackPaths.length} Attack Path{attackPaths.length > 1 ? 's' : ''}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {attackPaths.map((path, index) => (
                        <div
                          key={index}
                          className="p-3 bg-muted/50 rounded-lg cursor-pointer hover:bg-muted"
                          onClick={() => {
                            const pathNodeIds = path.nodes?.map((n: any) => n.id || n.element_id) || [];
                            setHighlightPath(pathNodeIds);
                          }}
                        >
                          <div className="flex items-center gap-2 text-sm">
                            <Badge variant="outline">Path {index + 1}</Badge>
                            <span className="text-muted-foreground">
                              {path.nodes?.length || 0} nodes, {path.relationships?.length || 0} hops
                            </span>
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground flex items-center gap-1 flex-wrap">
                            {path.nodes?.map((node: any, i: number) => (
                              <span key={i} className="flex items-center gap-1">
                                <Badge variant="secondary" className="text-xs">
                                  {node.properties?.value || node.labels?.[0] || 'Unknown'}
                                </Badge>
                                {i < (path.nodes?.length || 0) - 1 && <span>→</span>}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardContent className="p-0">
                  <GraphVisualization
                    data={graphData}
                    onNodeClick={handleNodeClick}
                    selectedNodeId={selectedNode?.id}
                    highlightPath={highlightPath}
                    loading={graphLoading}
                    height={500}
                  />
                </CardContent>
              </Card>
            </TabsContent>

            {/* Vulnerability Impact Tab */}
            <TabsContent value="impact" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Vulnerability Impact Analysis</CardTitle>
                  <CardDescription>
                    See which assets are affected by a vulnerability and understand the blast radius
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">
                    Select a vulnerability from the Findings page to analyze its impact across your attack surface.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-0">
                  <GraphVisualization
                    data={graphData}
                    onNodeClick={handleNodeClick}
                    selectedNodeId={selectedNode?.id}
                    highlightPath={highlightPath}
                    loading={graphLoading}
                    height={500}
                  />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        )}
      </div>
    </MainLayout>
  );
}
