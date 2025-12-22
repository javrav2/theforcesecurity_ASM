'use client';

import { useState, useEffect, useRef } from 'react';
import { Label } from '@/types/asm';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { 
  Plus, 
  X, 
  Tag, 
  Check, 
  Loader2, 
  MoreHorizontal,
  Pencil,
  Trash2,
  Search,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

interface LabelManagerProps {
  assetId?: number;
  assetIds?: number[];  // For bulk operations
  organizationId: number;
  selectedLabels?: Label[];
  onLabelsChange?: (labels: Label[]) => void;
  mode?: 'inline' | 'dropdown' | 'full';
}

const PRESET_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16', '#22c55e',
  '#10b981', '#14b8a6', '#06b6d4', '#0ea5e9', '#3b82f6', '#6366f1',
  '#8b5cf6', '#a855f7', '#d946ef', '#ec4899', '#f43f5e', '#64748b',
];

export function LabelManager({
  assetId,
  assetIds,
  organizationId,
  selectedLabels = [],
  onLabelsChange,
  mode = 'inline',
}: LabelManagerProps) {
  const { toast } = useToast();
  const [labels, setLabels] = useState<Label[]>([]);
  const [currentLabels, setCurrentLabels] = useState<Label[]>(selectedLabels);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState('');
  const [newLabelName, setNewLabelName] = useState('');
  const [newLabelColor, setNewLabelColor] = useState(PRESET_COLORS[11]); // Default indigo
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingLabel, setEditingLabel] = useState<Label | null>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchLabels();
  }, [organizationId]);

  useEffect(() => {
    setCurrentLabels(selectedLabels);
  }, [selectedLabels]);

  const fetchLabels = async () => {
    try {
      setLoading(true);
      const data = await api.getLabels({ organization_id: organizationId });
      setLabels(data);
    } catch (error) {
      console.error('Failed to fetch labels:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateLabel = async () => {
    if (!newLabelName.trim()) return;
    
    try {
      setCreating(true);
      const label = await api.createLabel({
        name: newLabelName.trim(),
        color: newLabelColor,
        organization_id: organizationId,
      });
      setLabels([...labels, label]);
      setNewLabelName('');
      setShowCreateDialog(false);
      toast({ title: `Label "${label.name}" created` });
      
      // Auto-assign to current asset if in inline mode
      if (assetId && mode === 'inline') {
        await handleToggleLabel(label);
      }
    } catch (error: any) {
      toast({
        title: 'Failed to create label',
        description: error.response?.data?.detail || 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setCreating(false);
    }
  };

  const handleQuickCreateLabel = async (name: string) => {
    try {
      setCreating(true);
      const label = await api.quickCreateLabel(name, organizationId);
      
      // Check if it already exists in our list
      const exists = labels.find(l => l.id === label.id);
      if (!exists) {
        setLabels([...labels, label]);
      }
      
      setSearch('');
      
      // Auto-assign to current asset
      if (assetId) {
        await handleToggleLabel(label);
      }
    } catch (error) {
      toast({ title: 'Failed to create label', variant: 'destructive' });
    } finally {
      setCreating(false);
    }
  };

  const handleToggleLabel = async (label: Label) => {
    const isAssigned = currentLabels.some(l => l.id === label.id);
    
    try {
      if (assetId) {
        if (isAssigned) {
          await api.removeAssetsFromLabel(label.id, [assetId]);
          const newLabels = currentLabels.filter(l => l.id !== label.id);
          setCurrentLabels(newLabels);
          onLabelsChange?.(newLabels);
        } else {
          await api.assignAssetsToLabel(label.id, [assetId]);
          const newLabels = [...currentLabels, label];
          setCurrentLabels(newLabels);
          onLabelsChange?.(newLabels);
        }
      } else if (assetIds && assetIds.length > 0) {
        // Bulk operation
        if (isAssigned) {
          await api.bulkAssignLabels({
            asset_ids: assetIds,
            add_labels: [],
            remove_labels: [label.id],
          });
          const newLabels = currentLabels.filter(l => l.id !== label.id);
          setCurrentLabels(newLabels);
          onLabelsChange?.(newLabels);
        } else {
          await api.bulkAssignLabels({
            asset_ids: assetIds,
            add_labels: [label.id],
            remove_labels: [],
          });
          const newLabels = [...currentLabels, label];
          setCurrentLabels(newLabels);
          onLabelsChange?.(newLabels);
        }
      }
    } catch (error) {
      toast({ title: 'Failed to update label', variant: 'destructive' });
    }
  };

  const handleDeleteLabel = async (label: Label) => {
    try {
      await api.deleteLabel(label.id);
      setLabels(labels.filter(l => l.id !== label.id));
      setCurrentLabels(currentLabels.filter(l => l.id !== label.id));
      toast({ title: `Label "${label.name}" deleted` });
    } catch (error) {
      toast({ title: 'Failed to delete label', variant: 'destructive' });
    }
  };

  const handleUpdateLabel = async () => {
    if (!editingLabel || !newLabelName.trim()) return;
    
    try {
      const updated = await api.updateLabel(editingLabel.id, {
        name: newLabelName.trim(),
        color: newLabelColor,
      });
      setLabels(labels.map(l => l.id === updated.id ? updated : l));
      setCurrentLabels(currentLabels.map(l => l.id === updated.id ? updated : l));
      setEditingLabel(null);
      setNewLabelName('');
      toast({ title: 'Label updated' });
    } catch (error) {
      toast({ title: 'Failed to update label', variant: 'destructive' });
    }
  };

  const filteredLabels = labels.filter(l =>
    l.name.toLowerCase().includes(search.toLowerCase())
  );

  const showQuickCreate = search.trim() && !filteredLabels.some(
    l => l.name.toLowerCase() === search.toLowerCase()
  );

  // Inline mode - shows current labels with add button
  if (mode === 'inline') {
    return (
      <div className="flex flex-wrap items-center gap-1">
        {currentLabels.map(label => (
          <Badge
            key={label.id}
            style={{ backgroundColor: label.color }}
            className="text-white text-xs cursor-pointer hover:opacity-80"
            onClick={() => handleToggleLabel(label)}
          >
            {label.name}
            <X className="h-3 w-3 ml-1" />
          </Badge>
        ))}
        
        <DropdownMenu open={dropdownOpen} onOpenChange={setDropdownOpen}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-6 px-2">
              <Plus className="h-3 w-3" />
              <Tag className="h-3 w-3 ml-1" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <div className="p-2">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  ref={inputRef}
                  placeholder="Search or create label..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8 h-8"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && showQuickCreate) {
                      e.preventDefault();
                      handleQuickCreateLabel(search.trim());
                    }
                  }}
                />
              </div>
            </div>
            
            <div className="max-h-48 overflow-y-auto">
              {loading ? (
                <div className="p-4 text-center">
                  <Loader2 className="h-4 w-4 animate-spin mx-auto" />
                </div>
              ) : (
                <>
                  {filteredLabels.map(label => {
                    const isAssigned = currentLabels.some(l => l.id === label.id);
                    return (
                      <DropdownMenuItem
                        key={label.id}
                        onClick={() => handleToggleLabel(label)}
                        className="cursor-pointer"
                      >
                        <div className="flex items-center justify-between w-full">
                          <div className="flex items-center gap-2">
                            <div
                              className="w-3 h-3 rounded-full"
                              style={{ backgroundColor: label.color }}
                            />
                            <span>{label.name}</span>
                          </div>
                          {isAssigned && <Check className="h-4 w-4 text-primary" />}
                        </div>
                      </DropdownMenuItem>
                    );
                  })}
                  
                  {showQuickCreate && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleQuickCreateLabel(search.trim())}
                        className="cursor-pointer"
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Create "{search.trim()}"
                      </DropdownMenuItem>
                    </>
                  )}
                  
                  {filteredLabels.length === 0 && !showQuickCreate && (
                    <div className="p-4 text-center text-sm text-muted-foreground">
                      No labels found
                    </div>
                  )}
                </>
              )}
            </div>
            
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => setShowCreateDialog(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create new label...
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Create/Edit Label Dialog */}
        <Dialog 
          open={showCreateDialog || !!editingLabel} 
          onOpenChange={(open) => {
            if (!open) {
              setShowCreateDialog(false);
              setEditingLabel(null);
              setNewLabelName('');
            }
          }}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{editingLabel ? 'Edit Label' : 'Create New Label'}</DialogTitle>
              <DialogDescription>
                {editingLabel ? 'Update the label name and color.' : 'Create a new label to organize your assets.'}
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4 py-4">
              <div>
                <label className="text-sm font-medium">Label Name</label>
                <Input
                  value={newLabelName}
                  onChange={(e) => setNewLabelName(e.target.value)}
                  placeholder="e.g., Production, Critical, External"
                  className="mt-1"
                />
              </div>
              
              <div>
                <label className="text-sm font-medium">Color</label>
                <div className="flex flex-wrap gap-2 mt-2">
                  {PRESET_COLORS.map(color => (
                    <button
                      key={color}
                      className={`w-6 h-6 rounded-full transition-all ${
                        newLabelColor === color ? 'ring-2 ring-offset-2 ring-primary' : ''
                      }`}
                      style={{ backgroundColor: color }}
                      onClick={() => setNewLabelColor(color)}
                    />
                  ))}
                </div>
              </div>
              
              <div>
                <label className="text-sm font-medium">Preview</label>
                <div className="mt-2">
                  <Badge style={{ backgroundColor: newLabelColor }} className="text-white">
                    {newLabelName || 'Label Name'}
                  </Badge>
                </div>
              </div>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => {
                setShowCreateDialog(false);
                setEditingLabel(null);
                setNewLabelName('');
              }}>
                Cancel
              </Button>
              <Button 
                onClick={editingLabel ? handleUpdateLabel : handleCreateLabel}
                disabled={!newLabelName.trim() || creating}
              >
                {creating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {editingLabel ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  // Full mode - shows all labels with management options
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search labels..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Button onClick={() => setShowCreateDialog(true)}>
          <Plus className="h-4 w-4 mr-2" />
          New Label
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filteredLabels.map(label => (
          <div
            key={label.id}
            className="flex items-center justify-between p-3 rounded-lg border bg-card"
          >
            <div className="flex items-center gap-3">
              <div
                className="w-4 h-4 rounded-full"
                style={{ backgroundColor: label.color }}
              />
              <div>
                <div className="font-medium">{label.name}</div>
                <div className="text-xs text-muted-foreground">
                  {label.asset_count || 0} assets
                </div>
              </div>
            </div>
            
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => {
                  setEditingLabel(label);
                  setNewLabelName(label.name);
                  setNewLabelColor(label.color);
                }}>
                  <Pencil className="h-4 w-4 mr-2" />
                  Edit
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => handleDeleteLabel(label)}
                  className="text-destructive"
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        ))}
      </div>

      {/* Create/Edit Dialog (same as above) */}
      <Dialog 
        open={showCreateDialog || !!editingLabel} 
        onOpenChange={(open) => {
          if (!open) {
            setShowCreateDialog(false);
            setEditingLabel(null);
            setNewLabelName('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingLabel ? 'Edit Label' : 'Create New Label'}</DialogTitle>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div>
              <label className="text-sm font-medium">Label Name</label>
              <Input
                value={newLabelName}
                onChange={(e) => setNewLabelName(e.target.value)}
                placeholder="e.g., Production, Critical, External"
                className="mt-1"
              />
            </div>
            
            <div>
              <label className="text-sm font-medium">Color</label>
              <div className="flex flex-wrap gap-2 mt-2">
                {PRESET_COLORS.map(color => (
                  <button
                    key={color}
                    className={`w-6 h-6 rounded-full ${
                      newLabelColor === color ? 'ring-2 ring-offset-2 ring-primary' : ''
                    }`}
                    style={{ backgroundColor: color }}
                    onClick={() => setNewLabelColor(color)}
                  />
                ))}
              </div>
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => {
              setShowCreateDialog(false);
              setEditingLabel(null);
            }}>
              Cancel
            </Button>
            <Button 
              onClick={editingLabel ? handleUpdateLabel : handleCreateLabel}
              disabled={!newLabelName.trim()}
            >
              {editingLabel ? 'Update' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Helper component to show label badges
export function LabelBadges({ labels }: { labels: Label[] }) {
  if (!labels || labels.length === 0) return null;
  
  return (
    <div className="flex flex-wrap gap-1">
      {labels.map(label => (
        <Badge
          key={label.id}
          style={{ backgroundColor: label.color }}
          className="text-white text-xs"
        >
          {label.name}
        </Badge>
      ))}
    </div>
  );
}


