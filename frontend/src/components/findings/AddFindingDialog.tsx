'use client';

import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Loader2, Plus, ShieldAlert } from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { SeverityLevel } from '@/types/asm';

interface AddFindingDialogProps {
  assetId: number;
  assetValue: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onFindingAdded?: () => void;
}

interface FindingFormData {
  title: string;
  severity: SeverityLevel;
  description: string;
  impact: string;
  affected_component: string;
  steps_to_reproduce: string;
  evidence: string;
  proof_of_concept: string;
  remediation: string;
  cvss_score: string;
  cve_id: string;
  cwe_id: string;
  references: string;
}

const initialFormData: FindingFormData = {
  title: '',
  severity: 'medium',
  description: '',
  impact: '',
  affected_component: '',
  steps_to_reproduce: '',
  evidence: '',
  proof_of_concept: '',
  remediation: '',
  cvss_score: '',
  cve_id: '',
  cwe_id: '',
  references: '',
};

const severityOptions: { value: SeverityLevel; label: string; color: string }[] = [
  { value: 'critical', label: 'Critical', color: 'bg-red-500' },
  { value: 'high', label: 'High', color: 'bg-orange-500' },
  { value: 'medium', label: 'Medium', color: 'bg-yellow-500' },
  { value: 'low', label: 'Low', color: 'bg-blue-500' },
  { value: 'info', label: 'Informational', color: 'bg-gray-500' },
];

export function AddFindingDialog({
  assetId,
  assetValue,
  open,
  onOpenChange,
  onFindingAdded,
}: AddFindingDialogProps) {
  const { toast } = useToast();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formData, setFormData] = useState<FindingFormData>(initialFormData);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSeverityChange = (value: string) => {
    setFormData((prev) => ({ ...prev, severity: value as SeverityLevel }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.title.trim()) {
      toast({
        title: 'Validation Error',
        description: 'Title is required',
        variant: 'destructive',
      });
      return;
    }

    setIsSubmitting(true);

    try {
      const references = formData.references
        .split('\n')
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      const payload = {
        title: formData.title.trim(),
        severity: formData.severity,
        description: formData.description || undefined,
        impact: formData.impact || undefined,
        affected_component: formData.affected_component || undefined,
        steps_to_reproduce: formData.steps_to_reproduce || undefined,
        evidence: formData.evidence || undefined,
        proof_of_concept: formData.proof_of_concept || undefined,
        remediation: formData.remediation || undefined,
        cvss_score: formData.cvss_score ? parseFloat(formData.cvss_score) : undefined,
        cve_id: formData.cve_id || undefined,
        cwe_id: formData.cwe_id || undefined,
        references: references.length > 0 ? references : [],
        asset_id: assetId,
        detected_by: 'manual',
        is_manual: true,
        tags: ['manual-finding'],
        metadata: {},
      };

      await api.createVulnerability(payload);

      toast({
        title: 'Finding Added',
        description: 'Manual finding has been successfully created.',
      });

      setFormData(initialFormData);
      onOpenChange(false);
      onFindingAdded?.();
    } catch (error) {
      toast({
        title: 'Error',
        description: getApiErrorMessage(error, 'Failed to create finding'),
        variant: 'destructive',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    if (!isSubmitting) {
      setFormData(initialFormData);
      onOpenChange(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" />
            Add Manual Finding
          </DialogTitle>
          <DialogDescription>
            Create a manual pentest finding for <strong>{assetValue}</strong>
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <Label htmlFor="title">Title *</Label>
              <Input
                id="title"
                name="title"
                value={formData.title}
                onChange={handleInputChange}
                placeholder="e.g., SQL Injection in Login Form"
                required
              />
            </div>

            <div>
              <Label htmlFor="severity">Severity *</Label>
              <Select
                value={formData.severity}
                onValueChange={handleSeverityChange}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select severity" />
                </SelectTrigger>
                <SelectContent>
                  {severityOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-3 h-3 rounded-full ${option.color}`}
                        />
                        {option.label}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="cvss_score">CVSS Score (0.0 - 10.0)</Label>
              <Input
                id="cvss_score"
                name="cvss_score"
                type="number"
                step="0.1"
                min="0"
                max="10"
                value={formData.cvss_score}
                onChange={handleInputChange}
                placeholder="e.g., 8.5"
              />
            </div>

            <div>
              <Label htmlFor="cve_id">CVE ID</Label>
              <Input
                id="cve_id"
                name="cve_id"
                value={formData.cve_id}
                onChange={handleInputChange}
                placeholder="e.g., CVE-2024-1234"
              />
            </div>

            <div>
              <Label htmlFor="cwe_id">CWE ID</Label>
              <Input
                id="cwe_id"
                name="cwe_id"
                value={formData.cwe_id}
                onChange={handleInputChange}
                placeholder="e.g., CWE-89"
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="affected_component">Affected Component</Label>
              <Input
                id="affected_component"
                name="affected_component"
                value={formData.affected_component}
                onChange={handleInputChange}
                placeholder="e.g., /api/v1/users/login endpoint"
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Detailed description of the vulnerability..."
                rows={3}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="impact">Impact</Label>
              <Textarea
                id="impact"
                name="impact"
                value={formData.impact}
                onChange={handleInputChange}
                placeholder="What is the business impact of this vulnerability?"
                rows={2}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="steps_to_reproduce">Steps to Reproduce</Label>
              <Textarea
                id="steps_to_reproduce"
                name="steps_to_reproduce"
                value={formData.steps_to_reproduce}
                onChange={handleInputChange}
                placeholder="1. Navigate to...&#10;2. Enter...&#10;3. Click..."
                rows={4}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="evidence">Evidence</Label>
              <Textarea
                id="evidence"
                name="evidence"
                value={formData.evidence}
                onChange={handleInputChange}
                placeholder="HTTP request/response, error messages, etc."
                rows={3}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="proof_of_concept">Proof of Concept</Label>
              <Textarea
                id="proof_of_concept"
                name="proof_of_concept"
                value={formData.proof_of_concept}
                onChange={handleInputChange}
                placeholder="Code, payload, or commands to demonstrate the vulnerability..."
                rows={3}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="remediation">Remediation</Label>
              <Textarea
                id="remediation"
                name="remediation"
                value={formData.remediation}
                onChange={handleInputChange}
                placeholder="Recommended steps to fix this vulnerability..."
                rows={3}
              />
            </div>

            <div className="col-span-2">
              <Label htmlFor="references">References (one per line)</Label>
              <Textarea
                id="references"
                name="references"
                value={formData.references}
                onChange={handleInputChange}
                placeholder="https://owasp.org/...&#10;https://cve.mitre.org/..."
                rows={2}
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={handleClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : (
                <>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Finding
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
