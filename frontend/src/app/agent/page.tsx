'use client';

import { useState, useRef, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { MessageSquare, Send, Loader2, AlertCircle, CheckCircle } from 'lucide-react';
import { api, getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';

type MessageRole = 'user' | 'agent';

interface Message {
  id: string;
  role: MessageRole;
  content: string;
  phase?: string;
  taskComplete?: boolean;
  traceSummary?: string;
  awaitingApproval?: boolean;
  approvalRequest?: Record<string, unknown>;
  awaitingQuestion?: boolean;
  questionRequest?: Record<string, unknown>;
}

export default function AgentPage() {
  const searchParams = useSearchParams();
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [agentAvailable, setAgentAvailable] = useState<boolean | null>(null);
  const [pendingAnswer, setPendingAnswer] = useState(false); // true when agent asked a question and we should send next input as answer
  const [playbooks, setPlaybooks] = useState<{ id: string; name: string; description: string }[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('custom');
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<'assist' | 'agent'>('assist');
  const [urlPrefilled, setUrlPrefilled] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  // Pre-fill from URL (e.g. /agent?target=example.com&playbook=vuln_scan&question=...)
  useEffect(() => {
    const t = searchParams.get('target');
    const p = searchParams.get('playbook');
    const q = searchParams.get('question');
    if (t != null && t !== '') setTarget(decodeURIComponent(t));
    if (p != null && p !== '') setSelectedPlaybookId(decodeURIComponent(p));
    if (q != null && q !== '') {
      setQuestion(decodeURIComponent(q));
      setUrlPrefilled(true);
    }
  }, [searchParams]);

  const scrollToBottom = () => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    api.getAgentStatus().then((data: { available: boolean }) => {
      setAgentAvailable(data?.available ?? false);
    }).catch(() => setAgentAvailable(false));
  }, []);

  useEffect(() => {
    if (agentAvailable) {
      api.getAgentPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
    }
  }, [agentAvailable]);

  const appendAgentMessage = (payload: {
    answer: string;
    current_phase?: string;
    task_complete?: boolean;
    execution_trace_summary?: string;
    awaiting_approval?: boolean;
    approval_request?: Record<string, unknown>;
    awaiting_question?: boolean;
    question_request?: Record<string, unknown>;
  }) => {
    setMessages((prev) => [
      ...prev,
      {
        id: `agent-${Date.now()}`,
        role: 'agent',
        content: payload.answer || '(No response)',
        phase: payload.current_phase,
        taskComplete: payload.task_complete,
        traceSummary: payload.execution_trace_summary,
        awaitingApproval: payload.awaiting_approval,
        approvalRequest: payload.approval_request,
        awaitingQuestion: payload.awaiting_question,
        questionRequest: payload.question_request,
      },
    ]);
  };

  const handleSend = async () => {
    const q = question.trim();
    const usePreset = selectedPlaybookId !== 'custom';
    if (!usePreset && !q) return;
    if (loading) return;

    const displayContent = usePreset
      ? `${playbooks.find((p) => p.id === selectedPlaybookId)?.name ?? selectedPlaybookId}${target.trim() ? ` — ${target.trim()}` : ''}`
      : q;

    setMessages((prev) => [
      ...prev,
      { id: `user-${Date.now()}`, role: 'user', content: displayContent },
    ]);
    if (!usePreset) setQuestion('');
    setUrlPrefilled(false);
    setLoading(true);

    try {
      if (pendingAnswer && sessionId) {
        setPendingAnswer(false);
        const data = await api.answerAgentQuestion(sessionId, q || displayContent);
        appendAgentMessage({
          answer: data.answer,
          current_phase: data.current_phase,
          task_complete: data.task_complete,
          execution_trace_summary: data.execution_trace_summary,
          awaiting_approval: data.awaiting_approval,
          approval_request: data.approval_request,
          awaiting_question: data.awaiting_question,
          question_request: data.question_request,
        });
        if (data.awaiting_question) setPendingAnswer(true);
      } else {
        const data = await api.queryAgent(
          usePreset ? displayContent : q,
          sessionId ?? undefined,
          {
            ...(usePreset ? { playbookId: selectedPlaybookId, target: target.trim() || undefined } : {}),
            mode,
          }
        );
        if (data.session_id) setSessionId(data.session_id);
        appendAgentMessage({
          answer: data.answer,
          current_phase: data.current_phase,
          task_complete: data.task_complete,
          execution_trace_summary: data.execution_trace_summary,
          awaiting_approval: data.awaiting_approval,
          approval_request: data.approval_request,
          awaiting_question: data.awaiting_question,
          question_request: data.question_request,
        });
        if (data.awaiting_question) setPendingAnswer(true);
        if (data.error) toast({ variant: 'destructive', title: 'Agent error', description: data.error });
      }
    } catch (err: unknown) {
      const msg = getApiErrorMessage(err as Error, 'Failed to send');
      toast({ variant: 'destructive', title: 'Error', description: msg });
      appendAgentMessage({ answer: `Error: ${msg}` });
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!sessionId || loading) return;
    setLoading(true);
    try {
      const data = await api.approveAgent(sessionId, decision, modification);
      appendAgentMessage({
        answer: data.answer,
        current_phase: data.current_phase,
        task_complete: data.task_complete,
        execution_trace_summary: data.execution_trace_summary,
        awaiting_approval: data.awaiting_approval,
        approval_request: data.approval_request,
        awaiting_question: data.awaiting_question,
        question_request: data.question_request,
      });
      if (data.awaiting_question) setPendingAnswer(true);
    } catch (err: unknown) {
      toast({ variant: 'destructive', title: 'Error', description: getApiErrorMessage(err as Error) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      <Header title="Agent" subtitle="Ask questions and run tests. The agent uses security tools (Nuclei, Naabu, HTTPX, etc.) to perform scans and discovery." />
      <div className="space-y-4">
        {agentAvailable === false && (
          <Card className="border-amber-500/50 bg-amber-500/5">
            <CardContent className="pt-4 flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-amber-500 shrink-0" />
              <p className="text-sm">
                Agent is not available. Configure <code className="bg-muted px-1 rounded">OPENAI_API_KEY</code> or <code className="bg-muted px-1 rounded">ANTHROPIC_API_KEY</code> in the backend. You must belong to an organization to use the agent.
              </p>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MessageSquare className="h-5 w-5" />
              Ask a question for testing
            </CardTitle>
            <CardDescription>
              Example: &quot;Run a quick port scan on example.com&quot;, &quot;What are the critical vulnerabilities for my organization?&quot;, &quot;Discover subdomains for my org domain.&quot; The agent will use MCP tools (Nuclei, Naabu, HTTPX, Subfinder, etc.) as needed.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-lg border bg-muted/30 max-h-[50vh] overflow-y-auto p-4 space-y-3">
              {messages.length === 0 && (
                <p className="text-muted-foreground text-sm">Send a message to start. The agent can run scans and discovery for your organization.</p>
              )}
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`flex flex-col gap-1 ${m.role === 'user' ? 'items-end' : 'items-start'}`}
                >
                  <div
                    className={`rounded-lg px-3 py-2 max-w-[85%] ${
                      m.role === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted border'
                    }`}
                  >
                    <p className="text-sm whitespace-pre-wrap">{m.content}</p>
                    {m.role === 'agent' && m.phase && (
                      <Badge variant="outline" className="mt-2 text-xs">{m.phase}</Badge>
                    )}
                    {m.role === 'agent' && m.taskComplete && (
                      <span className="ml-2 text-xs text-muted-foreground flex items-center gap-1">
                        <CheckCircle className="h-3 w-3" /> Task complete
                      </span>
                    )}
                    {m.role === 'agent' && m.traceSummary && (
                      <details className="mt-2">
                        <summary className="text-xs cursor-pointer text-muted-foreground">Execution trace</summary>
                        <pre className="text-xs mt-1 p-2 rounded bg-background overflow-x-auto whitespace-pre-wrap">{m.traceSummary}</pre>
                      </details>
                    )}
                  </div>
                  {m.role === 'agent' && m.awaitingApproval && m.approvalRequest && (
                    <div className="flex flex-wrap gap-2 mt-1">
                      <Button size="sm" onClick={() => handleApprove('approve')} disabled={loading}>
                        Approve
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => handleApprove('abort')} disabled={loading}>
                        Abort
                      </Button>
                    </div>
                  )}
                  {m.role === 'agent' && m.awaitingQuestion && m.questionRequest && (
                    <p className="text-xs text-muted-foreground mt-1">Type your answer below and press Send.</p>
                  )}
                </div>
              ))}
              {loading && (
                <div className="flex items-center gap-2 text-muted-foreground text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Agent is thinking and may run tools…
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="mode-select">Mode</Label>
                <Select value={mode} onValueChange={(v) => setMode(v as 'assist' | 'agent')}>
                  <SelectTrigger id="mode-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="assist">Assist (approval required between phases)</SelectItem>
                    <SelectItem value="agent">Agent (autonomous; no approval)</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Agent mode runs without asking for approval between phases. Use when you have defined the task (e.g. via a preset).
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="playbook-select">Preset</Label>
                <Select value={selectedPlaybookId} onValueChange={setSelectedPlaybookId}>
                  <SelectTrigger id="playbook-select">
                    <SelectValue placeholder="Custom" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="custom">Custom (free-form question)</SelectItem>
                    {playbooks.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {selectedPlaybookId !== 'custom' && (
                <div className="space-y-1.5">
                  <Label htmlFor="target-input">Target (optional)</Label>
                  <Input
                    id="target-input"
                    placeholder="e.g. example.com or https://app.example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={loading || agentAvailable === false}
                  />
                </div>
              )}
            </div>
            {urlPrefilled && (
              <p className="text-sm text-muted-foreground">
                Pre-filled from link. Click Send to start the assessment.
              </p>
            )}
            <div className="flex gap-2">
              <Textarea
                placeholder={
                  pendingAnswer
                    ? 'Type your answer to the agent…'
                    : selectedPlaybookId === 'custom'
                      ? 'Ask a question (e.g. run a port scan on example.com)'
                      : 'Add a note or leave blank to run the preset'
                }
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
                rows={2}
                className="resize-none"
                disabled={loading || agentAvailable === false}
              />
              <Button
                onClick={handleSend}
                disabled={
                  loading ||
                  agentAvailable === false ||
                  (selectedPlaybookId === 'custom' ? !question.trim() : false)
                }
                size="icon"
                className="shrink-0 h-auto py-3"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              </Button>
            </div>
            {sessionId && (
              <p className="text-xs text-muted-foreground">Session: {sessionId.slice(0, 8)}…</p>
            )}
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
