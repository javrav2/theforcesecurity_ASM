'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import { MainLayout } from '@/components/layout/MainLayout';
import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { MessageSquare, Send, Loader2, AlertCircle, CheckCircle, Wifi, WifiOff } from 'lucide-react';
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

// ---------------------------------------------------------------------------
// WebSocket helpers
// ---------------------------------------------------------------------------

function buildWsUrl(sessionId: string): string {
  const { protocol, host } = window.location;
  const wsProtocol = protocol === 'https:' ? 'wss:' : 'ws:';
  return `${wsProtocol}//${host}/api/v1/agent/ws/${sessionId}`;
}

export default function AgentPage() {
  const searchParams = useSearchParams();
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [statusText, setStatusText] = useState('');
  const [agentAvailable, setAgentAvailable] = useState<boolean | null>(null);
  const [pendingAnswer, setPendingAnswer] = useState(false);
  const [playbooks, setPlaybooks] = useState<{ id: string; name: string; description: string }[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('custom');
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<'assist' | 'agent'>('assist');
  const [urlPrefilled, setUrlPrefilled] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [useWebSocket, setUseWebSocket] = useState(true);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const wsInitializedRef = useRef(false);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { toast } = useToast();

  // Pre-fill from URL
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
  useEffect(() => { scrollToBottom(); }, [messages]);

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

  // ---------------------------------------------------------------------------
  // Message helpers
  // ---------------------------------------------------------------------------

  const appendAgentMessage = useCallback((payload: {
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
  }, []);

  // ---------------------------------------------------------------------------
  // WebSocket connection management
  // ---------------------------------------------------------------------------

  const connectWebSocket = useCallback((sid: string) => {
    // Clean up any existing connection
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    const url = buildWsUrl(sid);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      // Send JWT init
      const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
      if (token) {
        ws.send(JSON.stringify({ type: 'init', token }));
      } else {
        // No token — can't authenticate WS, fall back to REST
        setUseWebSocket(false);
        ws.close();
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        switch (data.type) {
          case 'initialized':
            setWsConnected(true);
            wsInitializedRef.current = true;
            break;

          case 'thinking':
            setStatusText(`Thinking (iteration ${data.iteration ?? '?'}, phase: ${data.phase ?? '?'})...`);
            break;

          case 'tool_start':
            setStatusText(`Running tool: ${data.tool_name ?? 'unknown'}...`);
            break;

          case 'tool_complete':
            setStatusText(`Tool ${data.tool_name ?? ''} ${data.success ? 'completed' : 'failed'}`);
            break;

          case 'approval_request':
            appendAgentMessage({
              answer: `Phase transition requested: ${data.from_phase ?? '?'} → ${data.to_phase ?? '?'}. Reason: ${data.reason ?? 'N/A'}`,
              current_phase: data.from_phase,
              awaiting_approval: true,
              approval_request: data,
            });
            setLoading(false);
            setStatusText('');
            break;

          case 'question_request':
            appendAgentMessage({
              answer: data.question ?? 'The agent has a question for you.',
              awaiting_question: true,
              question_request: data,
            });
            setPendingAnswer(true);
            setLoading(false);
            setStatusText('');
            break;

          case 'response':
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
            setLoading(false);
            setStatusText('');
            break;

          case 'error':
            toast({ variant: 'destructive', title: 'Agent error', description: data.message });
            appendAgentMessage({ answer: `Error: ${data.message}` });
            setLoading(false);
            setStatusText('');
            break;

          case 'pong':
            break;

          default:
            break;
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      wsInitializedRef.current = false;
      wsRef.current = null;

      // Auto-reconnect after 3 seconds if we still have a session
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = setTimeout(() => {
        if (sid) {
          connectWebSocket(sid);
        }
      }, 3000);
    };

    ws.onerror = () => {
      // WebSocket failed — fall back to REST for this session
      setUseWebSocket(false);
      setWsConnected(false);
      wsInitializedRef.current = false;
    };
  }, [appendAgentMessage, toast]);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, []);

  // ---------------------------------------------------------------------------
  // WebSocket send helpers
  // ---------------------------------------------------------------------------

  const wsSend = (msg: Record<string, unknown>): boolean => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN && wsInitializedRef.current) {
      wsRef.current.send(JSON.stringify(msg));
      return true;
    }
    return false;
  };

  // ---------------------------------------------------------------------------
  // Send handler (WebSocket primary, REST fallback)
  // ---------------------------------------------------------------------------

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
    setStatusText('Agent is thinking...');

    // Determine or create session ID
    let sid = sessionId;
    if (!sid) {
      sid = crypto.randomUUID();
      setSessionId(sid);
    }

    // Try WebSocket first
    if (useWebSocket) {
      // Connect if not already connected
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
        connectWebSocket(sid);
        // Wait briefly for connection + init
        await new Promise<void>((resolve) => {
          let attempts = 0;
          const check = () => {
            attempts++;
            if (wsInitializedRef.current || attempts > 20) {
              resolve();
            } else {
              setTimeout(check, 150);
            }
          };
          check();
        });
      }

      if (wsInitializedRef.current) {
        if (pendingAnswer) {
          setPendingAnswer(false);
          if (wsSend({ type: 'answer', answer: q || displayContent })) return;
        } else {
          if (wsSend({ type: 'query', question: usePreset ? displayContent : q })) return;
        }
      }
    }

    // Fallback: use REST API
    setStatusText('Agent is thinking (via REST)...');
    try {
      if (pendingAnswer && sid) {
        setPendingAnswer(false);
        const data = await api.answerAgentQuestion(sid, q || displayContent);
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
          sid ?? undefined,
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
      setStatusText('');
    }
  };

  // ---------------------------------------------------------------------------
  // Approval handler (WebSocket primary, REST fallback)
  // ---------------------------------------------------------------------------

  const handleApprove = async (decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!sessionId || loading) return;
    setLoading(true);
    setStatusText('Processing approval...');

    // Try WebSocket
    if (useWebSocket && wsInitializedRef.current) {
      if (wsSend({ type: 'approval', decision, modification: modification ?? undefined })) return;
    }

    // REST fallback
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
      setStatusText('');
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
                  {statusText || 'Agent is thinking and may run tools\u2026'}
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
                    ? 'Type your answer to the agent\u2026'
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
            <div className="flex items-center gap-2">
              {sessionId && (
                <p className="text-xs text-muted-foreground">Session: {sessionId.slice(0, 8)}\u2026</p>
              )}
              {sessionId && (
                <span className="text-xs text-muted-foreground flex items-center gap-1">
                  {wsConnected ? (
                    <><Wifi className="h-3 w-3 text-green-500" /> Live</>
                  ) : (
                    <><WifiOff className="h-3 w-3 text-muted-foreground" /> REST</>
                  )}
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}
