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
import {
  MessageSquare, Send, Loader2, AlertCircle, CheckCircle,
  Wifi, WifiOff, Clock, Trash2, Plus, ChevronRight, History
} from 'lucide-react';
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

interface ConversationSummary {
  session_id: string;
  title: string | null;
  mode: string;
  current_phase: string;
  is_active: boolean;
  message_count: number;
  created_at: string;
  updated_at: string;
}

interface StatusUpdate {
  type: string;
  iteration?: number;
  phase?: string;
  thought?: string;
  tool_name?: string;
  tool_args?: Record<string, unknown>;
  success?: boolean;
  output_summary?: string;
  action?: string;
}

type ConnectionMode = 'connecting' | 'websocket' | 'rest' | 'disconnected';

export default function AgentPage() {
  const searchParams = useSearchParams();
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<Message[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [agentAvailable, setAgentAvailable] = useState<boolean | null>(null);
  const [agentStatusHint, setAgentStatusHint] = useState<string | null>(null);
  const [pendingAnswer, setPendingAnswer] = useState(false);
  const [playbooks, setPlaybooks] = useState<{ id: string; name: string; description: string }[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('custom');
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<'assist' | 'agent'>('assist');
  const [urlPrefilled, setUrlPrefilled] = useState(false);

  // WebSocket streaming state
  const [connectionMode, setConnectionMode] = useState<ConnectionMode>('connecting');
  const [liveStatus, setLiveStatus] = useState<StatusUpdate | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const wsAuthenticatedRef = useRef(false);
  const wsFailCountRef = useRef(0);

  // Conversation history
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
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
  useEffect(() => { scrollToBottom(); }, [messages, liveStatus]);

  // Check agent status + load playbooks + conversations
  useEffect(() => {
    api.getAgentStatus()
      .then((data: { available?: boolean; hint?: string }) => {
        setAgentAvailable(data?.available ?? false);
        setAgentStatusHint(data?.hint ?? null);
      })
      .catch((err: unknown) => {
        setAgentAvailable(false);
        setAgentStatusHint(getApiErrorMessage(err as Error, 'Could not reach agent status.'));
      });
  }, []);

  useEffect(() => {
    if (agentAvailable) {
      api.getAgentPlaybooks().then(setPlaybooks).catch(() => setPlaybooks([]));
      loadConversations();
      if (!sessionId) {
        setSessionId(crypto.randomUUID());
      }
    }
  }, [agentAvailable]);

  const loadConversations = useCallback(() => {
    api.getAgentConversations(50)
      .then((data: ConversationSummary[]) => setConversations(data || []))
      .catch(() => setConversations([]));
  }, []);

  // =========================================================================
  // WebSocket management
  // =========================================================================

  const connectWebSocket = useCallback((sid: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    const token = api.getToken();
    if (!token) {
      setConnectionMode('rest');
      return;
    }

    if (wsFailCountRef.current >= 1) {
      setConnectionMode('rest');
      return;
    }

    setConnectionMode('connecting');
    const url = api.getAgentWebSocketUrl(sid);
    const ws = new WebSocket(url);
    wsRef.current = ws;
    wsAuthenticatedRef.current = false;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'init', token }));
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWsMessage(data, sid);
      } catch {
        // ignore parse errors
      }
    };

    ws.onerror = () => {
      wsFailCountRef.current += 1;
      wsRef.current = null;
      wsAuthenticatedRef.current = false;
      setConnectionMode('rest');
    };

    ws.onclose = () => {
      wsRef.current = null;
      wsAuthenticatedRef.current = false;
      setConnectionMode('rest');
    };
  }, []);

  const handleWsMessage = useCallback((data: Record<string, unknown>, sid: string) => {
    const msgType = data.type as string;

    if (msgType === 'connected') {
      // waiting for auth
    } else if (msgType === 'authenticated') {
      wsAuthenticatedRef.current = true;
      setConnectionMode('websocket');
    } else if (msgType === 'thinking' || msgType === 'tool_start' || msgType === 'tool_complete') {
      setLiveStatus(data as unknown as StatusUpdate);
    } else if (msgType === 'response') {
      setLiveStatus(null);
      setLoading(false);
      appendAgentMessage({
        answer: data.answer as string,
        current_phase: data.current_phase as string,
        task_complete: data.task_complete as boolean,
        execution_trace_summary: data.execution_trace_summary as string,
        awaiting_approval: data.awaiting_approval as boolean,
        approval_request: data.approval_request as Record<string, unknown>,
        awaiting_question: data.awaiting_question as boolean,
        question_request: data.question_request as Record<string, unknown>,
      });
      if (data.awaiting_question) setPendingAnswer(true);
      loadConversations();
    } else if (msgType === 'error') {
      setLiveStatus(null);
      setLoading(false);
      const errMsg = (data.message as string) || 'Unknown error';
      toast({ variant: 'destructive', title: 'Agent error', description: errMsg });
      appendAgentMessage({ answer: `Error: ${errMsg}` });
    } else if (msgType === 'pong') {
      // keepalive
    }
  }, []);

  // Disconnect WebSocket on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, []);

  // Auto-connect WebSocket once when session and agent are ready
  useEffect(() => {
    if (sessionId && agentAvailable) {
      connectWebSocket(sessionId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, agentAvailable]);

  // Keepalive ping
  useEffect(() => {
    const interval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'ping' }));
      }
    }, 25000);
    return () => clearInterval(interval);
  }, []);

  // Safety timeout: reset loading state if no response after 3 minutes
  const loadingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (loading) {
      loadingTimeoutRef.current = setTimeout(() => {
        setLoading(false);
        setLiveStatus(null);
        toast({ variant: 'destructive', title: 'Timeout', description: 'No response from the agent after 3 minutes. The backend may still be processing — check back shortly or try again.' });
        appendAgentMessage({ answer: 'Error: No response received within 3 minutes. The agent may have timed out on the server. Please try again.' });
      }, 180_000);
    } else if (loadingTimeoutRef.current) {
      clearTimeout(loadingTimeoutRef.current);
      loadingTimeoutRef.current = null;
    }
    return () => {
      if (loadingTimeoutRef.current) clearTimeout(loadingTimeoutRef.current);
    };
  }, [loading]);

  // =========================================================================
  // Message helpers
  // =========================================================================

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

  // =========================================================================
  // Send via WebSocket or REST fallback
  // =========================================================================

  const sendViaWs = (msgObj: Record<string, unknown>): boolean => {
    if (wsRef.current?.readyState === WebSocket.OPEN && wsAuthenticatedRef.current) {
      wsRef.current.send(JSON.stringify(msgObj));
      return true;
    }
    return false;
  };

  const handleSend = async () => {
    const q = question.trim();
    const usePreset = selectedPlaybookId !== 'custom';
    if (!usePreset && !q) return;
    if (loading) return;

    const displayContent = usePreset
      ? `${playbooks.find((p) => p.id === selectedPlaybookId)?.name ?? selectedPlaybookId}${target.trim() ? ` — ${target.trim()}` : ''}`
      : q;

    setMessages((prev) => [...prev, { id: `user-${Date.now()}`, role: 'user', content: displayContent }]);
    if (!usePreset) setQuestion('');
    setUrlPrefilled(false);
    setLoading(true);
    setLiveStatus(null);

    const sid = sessionId || crypto.randomUUID();
    if (!sessionId) setSessionId(sid);

    try {
      if (pendingAnswer && sid) {
        setPendingAnswer(false);
        const sent = sendViaWs({ type: 'answer', answer: q || displayContent });
        if (!sent) {
          const data = await api.answerAgentQuestion(sid, q || displayContent);
          setLoading(false);
          appendAgentMessage(data);
          if (data.awaiting_question) setPendingAnswer(true);
          loadConversations();
        }
      } else {
        const wsMsg: Record<string, unknown> = {
          type: 'query',
          question: usePreset ? displayContent : q,
          mode,
        };
        if (usePreset) {
          wsMsg.playbook_id = selectedPlaybookId;
          wsMsg.target = target.trim() || undefined;
        }

        const sent = sendViaWs(wsMsg);
        if (!sent) {
          const data = await api.queryAgent(
            usePreset ? displayContent : q,
            sid,
            {
              ...(usePreset ? { playbookId: selectedPlaybookId, target: target.trim() || undefined } : {}),
              mode,
            }
          );
          setLoading(false);
          if (data.session_id) setSessionId(data.session_id);
          appendAgentMessage(data);
          if (data.awaiting_question) setPendingAnswer(true);
          if (data.error) toast({ variant: 'destructive', title: 'Agent error', description: data.error });
          loadConversations();
        }
      }
    } catch (err: unknown) {
      setLoading(false);
      const msg = getApiErrorMessage(err as Error, 'Failed to send');
      toast({ variant: 'destructive', title: 'Error', description: msg });
      appendAgentMessage({ answer: `Error: ${msg}` });
    }
  };

  const handleApprove = async (decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!sessionId || loading) return;
    setLoading(true);
    setLiveStatus(null);

    const sent = sendViaWs({ type: 'approval', decision, modification });
    if (!sent) {
      try {
        const data = await api.approveAgent(sessionId, decision, modification);
        setLoading(false);
        appendAgentMessage(data);
        if (data.awaiting_question) setPendingAnswer(true);
        loadConversations();
      } catch (err: unknown) {
        setLoading(false);
        toast({ variant: 'destructive', title: 'Error', description: getApiErrorMessage(err as Error) });
      }
    }
  };

  // =========================================================================
  // Conversation history
  // =========================================================================

  const loadConversation = async (sid: string) => {
    try {
      const data = await api.getAgentConversation(sid);
      setSessionId(sid);
      const restored: Message[] = (data.messages || []).map((m: { role: string; content: string }, i: number) => ({
        id: `${m.role}-${i}`,
        role: m.role as MessageRole,
        content: m.content,
        phase: m.role === 'agent' ? data.current_phase : undefined,
      }));
      setMessages(restored);
      setShowHistory(false);
      setPendingAnswer(false);
    } catch {
      toast({ variant: 'destructive', title: 'Error', description: 'Could not load conversation' });
    }
  };

  const deleteConversation = async (sid: string) => {
    try {
      await api.deleteAgentConversation(sid);
      setConversations((prev) => prev.filter((c) => c.session_id !== sid));
      if (sessionId === sid) {
        startNewConversation();
      }
    } catch {
      toast({ variant: 'destructive', title: 'Error', description: 'Could not delete conversation' });
    }
  };

  const startNewConversation = () => {
    setMessages([]);
    setPendingAnswer(false);
    setLiveStatus(null);
    setShowHistory(false);
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    wsAuthenticatedRef.current = false;
    wsFailCountRef.current = 0;
    const newSid = crypto.randomUUID();
    setSessionId(newSid);
    setConnectionMode('connecting');
  };

  // =========================================================================
  // Render helpers
  // =========================================================================

  const connectionBadge = () => {
    switch (connectionMode) {
      case 'websocket':
        return <Badge variant="outline" className="text-green-500 border-green-500 gap-1 text-xs"><Wifi className="h-3 w-3" /> Live</Badge>;
      case 'rest':
        return <Badge variant="outline" className="text-yellow-500 border-yellow-500 gap-1 text-xs"><WifiOff className="h-3 w-3" /> REST</Badge>;
      case 'connecting':
        return <Badge variant="outline" className="text-muted-foreground gap-1 text-xs"><Loader2 className="h-3 w-3 animate-spin" /> Connecting</Badge>;
      default:
        return <Badge variant="outline" className="text-red-500 border-red-500 gap-1 text-xs"><WifiOff className="h-3 w-3" /> Offline</Badge>;
    }
  };

  const renderLiveStatus = () => {
    if (!liveStatus) return null;
    const { type, iteration, phase, thought, tool_name, success, output_summary } = liveStatus;

    if (type === 'thinking') {
      return (
        <div className="flex items-start gap-2 text-muted-foreground text-sm animate-pulse">
          <Loader2 className="h-4 w-4 animate-spin mt-0.5 shrink-0" />
          <div>
            <span className="font-medium">Step {iteration}</span>
            {phase && <Badge variant="outline" className="ml-2 text-xs">{phase}</Badge>}
            {thought && <p className="text-xs mt-0.5 opacity-80">{thought}</p>}
          </div>
        </div>
      );
    }

    if (type === 'tool_start') {
      return (
        <div className="flex items-start gap-2 text-muted-foreground text-sm">
          <Loader2 className="h-4 w-4 animate-spin mt-0.5 shrink-0" />
          <div>
            <span className="font-medium">Running tool:</span>{' '}
            <code className="bg-muted px-1 rounded text-xs">{tool_name}</code>
          </div>
        </div>
      );
    }

    if (type === 'tool_complete') {
      return (
        <div className="flex items-start gap-2 text-muted-foreground text-sm">
          {success ? <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 shrink-0" /> : <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />}
          <div>
            <code className="bg-muted px-1 rounded text-xs">{tool_name}</code>{' '}
            <span className="text-xs">{success ? 'completed' : 'failed'}</span>
            {output_summary && <p className="text-xs mt-0.5 opacity-70">{output_summary}</p>}
          </div>
        </div>
      );
    }

    return null;
  };

  return (
    <MainLayout>
      <Header title="Agent" subtitle="Ask questions and run tests. The agent uses security tools (Nuclei, Naabu, HTTPX, etc.) to perform scans and discovery." />
      <div className="space-y-4">
        {agentAvailable === false && (
          <Card className="border-amber-500/50 bg-amber-500/5">
            <CardContent className="pt-4 flex flex-col gap-2">
              <p className="text-sm flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-amber-500 shrink-0" />
                Agent is not available.
              </p>
              {agentStatusHint && <p className="text-sm text-muted-foreground pl-7">{agentStatusHint}</p>}
              {!agentStatusHint && (
                <p className="text-sm text-muted-foreground pl-7">
                  Configure <code className="bg-muted px-1 rounded">OPENAI_API_KEY</code> or <code className="bg-muted px-1 rounded">ANTHROPIC_API_KEY</code> in the backend .env, then restart.
                </p>
              )}
            </CardContent>
          </Card>
        )}

        <div className="flex gap-4">
          {/* Conversation History Sidebar */}
          {showHistory && (
            <Card className="w-72 shrink-0">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-1.5"><History className="h-4 w-4" /> History</CardTitle>
                  <Button variant="ghost" size="sm" onClick={startNewConversation} className="h-7 px-2">
                    <Plus className="h-3.5 w-3.5 mr-1" /> New
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="p-2 max-h-[60vh] overflow-y-auto space-y-1">
                {conversations.length === 0 && <p className="text-xs text-muted-foreground p-2">No conversations yet.</p>}
                {conversations.map((c) => (
                  <div
                    key={c.session_id}
                    className={`flex items-center gap-1.5 rounded-md px-2 py-1.5 cursor-pointer text-sm hover:bg-muted/60 transition-colors ${c.session_id === sessionId ? 'bg-muted' : ''}`}
                    onClick={() => loadConversation(c.session_id)}
                  >
                    <div className="flex-1 min-w-0">
                      <p className="truncate font-medium text-xs">{c.title || c.session_id.slice(0, 8)}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {new Date(c.updated_at).toLocaleDateString()} · {c.message_count} msgs
                      </p>
                    </div>
                    <Badge variant="outline" className="text-[10px] shrink-0">{c.current_phase}</Badge>
                    <Button
                      variant="ghost" size="icon" className="h-5 w-5 shrink-0 opacity-50 hover:opacity-100"
                      onClick={(e) => { e.stopPropagation(); deleteConversation(c.session_id); }}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Main Chat Card */}
          <Card className="flex-1">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <MessageSquare className="h-5 w-5" />
                  AI Security Agent
                </CardTitle>
                <div className="flex items-center gap-2">
                  {connectionBadge()}
                  <Button
                    variant="ghost" size="sm"
                    onClick={() => { setShowHistory(!showHistory); if (!showHistory) loadConversations(); }}
                    className="h-8 px-2"
                  >
                    <Clock className="h-4 w-4 mr-1" />
                    <span className="text-xs">{showHistory ? 'Hide' : 'History'}</span>
                  </Button>
                </div>
              </div>
              <CardDescription>
                Use the agent to query assets, scan targets, and analyze your attack surface. WebSocket provides real-time status; REST is used as fallback.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Chat messages */}
              <div className="rounded-lg border bg-muted/30 max-h-[50vh] overflow-y-auto p-4 space-y-3">
                {messages.length === 0 && (
                  <p className="text-muted-foreground text-sm">Send a message to start. The agent can run scans and discovery for your organization.</p>
                )}
                {messages.map((m) => (
                  <div key={m.id} className={`flex flex-col gap-1 ${m.role === 'user' ? 'items-end' : 'items-start'}`}>
                    <div className={`rounded-lg px-3 py-2 max-w-[85%] ${m.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted border'}`}>
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
                        <Button size="sm" onClick={() => handleApprove('approve')} disabled={loading}>Approve</Button>
                        <Button size="sm" variant="outline" onClick={() => handleApprove('abort')} disabled={loading}>Abort</Button>
                      </div>
                    )}
                    {m.role === 'agent' && m.awaitingQuestion && m.questionRequest && (
                      <p className="text-xs text-muted-foreground mt-1">Type your answer below and press Send.</p>
                    )}
                  </div>
                ))}

                {/* Live status indicator */}
                {loading && renderLiveStatus()}
                {loading && !liveStatus && (
                  <div className="flex items-center gap-2 text-muted-foreground text-sm">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Agent is thinking and may run tools…
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>

              {/* Controls */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="mode-select">Mode</Label>
                  <Select value={mode} onValueChange={(v) => setMode(v as 'assist' | 'agent')}>
                    <SelectTrigger id="mode-select"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="assist">Assist (approval required between phases)</SelectItem>
                      <SelectItem value="agent">Agent (autonomous; no approval)</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Agent mode runs without asking for approval between phases.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="playbook-select">Preset</Label>
                  <Select value={selectedPlaybookId} onValueChange={setSelectedPlaybookId}>
                    <SelectTrigger id="playbook-select"><SelectValue placeholder="Custom" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="custom">Custom (free-form question)</SelectItem>
                      {playbooks.map((p) => (
                        <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {selectedPlaybookId !== 'custom' && (
                  <div className="space-y-1.5">
                    <Label htmlFor="target-input">Target (optional)</Label>
                    <Input
                      id="target-input"
                      placeholder="e.g. example.com"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      disabled={loading || agentAvailable === false}
                    />
                  </div>
                )}
              </div>
              {urlPrefilled && (
                <p className="text-sm text-muted-foreground">Pre-filled from link. Click Send to start.</p>
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
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
                  }}
                  rows={2}
                  className="resize-none"
                  disabled={loading || agentAvailable === false}
                />
                <Button
                  onClick={handleSend}
                  disabled={loading || agentAvailable === false || (selectedPlaybookId === 'custom' ? !question.trim() : false)}
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
      </div>
    </MainLayout>
  );
}
