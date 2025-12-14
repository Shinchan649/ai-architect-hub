import { useState, useRef, useEffect } from 'react';
import { Send, Loader2, Bot, User, AlertTriangle, CheckCircle, XCircle, Wifi, WifiOff, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ChatSession, Message, UploadedFile } from '@/types/app';
import { cn } from '@/lib/utils';

interface ConsoleSectionProps {
  session: ChatSession | null;
  isLoading: boolean;
  onSendMessage: (message: string) => void;
  internetEnabled: boolean;
  onToggleInternet: () => void;
  uploadedFiles: UploadedFile[];
  onOpenFileManager: () => void;
}

function MessageBubble({ message }: { message: Message }) {
  const isUser = message.role === 'user';
  const isConfirmation = message.type === 'execution';

  return (
    <div className={cn("flex gap-3 animate-slide-up", isUser ? "flex-row-reverse" : "flex-row")}>
      <div className={cn(
        "w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border",
        isUser
          ? "bg-accent/20 border-accent/50"
          : "bg-primary/20 border-primary/50"
      )}>
        {isUser ? (
          <User className="h-4 w-4 text-accent" />
        ) : (
          <Bot className="h-4 w-4 text-primary" />
        )}
      </div>

      <div className={cn(
        "max-w-[80%] rounded-lg p-4 border",
        isUser
          ? "bg-accent/10 border-accent/30"
          : isConfirmation
            ? "bg-destructive/10 border-destructive/30"
            : "cyber-card"
      )}>
        {isConfirmation && (
          <div className="flex items-center gap-2 mb-2 text-destructive">
            <AlertTriangle className="h-4 w-4" />
            <span className="text-xs font-medium uppercase tracking-wider">Confirmation Required</span>
          </div>
        )}
        <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
        
        {isConfirmation && (
          <div className="flex gap-2 mt-4">
            <Button variant="accent" size="sm" className="flex-1">
              <CheckCircle className="h-4 w-4 mr-1" />
              Confirm
            </Button>
            <Button variant="destructive" size="sm" className="flex-1">
              <XCircle className="h-4 w-4 mr-1" />
              Cancel
            </Button>
          </div>
        )}
        
        <span className="text-xs text-muted-foreground mt-2 block">
          {new Date(message.timestamp).toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
}

export function ConsoleSection({
  session,
  isLoading,
  onSendMessage,
  internetEnabled,
  onToggleInternet,
  uploadedFiles,
  onOpenFileManager,
}: ConsoleSectionProps) {
  const [message, setMessage] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session?.messages]);

  const handleSend = () => {
    if (message.trim() && !isLoading) {
      onSendMessage(message.trim());
      setMessage('');
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header Bar */}
      <div className="p-3 border-b border-primary/20 bg-card/50 flex items-center justify-between gap-4">
        <h2 className="font-display font-bold text-foreground">Interaction Console</h2>
        
        <div className="flex items-center gap-2">
          {/* Internet Toggle */}
          <Button
            variant={internetEnabled ? "accent" : "outline"}
            size="sm"
            onClick={onToggleInternet}
            className="gap-1"
          >
            {internetEnabled ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            <span className="hidden sm:inline">{internetEnabled ? 'Online' : 'Offline'}</span>
          </Button>

          {/* File Manager */}
          <Button
            variant="outline"
            size="sm"
            onClick={onOpenFileManager}
            className="gap-1 relative"
          >
            <Upload className="h-3 w-3" />
            <span className="hidden sm:inline">Files</span>
            {uploadedFiles.length > 0 && (
              <span className="absolute -top-1 -right-1 bg-primary text-primary-foreground text-xs rounded-full w-4 h-4 flex items-center justify-center">
                {uploadedFiles.length}
              </span>
            )}
          </Button>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 matrix-bg scanline">
        {session?.messages && session.messages.length > 0 ? (
          <>
            {session.messages.map((msg) => (
              <MessageBubble key={msg.id} message={msg} />
            ))}
            {isLoading && (
              <div className="flex gap-3 animate-fade-in">
                <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
                  <Bot className="h-4 w-4 text-primary" />
                </div>
                <div className="cyber-card rounded-lg p-4">
                  <div className="flex items-center gap-2 text-primary">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm">Analyzing request...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center">
            <Bot className="h-16 w-16 text-primary/30 mb-4" />
            <h3 className="text-lg font-display font-bold text-foreground mb-2">
              Ready for Commands
            </h3>
            <p className="text-sm text-muted-foreground max-w-md">
              Describe your testing task in natural language. The AI will analyze, 
              determine required tools, and request confirmation before execution.
            </p>
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-primary/20 bg-card/50">
        <div className="flex gap-2">
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            placeholder="Describe your task..."
            disabled={isLoading}
            rows={1}
            className="flex-1 bg-muted/30 border border-primary/30 rounded-lg px-4 py-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50 resize-none font-mono text-sm"
          />
          <Button
            variant="cyber"
            size="icon"
            onClick={handleSend}
            disabled={!message.trim() || isLoading}
            className="h-auto aspect-square"
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground text-center mt-2">
          All executions require explicit confirmation • Press Enter to send
        </p>
      </div>
    </div>
  );
}
