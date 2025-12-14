import { useRef, useEffect } from 'react';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { ChatSession } from '@/types/chat';
import { Bot, Sparkles } from 'lucide-react';

interface ChatAreaProps {
  session: ChatSession | null;
  isLoading: boolean;
  onSendMessage: (message: string) => void;
}

export function ChatArea({ session, isLoading, onSendMessage }: ChatAreaProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session?.messages]);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6 matrix-bg scanline">
        {session?.messages && session.messages.length > 0 ? (
          <>
            {session.messages.map((message) => (
              <MessageBubble key={message.id} message={message} />
            ))}
            {isLoading && (
              <div className="flex gap-3 animate-fade-in">
                <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
                  <Bot className="h-4 w-4 text-primary" />
                </div>
                <div className="cyber-card rounded-lg p-4 max-w-[80%]">
                  <div className="flex items-center gap-2 text-primary">
                    <Sparkles className="h-4 w-4 animate-pulse" />
                    <span className="text-sm typing-cursor">Processing</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center animate-fade-in">
            <div className="w-24 h-24 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center mb-6 animate-float">
              <span className="text-4xl font-display font-bold text-primary glow-text">0x</span>
            </div>
            <h2 className="text-2xl font-display font-bold text-foreground mb-2">
              Welcome to <span className="text-primary glow-text">0x.AI</span>
            </h2>
            <p className="text-muted-foreground max-w-md mb-8">
              Your cybernetic AI assistant. Start a conversation or configure your API settings to begin.
            </p>
            <div className="grid gap-3 max-w-lg w-full">
              {[
                "What can you help me with?",
                "Tell me about your capabilities",
                "How do I configure the API?",
              ].map((prompt, i) => (
                <button
                  key={i}
                  onClick={() => onSendMessage(prompt)}
                  className="p-4 text-left rounded-lg border border-primary/20 bg-card/50 hover:bg-primary/10 hover:border-primary/50 transition-all duration-300 group"
                >
                  <span className="text-sm text-muted-foreground group-hover:text-foreground transition-colors">
                    {prompt}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Input Area */}
      <ChatInput onSend={onSendMessage} isLoading={isLoading} />
    </div>
  );
}
