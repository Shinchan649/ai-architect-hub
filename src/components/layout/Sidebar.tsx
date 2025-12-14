import { useState } from 'react';
import { MessageSquare, Plus, Settings, FileText, Trash2, Menu, X, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ChatSession } from '@/types/chat';
import { cn } from '@/lib/utils';

interface SidebarProps {
  sessions: ChatSession[];
  currentSessionId: string | null;
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
  onDeleteSession: (id: string) => void;
  onOpenSettings: () => void;
  onOpenLicense: () => void;
}

export function Sidebar({
  sessions,
  currentSessionId,
  onSelectSession,
  onNewChat,
  onDeleteSession,
  onOpenSettings,
  onOpenLicense,
}: SidebarProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-4 border-b border-primary/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
            <span className="text-primary font-display font-bold text-lg">0x</span>
          </div>
          {!isCollapsed && (
            <div className="animate-fade-in">
              <h1 className="font-display text-lg font-bold text-foreground glow-text">0x.AI</h1>
              <p className="text-xs text-muted-foreground">Cybernetic Assistant</p>
            </div>
          )}
        </div>
      </div>

      {/* New Chat Button */}
      <div className="p-3">
        <Button
          variant="cyber"
          className={cn("w-full", isCollapsed && "px-2")}
          onClick={onNewChat}
        >
          <Plus className="h-4 w-4" />
          {!isCollapsed && <span>New Chat</span>}
        </Button>
      </div>

      {/* Sessions List */}
      <div className="flex-1 overflow-y-auto px-2 space-y-1">
        {sessions.map((session) => (
          <div
            key={session.id}
            className={cn(
              "group flex items-center gap-2 p-2 rounded-md cursor-pointer transition-all duration-200",
              currentSessionId === session.id
                ? "bg-primary/20 border border-primary/50"
                : "hover:bg-muted/50 border border-transparent"
            )}
            onClick={() => onSelectSession(session.id)}
          >
            <MessageSquare className="h-4 w-4 text-primary shrink-0" />
            {!isCollapsed && (
              <>
                <span className="flex-1 truncate text-sm text-foreground">
                  {session.title}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteSession(session.id);
                  }}
                >
                  <Trash2 className="h-3 w-3 text-destructive" />
                </Button>
              </>
            )}
          </div>
        ))}
        {sessions.length === 0 && !isCollapsed && (
          <div className="text-center py-8 text-muted-foreground text-sm">
            No conversations yet
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-3 border-t border-primary/20 space-y-1">
        <Button
          variant="ghost"
          className={cn("w-full justify-start", isCollapsed && "justify-center px-2")}
          onClick={onOpenSettings}
        >
          <Settings className="h-4 w-4" />
          {!isCollapsed && <span>Settings</span>}
        </Button>
        <Button
          variant="ghost"
          className={cn("w-full justify-start", isCollapsed && "justify-center px-2")}
          onClick={onOpenLicense}
        >
          <FileText className="h-4 w-4" />
          {!isCollapsed && <span>License</span>}
        </Button>
      </div>

      {/* Collapse Toggle */}
      <div className="p-2 border-t border-primary/20 hidden md:block">
        <Button
          variant="ghost"
          size="sm"
          className="w-full"
          onClick={() => setIsCollapsed(!isCollapsed)}
        >
          <ChevronRight className={cn("h-4 w-4 transition-transform", isCollapsed ? "" : "rotate-180")} />
        </Button>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Toggle */}
      <Button
        variant="outline"
        size="icon"
        className="fixed top-4 left-4 z-50 md:hidden"
        onClick={() => setIsMobileOpen(!isMobileOpen)}
      >
        {isMobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
      </Button>

      {/* Mobile Overlay */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 md:hidden"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed md:relative z-40 h-full bg-card border-r border-primary/20 transition-all duration-300",
          isCollapsed ? "w-16" : "w-64",
          isMobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        <SidebarContent />
      </aside>
    </>
  );
}
