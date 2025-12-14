import { 
  Home, 
  Terminal, 
  Key, 
  Shield, 
  FileText, 
  Settings, 
  ScrollText, 
  Info,
  Lock,
  Menu,
  X
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { MenuSection } from '@/types/app';
import { cn } from '@/lib/utils';
import { useState } from 'react';

interface MainSidebarProps {
  activeSection: MenuSection;
  onSectionChange: (section: MenuSection) => void;
  appName: string;
  isAuthenticated: boolean;
}

const menuItems: { id: MenuSection; label: string; icon: React.ReactNode; locked?: boolean }[] = [
  { id: 'home', label: 'Home', icon: <Home className="h-4 w-4" /> },
  { id: 'console', label: 'Interaction Console', icon: <Terminal className="h-4 w-4" /> },
  { id: 'api', label: 'API', icon: <Key className="h-4 w-4" /> },
  { id: 'modification', label: 'Modification', icon: <Shield className="h-4 w-4" />, locked: true },
  { id: 'license', label: 'License', icon: <FileText className="h-4 w-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
  { id: 'logs', label: 'Logs', icon: <ScrollText className="h-4 w-4" /> },
  { id: 'about', label: 'About', icon: <Info className="h-4 w-4" /> },
];

export function MainSidebar({ activeSection, onSectionChange, appName, isAuthenticated }: MainSidebarProps) {
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-4 border-b border-primary/20">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/30 to-accent/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
            <span className="text-primary font-display font-bold text-sm">0.x"</span>
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="font-display text-base font-bold text-foreground glow-text truncate">
              {appName}
            </h1>
            <p className="text-xs text-muted-foreground">Cybersecurity AI Platform</p>
          </div>
        </div>
      </div>

      {/* Menu Items */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => {
              onSectionChange(item.id);
              setIsMobileOpen(false);
            }}
            className={cn(
              "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
              activeSection === item.id
                ? "bg-primary/20 text-primary border border-primary/50 glow-primary"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            )}
          >
            <span className={cn(
              "transition-colors",
              activeSection === item.id ? "text-primary" : ""
            )}>
              {item.icon}
            </span>
            <span className="flex-1 text-left">{item.label}</span>
            {item.locked && (
              <Lock className={cn(
                "h-3 w-3",
                isAuthenticated && item.id === 'modification' ? "text-accent" : "text-muted-foreground"
              )} />
            )}
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-primary/20">
        <p className="text-xs text-center text-muted-foreground">
          Created by <span className="text-primary font-medium">0.x" vexX</span>
        </p>
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
          "fixed md:relative z-40 h-full w-64 bg-card border-r border-primary/20 transition-transform duration-300",
          isMobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        <SidebarContent />
      </aside>
    </>
  );
}
