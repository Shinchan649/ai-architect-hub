import { Terminal, Shield, Wifi, WifiOff, Upload, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { MenuSection } from '@/types/app';

interface HomeSectionProps {
  appName: string;
  internetEnabled: boolean;
  onToggleInternet: () => void;
  onNavigate: (section: MenuSection) => void;
  uploadedFilesCount: number;
}

export function HomeSection({ 
  appName, 
  internetEnabled, 
  onToggleInternet,
  onNavigate,
  uploadedFilesCount
}: HomeSectionProps) {
  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto matrix-bg">
      {/* Hero */}
      <div className="flex-1 flex flex-col items-center justify-center text-center max-w-2xl mx-auto">
        <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/10 border border-primary/30 flex items-center justify-center mb-6 animate-float">
          <Shield className="h-12 w-12 text-primary" />
        </div>
        
        <h1 className="text-3xl md:text-4xl font-display font-bold text-foreground mb-3">
          Welcome to <span className="text-primary glow-text">{appName}</span>
        </h1>
        
        <p className="text-muted-foreground mb-8 max-w-lg">
          AI-driven cybersecurity testing & simulation platform for controlled lab environments. 
          All operations execute through secure, sandboxed environments with full transparency.
        </p>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full max-w-xl mb-8">
          <Button
            variant="cyber"
            size="lg"
            className="flex-col h-auto py-6 gap-2"
            onClick={() => onNavigate('console')}
          >
            <Terminal className="h-6 w-6" />
            <span>Open Console</span>
          </Button>

          <Button
            variant={internetEnabled ? "accent" : "outline"}
            size="lg"
            className="flex-col h-auto py-6 gap-2"
            onClick={onToggleInternet}
          >
            {internetEnabled ? (
              <>
                <Wifi className="h-6 w-6" />
                <span>Internet ON</span>
              </>
            ) : (
              <>
                <WifiOff className="h-6 w-6" />
                <span>Internet OFF</span>
              </>
            )}
          </Button>

          <Button
            variant="outline"
            size="lg"
            className="flex-col h-auto py-6 gap-2 relative"
            onClick={() => onNavigate('settings')}
          >
            <Upload className="h-6 w-6" />
            <span>Add Files</span>
            {uploadedFilesCount > 0 && (
              <span className="absolute top-2 right-2 bg-primary text-primary-foreground text-xs rounded-full w-5 h-5 flex items-center justify-center">
                {uploadedFilesCount}
              </span>
            )}
          </Button>
        </div>

        {/* Status Cards */}
        <div className="grid grid-cols-2 gap-4 w-full max-w-lg">
          <div className="cyber-card rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-2 h-2 rounded-full ${internetEnabled ? 'bg-accent animate-pulse' : 'bg-muted-foreground'}`} />
              <span className="text-sm text-muted-foreground">Network Status</span>
            </div>
            <p className="text-lg font-medium text-foreground">
              {internetEnabled ? 'Online Mode' : 'Offline Mode'}
            </p>
          </div>

          <div className="cyber-card rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="h-3 w-3 text-primary" />
              <span className="text-sm text-muted-foreground">Files Loaded</span>
            </div>
            <p className="text-lg font-medium text-foreground">
              {uploadedFilesCount} files
            </p>
          </div>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="mt-8 p-4 rounded-lg border border-primary/20 bg-primary/5 max-w-2xl mx-auto">
        <p className="text-xs text-center text-muted-foreground">
          <span className="text-primary font-medium">⚠️ Lab Environment Only</span> — 
          All operations require explicit confirmation. No execution occurs without user approval.
        </p>
      </div>
    </div>
  );
}
