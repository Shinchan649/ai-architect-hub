import { Download, X } from 'lucide-react';
import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';

export const InstallBanner = () => {
  const [isVisible, setIsVisible] = useState(true);
  const [isStandalone, setIsStandalone] = useState(false);

  useEffect(() => {
    // Check if already installed as PWA
    const standalone = window.matchMedia('(display-mode: standalone)').matches;
    setIsStandalone(standalone);
    
    // Check if user dismissed the banner
    const dismissed = localStorage.getItem('install-banner-dismissed');
    if (dismissed) {
      setIsVisible(false);
    }
  }, []);

  const handleDismiss = () => {
    setIsVisible(false);
    localStorage.setItem('install-banner-dismissed', 'true');
  };

  // Don't show if already installed or dismissed
  if (!isVisible || isStandalone) {
    return null;
  }

  return (
    <div className="bg-primary/10 border-b border-primary/30 px-4 py-2 flex items-center justify-between gap-4">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <Download className="h-4 w-4 text-primary shrink-0 animate-pulse" />
        <p className="text-sm text-foreground truncate">
          <span className="font-medium">Install this app</span>
          <span className="hidden sm:inline text-muted-foreground"> — Use it offline on your phone!</span>
        </p>
      </div>
      
      <div className="flex items-center gap-2 shrink-0">
        <Button asChild size="sm" className="h-7 text-xs">
          <Link to="/install">
            Install
          </Link>
        </Button>
        <button
          onClick={handleDismiss}
          className="p-1 hover:bg-muted rounded transition-colors"
          aria-label="Dismiss"
        >
          <X className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>
    </div>
  );
};
