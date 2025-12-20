import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Download, Smartphone, Check, Share, MoreVertical } from 'lucide-react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

const Install = () => {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIOS, setIsIOS] = useState(false);

  useEffect(() => {
    // Check if already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      setIsInstalled(true);
    }

    // Check if iOS
    const isIOSDevice = /iPad|iPhone|iPod/.test(navigator.userAgent);
    setIsIOS(isIOSDevice);

    // Listen for install prompt
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, []);

  const handleInstall = async () => {
    if (!deferredPrompt) return;

    await deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    
    if (outcome === 'accepted') {
      setIsInstalled(true);
    }
    setDeferredPrompt(null);
  };

  if (isInstalled) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full bg-card border-border">
          <CardHeader className="text-center">
            <div className="mx-auto w-16 h-16 bg-primary/20 rounded-full flex items-center justify-center mb-4">
              <Check className="w-8 h-8 text-primary" />
            </div>
            <CardTitle className="text-foreground">App Installed!</CardTitle>
            <CardDescription className="text-muted-foreground">
              VEXX AI is now installed on your device. You can find it on your home screen.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="max-w-md w-full bg-card border-border">
        <CardHeader className="text-center">
          <div className="mx-auto w-20 h-20 mb-4">
            <img src="/pwa-192x192.png" alt="VEXX AI" className="w-full h-full rounded-2xl" />
          </div>
          <CardTitle className="text-foreground text-2xl">Install VEXX AI</CardTitle>
          <CardDescription className="text-muted-foreground">
            Install this app on your device for the best experience. Works offline!
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isIOS ? (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground text-center">
                To install on iPhone/iPad:
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <Share className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Tap the Share button</span>
                </div>
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <Download className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Select "Add to Home Screen"</span>
                </div>
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <Check className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Tap "Add" to confirm</span>
                </div>
              </div>
            </div>
          ) : deferredPrompt ? (
            <Button onClick={handleInstall} className="w-full" size="lg">
              <Download className="w-5 h-5 mr-2" />
              Install App
            </Button>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground text-center">
                To install on Android:
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <MoreVertical className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Tap the menu (⋮) in Chrome</span>
                </div>
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <Smartphone className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Select "Install app" or "Add to Home Screen"</span>
                </div>
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <Check className="w-5 h-5 text-primary" />
                  <span className="text-sm text-foreground">Tap "Install" to confirm</span>
                </div>
              </div>
            </div>
          )}
          
          <div className="pt-4 border-t border-border">
            <h4 className="font-medium text-foreground mb-2">Why install?</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>✓ Works offline - no internet needed</li>
              <li>✓ Faster loading</li>
              <li>✓ Full screen experience</li>
              <li>✓ Easy access from home screen</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Install;