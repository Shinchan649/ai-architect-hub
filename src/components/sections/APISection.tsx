import { useState } from 'react';
import { Key, Plus, Trash2, Check, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ExternalAPI, AppSettings } from '@/types/app';
import { cn } from '@/lib/utils';

interface APISectionProps {
  settings: AppSettings;
  onUpdateSettings: (settings: AppSettings) => void;
}

const generateId = () => Math.random().toString(36).substring(2, 15);

export function APISection({ settings, onUpdateSettings }: APISectionProps) {
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({});
  const [isAdding, setIsAdding] = useState(false);
  const [newAPI, setNewAPI] = useState<Partial<ExternalAPI>>({
    name: '',
    key: '',
    provider: 'openai',
  });

  const toggleShowKey = (id: string) => {
    setShowKeys(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleAddAPI = () => {
    if (!newAPI.name || !newAPI.key) return;
    if (settings.externalAPIs.length >= 4) return;

    const api: ExternalAPI = {
      id: generateId(),
      name: newAPI.name,
      key: newAPI.key,
      provider: newAPI.provider as ExternalAPI['provider'],
      endpoint: newAPI.endpoint,
      isActive: settings.externalAPIs.length === 0,
    };

    onUpdateSettings({
      ...settings,
      externalAPIs: [...settings.externalAPIs, api],
      activeAPIId: settings.externalAPIs.length === 0 ? api.id : settings.activeAPIId,
    });

    setNewAPI({ name: '', key: '', provider: 'openai' });
    setIsAdding(false);
  };

  const handleRemoveAPI = (id: string) => {
    const updated = settings.externalAPIs.filter(a => a.id !== id);
    onUpdateSettings({
      ...settings,
      externalAPIs: updated,
      activeAPIId: settings.activeAPIId === id ? (updated[0]?.id || null) : settings.activeAPIId,
    });
  };

  const handleSetActive = (id: string) => {
    onUpdateSettings({
      ...settings,
      activeAPIId: id,
      externalAPIs: settings.externalAPIs.map(a => ({
        ...a,
        isActive: a.id === id,
      })),
    });
  };

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      <div className="max-w-2xl mx-auto w-full space-y-6">
        <div>
          <h2 className="text-2xl font-display font-bold text-foreground mb-2">API Management</h2>
          <p className="text-muted-foreground text-sm">
            Manage your AI provider connections. External APIs are sandboxed and cannot modify app code.
          </p>
        </div>

        {/* Internal API (View Only) */}
        <div className="cyber-card rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-accent/20 border border-accent/50 flex items-center justify-center">
              <Key className="h-4 w-4 text-accent" />
            </div>
            <div>
              <h3 className="font-medium text-foreground">Internal Technician API</h3>
              <p className="text-xs text-muted-foreground">For app modification only (read-only view)</p>
            </div>
          </div>
          <div className="bg-muted/30 rounded-lg p-3 border border-primary/10">
            <p className="text-sm text-muted-foreground font-mono">
              {settings.internalAPIKey 
                ? '••••••••••••••••••••••••' 
                : 'Not configured (set in Modification section)'}
            </p>
          </div>
        </div>

        {/* External APIs */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-medium text-foreground">External APIs ({settings.externalAPIs.length}/4)</h3>
            {settings.externalAPIs.length < 4 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsAdding(true)}
                disabled={isAdding}
              >
                <Plus className="h-4 w-4 mr-1" />
                Add API
              </Button>
            )}
          </div>

          {settings.externalAPIs.length === 0 && !isAdding && (
            <div className="cyber-card rounded-lg p-6 text-center">
              <AlertCircle className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">
                No external APIs configured. Add an API to enable AI-powered analysis.
              </p>
            </div>
          )}

          {settings.externalAPIs.map((api) => (
            <div
              key={api.id}
              className={cn(
                "cyber-card rounded-lg p-4 transition-all",
                api.isActive && "border-primary/50 glow-primary"
              )}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={cn(
                    "w-8 h-8 rounded-lg border flex items-center justify-center",
                    api.isActive 
                      ? "bg-primary/20 border-primary/50" 
                      : "bg-muted/50 border-muted-foreground/20"
                  )}>
                    <Key className={cn("h-4 w-4", api.isActive ? "text-primary" : "text-muted-foreground")} />
                  </div>
                  <div>
                    <h4 className="font-medium text-foreground">{api.name}</h4>
                    <p className="text-xs text-muted-foreground capitalize">{api.provider}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {!api.isActive && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleSetActive(api.id)}
                    >
                      <Check className="h-4 w-4 mr-1" />
                      Use
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => handleRemoveAPI(api.id)}
                    className="text-destructive hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
              <div className="flex items-center gap-2 bg-muted/30 rounded-lg p-2 border border-primary/10">
                <span className="flex-1 text-sm font-mono text-muted-foreground truncate">
                  {showKeys[api.id] ? api.key : '••••••••••••••••••••••••'}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6"
                  onClick={() => toggleShowKey(api.id)}
                >
                  {showKeys[api.id] ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                </Button>
              </div>
              {api.isActive && (
                <div className="mt-2 flex items-center gap-1 text-xs text-accent">
                  <Check className="h-3 w-3" />
                  Currently active
                </div>
              )}
            </div>
          ))}

          {/* Add API Form */}
          {isAdding && (
            <div className="cyber-card rounded-lg p-4 border-2 border-dashed border-primary/30">
              <h4 className="font-medium text-foreground mb-3">Add New API</h4>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Name</label>
                  <Input
                    value={newAPI.name || ''}
                    onChange={(e) => setNewAPI({ ...newAPI, name: e.target.value })}
                    placeholder="My API"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Provider</label>
                  <select
                    value={newAPI.provider}
                    onChange={(e) => setNewAPI({ ...newAPI, provider: e.target.value as ExternalAPI['provider'] })}
                    className="w-full h-10 rounded-md border border-primary/30 bg-muted/50 px-3 text-sm focus:border-primary focus:ring-2 focus:ring-primary/50"
                  >
                    <option value="openai">OpenAI</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="google">Google</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">API Key</label>
                  <Input
                    type="password"
                    value={newAPI.key || ''}
                    onChange={(e) => setNewAPI({ ...newAPI, key: e.target.value })}
                    placeholder="sk-..."
                  />
                </div>
                {newAPI.provider === 'custom' && (
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Custom Endpoint</label>
                    <Input
                      value={newAPI.endpoint || ''}
                      onChange={(e) => setNewAPI({ ...newAPI, endpoint: e.target.value })}
                      placeholder="https://api.example.com/v1"
                    />
                  </div>
                )}
                <div className="flex gap-2 pt-2">
                  <Button variant="outline" onClick={() => setIsAdding(false)} className="flex-1">
                    Cancel
                  </Button>
                  <Button 
                    variant="cyber" 
                    onClick={handleAddAPI} 
                    className="flex-1"
                    disabled={!newAPI.name || !newAPI.key}
                  >
                    Add API
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Info */}
        <div className="p-4 rounded-lg border border-primary/20 bg-primary/5">
          <p className="text-xs text-muted-foreground">
            <span className="text-primary font-medium">Security Note:</span> External APIs are sandboxed. 
            They can be used for chat and analysis but cannot access or modify app configuration.
          </p>
        </div>
      </div>
    </div>
  );
}
