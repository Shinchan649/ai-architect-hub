import { useState, useEffect } from 'react';
import { X, Key, Palette, Database, Download, Trash2, Save, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AppSettings, ChatSession } from '@/types/chat';
import { cn } from '@/lib/utils';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  settings: AppSettings;
  onSaveSettings: (settings: AppSettings) => void;
  sessions: ChatSession[];
  onClearSessions: () => void;
}

type TabType = 'api' | 'appearance' | 'data';

export function SettingsModal({
  isOpen,
  onClose,
  settings,
  onSaveSettings,
  sessions,
  onClearSessions,
}: SettingsModalProps) {
  const [activeTab, setActiveTab] = useState<TabType>('api');
  const [localSettings, setLocalSettings] = useState<AppSettings>(settings);
  const [showApiKey, setShowApiKey] = useState(false);

  useEffect(() => {
    setLocalSettings(settings);
  }, [settings]);

  if (!isOpen) return null;

  const handleSave = () => {
    onSaveSettings(localSettings);
    onClose();
  };

  const handleExportChats = () => {
    const data = JSON.stringify(sessions, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `0xai-chats-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'api', label: 'API', icon: <Key className="h-4 w-4" /> },
    { id: 'appearance', label: 'Appearance', icon: <Palette className="h-4 w-4" /> },
    { id: 'data', label: 'Data', icon: <Database className="h-4 w-4" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-2xl cyber-card rounded-xl border border-primary/30 animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-primary/20">
          <h2 className="text-xl font-display font-bold text-foreground">Settings</h2>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-5 w-5" />
          </Button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-primary/20">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex-1 flex items-center justify-center gap-2 py-3 px-4 text-sm font-medium transition-all",
                activeTab === tab.id
                  ? "text-primary border-b-2 border-primary bg-primary/5"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="p-6 min-h-[300px]">
          {activeTab === 'api' && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  AI Provider
                </label>
                <select
                  value={localSettings.apiProvider}
                  onChange={(e) => setLocalSettings({ ...localSettings, apiProvider: e.target.value as AppSettings['apiProvider'] })}
                  className="w-full h-10 rounded-md border border-primary/30 bg-muted/50 px-3 text-sm focus:border-primary focus:ring-2 focus:ring-primary/50"
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="custom">Custom API</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  API Key
                </label>
                <div className="relative">
                  <Input
                    type={showApiKey ? 'text' : 'password'}
                    value={localSettings.apiKey}
                    onChange={(e) => setLocalSettings({ ...localSettings, apiKey: e.target.value })}
                    placeholder="Enter your API key..."
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Your API key is stored locally and never sent to our servers.
                </p>
              </div>

              {localSettings.apiProvider === 'custom' && (
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Custom API URL
                  </label>
                  <Input
                    type="url"
                    value={localSettings.customApiUrl || ''}
                    onChange={(e) => setLocalSettings({ ...localSettings, customApiUrl: e.target.value })}
                    placeholder="https://api.example.com/v1/chat"
                  />
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  Model
                </label>
                <Input
                  type="text"
                  value={localSettings.model}
                  onChange={(e) => setLocalSettings({ ...localSettings, model: e.target.value })}
                  placeholder="gpt-4, claude-3, etc."
                />
              </div>
            </div>
          )}

          {activeTab === 'appearance' && (
            <div className="space-y-6 animate-fade-in">
              <div>
                <label className="block text-sm font-medium text-foreground mb-2">
                  App Name
                </label>
                <Input
                  type="text"
                  value={localSettings.appName}
                  onChange={(e) => setLocalSettings({ ...localSettings, appName: e.target.value })}
                  placeholder="0x.AI"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-4">
                  Theme
                </label>
                <div className="grid grid-cols-3 gap-3">
                  {(['dark', 'cyber', 'light'] as const).map((theme) => (
                    <button
                      key={theme}
                      onClick={() => setLocalSettings({ ...localSettings, theme })}
                      className={cn(
                        "p-4 rounded-lg border-2 transition-all capitalize",
                        localSettings.theme === theme
                          ? "border-primary bg-primary/10"
                          : "border-primary/20 hover:border-primary/50"
                      )}
                    >
                      {theme}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'data' && (
            <div className="space-y-6 animate-fade-in">
              <div className="p-4 rounded-lg border border-primary/20 bg-muted/30">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-medium text-foreground">Chat History</h3>
                    <p className="text-sm text-muted-foreground">
                      {sessions.length} conversation{sessions.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={handleExportChats}>
                      <Download className="h-4 w-4 mr-1" />
                      Export
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={onClearSessions}
                      disabled={sessions.length === 0}
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      Clear All
                    </Button>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-lg border border-destructive/30 bg-destructive/5">
                <h3 className="font-medium text-destructive mb-2">Danger Zone</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Reset all app data including settings and chat history. This action cannot be undone.
                </p>
                <Button
                  variant="destructive"
                  onClick={() => {
                    if (confirm('Are you sure you want to reset all data? This cannot be undone.')) {
                      localStorage.clear();
                      window.location.reload();
                    }
                  }}
                >
                  Reset App Data
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-6 border-t border-primary/20">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="cyber" onClick={handleSave}>
            <Save className="h-4 w-4 mr-1" />
            Save Changes
          </Button>
        </div>
      </div>
    </div>
  );
}
