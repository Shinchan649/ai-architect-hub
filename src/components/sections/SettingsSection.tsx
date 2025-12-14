import { useState, useRef } from 'react';
import { Upload, Trash2, FileCode, FileText, FileType, Settings, Download, File } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { UploadedFile, AppSettings } from '@/types/app';
import { cn } from '@/lib/utils';

interface SettingsSectionProps {
  settings: AppSettings;
  uploadedFiles: UploadedFile[];
  onAddFile: (file: Omit<UploadedFile, 'id' | 'uploadedAt'>) => void;
  onRemoveFile: (fileId: string) => void;
  onUpdateSettings: (settings: AppSettings) => void;
}

const fileTypeIcons: Record<string, React.ReactNode> = {
  script: <FileCode className="h-4 w-4" />,
  wordlist: <FileText className="h-4 w-4" />,
  config: <Settings className="h-4 w-4" />,
  tool: <FileType className="h-4 w-4" />,
  other: <File className="h-4 w-4" />,
};

export function SettingsSection({
  settings,
  uploadedFiles,
  onAddFile,
  onRemoveFile,
  onUpdateSettings,
}: SettingsSectionProps) {
  const [activeTab, setActiveTab] = useState<'files' | 'general'>('files');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    for (const file of Array.from(files)) {
      const content = await file.text();
      const type = getFileType(file.name);
      
      onAddFile({
        name: file.name,
        type,
        content,
      });
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const getFileType = (filename: string): UploadedFile['type'] => {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (['sh', 'py', 'js', 'rb', 'pl'].includes(ext || '')) return 'script';
    if (['txt', 'lst', 'dic'].includes(ext || '')) return 'wordlist';
    if (['conf', 'cfg', 'ini', 'yaml', 'yml', 'json'].includes(ext || '')) return 'config';
    return 'other';
  };

  const handleExportFiles = () => {
    const data = JSON.stringify(uploadedFiles, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vexai-files-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      <div className="max-w-3xl mx-auto w-full">
        <h2 className="text-2xl font-display font-bold text-foreground mb-6">Settings</h2>

        {/* Tabs */}
        <div className="flex border-b border-primary/20 mb-6">
          {(['files', 'general'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                "px-4 py-2 text-sm font-medium capitalize transition-all",
                activeTab === tab
                  ? "text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {tab === 'files' ? 'Files & Tools' : 'General'}
            </button>
          ))}
        </div>

        {activeTab === 'files' && (
          <div className="space-y-6">
            {/* Upload Area */}
            <div className="cyber-card rounded-lg p-6">
              <h3 className="font-medium text-foreground mb-4">Add Files / Tools</h3>
              <p className="text-sm text-muted-foreground mb-4">
                Upload scripts, wordlists, config files, or custom tools. The AI can only use files you explicitly add.
              </p>
              
              <input
                ref={fileInputRef}
                type="file"
                multiple
                onChange={handleFileUpload}
                className="hidden"
              />
              
              <Button
                variant="cyber"
                className="w-full h-24 flex-col gap-2 border-dashed"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-6 w-6" />
                <span>Click to upload files</span>
              </Button>
            </div>

            {/* Uploaded Files */}
            <div className="cyber-card rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-medium text-foreground">Uploaded Files ({uploadedFiles.length})</h3>
                {uploadedFiles.length > 0 && (
                  <Button variant="outline" size="sm" onClick={handleExportFiles}>
                    <Download className="h-4 w-4 mr-1" />
                    Export
                  </Button>
                )}
              </div>

              {uploadedFiles.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No files uploaded yet
                </div>
              ) : (
                <div className="space-y-2">
                  {uploadedFiles.map((file) => (
                    <div
                      key={file.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-primary/10 hover:border-primary/30 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center text-primary">
                          {fileTypeIcons[file.type]}
                        </div>
                        <div>
                          <p className="text-sm font-medium text-foreground">{file.name}</p>
                          <p className="text-xs text-muted-foreground capitalize">
                            {file.type} • {new Date(file.uploadedAt).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => onRemoveFile(file.id)}
                        className="text-destructive hover:text-destructive"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'general' && (
          <div className="space-y-6">
            <div className="cyber-card rounded-lg p-6">
              <h3 className="font-medium text-foreground mb-4">Internet Access</h3>
              <p className="text-sm text-muted-foreground mb-4">
                When enabled, the AI can access public vulnerability databases, documentation, and tool references.
              </p>
              <div className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-primary/10">
                <span className="text-sm text-foreground">Network Access</span>
                <button
                  onClick={() => onUpdateSettings({ ...settings, internetEnabled: !settings.internetEnabled })}
                  className={cn(
                    "w-12 h-6 rounded-full transition-all relative",
                    settings.internetEnabled ? "bg-accent" : "bg-muted-foreground/30"
                  )}
                >
                  <div
                    className={cn(
                      "absolute top-1 w-4 h-4 rounded-full bg-white transition-all",
                      settings.internetEnabled ? "left-7" : "left-1"
                    )}
                  />
                </button>
              </div>
            </div>

            <div className="cyber-card rounded-lg p-6">
              <h3 className="font-medium text-foreground mb-4">Data Management</h3>
              <div className="space-y-3">
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => {
                    const data = {
                      settings,
                      files: uploadedFiles,
                    };
                    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `vexai-backup-${new Date().toISOString().split('T')[0]}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export All Data
                </Button>
                <Button
                  variant="destructive"
                  className="w-full justify-start"
                  onClick={() => {
                    if (confirm('Are you sure you want to clear all data? This cannot be undone.')) {
                      localStorage.clear();
                      window.location.reload();
                    }
                  }}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Reset All Data
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
