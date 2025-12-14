import { ScrollText, Trash2, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface LogsSectionProps {
  logs: string[];
  onClearLogs: () => void;
}

export function LogsSection({ logs, onClearLogs }: LogsSectionProps) {
  const handleExportLogs = () => {
    const data = logs.join('\n');
    const blob = new Blob([data], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vexai-logs-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col p-6 overflow-hidden">
      <div className="max-w-4xl mx-auto w-full flex flex-col h-full">
        <div className="flex items-center justify-between mb-6 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center">
              <ScrollText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-2xl font-display font-bold text-foreground">Logs</h2>
              <p className="text-sm text-muted-foreground">{logs.length} entries</p>
            </div>
          </div>
          
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleExportLogs} disabled={logs.length === 0}>
              <Download className="h-4 w-4 mr-1" />
              Export
            </Button>
            <Button variant="destructive" size="sm" onClick={onClearLogs} disabled={logs.length === 0}>
              <Trash2 className="h-4 w-4 mr-1" />
              Clear
            </Button>
          </div>
        </div>

        <div className="flex-1 cyber-card rounded-lg overflow-hidden">
          {logs.length === 0 ? (
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <ScrollText className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <p className="text-muted-foreground">No logs recorded yet</p>
              </div>
            </div>
          ) : (
            <div className="h-full overflow-y-auto p-4 font-mono text-xs space-y-1 scanline">
              {logs.map((log, index) => (
                <div
                  key={index}
                  className="p-2 rounded bg-muted/20 hover:bg-muted/40 transition-colors text-muted-foreground hover:text-foreground"
                >
                  {log}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
