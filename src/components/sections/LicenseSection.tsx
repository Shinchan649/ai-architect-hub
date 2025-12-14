import { FileText } from 'lucide-react';
import { LicenseInfo } from '@/types/app';

interface LicenseSectionProps {
  license: LicenseInfo;
}

export function LicenseSection({ license }: LicenseSectionProps) {
  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      <div className="max-w-3xl mx-auto w-full">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-12 h-12 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center">
            <FileText className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-2xl font-display font-bold text-foreground">License</h2>
            <p className="text-sm text-muted-foreground">
              Version {license.version} • Last updated: {license.lastUpdated ? new Date(license.lastUpdated).toLocaleDateString() : 'Never'}
            </p>
          </div>
        </div>

        <div className="cyber-card rounded-lg p-6">
          {license.text ? (
            <pre className="whitespace-pre-wrap text-sm text-muted-foreground font-mono leading-relaxed">
              {license.text}
            </pre>
          ) : (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <p className="text-muted-foreground">
                No license text configured.
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                License can be edited in the Modification section.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
