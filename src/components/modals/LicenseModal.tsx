import { useState } from 'react';
import { X, FileText, Edit2, Save } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { LicenseInfo } from '@/types/chat';

interface LicenseModalProps {
  isOpen: boolean;
  onClose: () => void;
  license: LicenseInfo;
  onSaveLicense: (license: LicenseInfo) => void;
  isAdmin?: boolean;
}

const DEFAULT_LICENSE = `MIT License

Copyright (c) 2024 0x.AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

export function LicenseModal({
  isOpen,
  onClose,
  license,
  onSaveLicense,
  isAdmin = false,
}: LicenseModalProps) {
  const [isEditing, setIsEditing] = useState(false);
  const [editedText, setEditedText] = useState(license.text || DEFAULT_LICENSE);

  if (!isOpen) return null;

  const handleSave = () => {
    onSaveLicense({
      ...license,
      text: editedText,
      lastUpdated: new Date(),
    });
    setIsEditing(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-background/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-3xl cyber-card rounded-xl border border-primary/30 animate-slide-up max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-primary/20 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center">
              <FileText className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-display font-bold text-foreground">License</h2>
              <p className="text-xs text-muted-foreground">
                Version {license.version || '1.0.0'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isAdmin && !isEditing && (
              <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
                <Edit2 className="h-4 w-4 mr-1" />
                Edit
              </Button>
            )}
            <Button variant="ghost" size="icon" onClick={onClose}>
              <X className="h-5 w-5" />
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {isEditing ? (
            <textarea
              value={editedText}
              onChange={(e) => setEditedText(e.target.value)}
              className="w-full h-96 p-4 rounded-lg border border-primary/30 bg-muted/30 text-foreground font-mono text-sm resize-none focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50"
            />
          ) : (
            <pre className="whitespace-pre-wrap text-sm text-muted-foreground font-mono p-4 rounded-lg bg-muted/30 border border-primary/10">
              {license.text || DEFAULT_LICENSE}
            </pre>
          )}
        </div>

        {/* Footer */}
        {isEditing && (
          <div className="flex justify-end gap-3 p-6 border-t border-primary/20 shrink-0">
            <Button variant="outline" onClick={() => setIsEditing(false)}>
              Cancel
            </Button>
            <Button variant="cyber" onClick={handleSave}>
              <Save className="h-4 w-4 mr-1" />
              Save License
            </Button>
          </div>
        )}

        {!isEditing && (
          <div className="p-4 border-t border-primary/20 text-center shrink-0">
            <p className="text-xs text-muted-foreground">
              Last updated: {license.lastUpdated ? new Date(license.lastUpdated).toLocaleDateString() : 'Never'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
