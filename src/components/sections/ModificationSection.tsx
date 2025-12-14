import { useState } from 'react';
import { Shield, Lock, Key, FileText, Mail, KeyRound, MessageSquare, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { AppSettings, LicenseInfo } from '@/types/app';
import { cn } from '@/lib/utils';

interface ModificationSectionProps {
  isAuthenticated: boolean;
  onAuthenticate: (password: string) => boolean;
  onLogout: () => void;
  settings: AppSettings;
  license: LicenseInfo;
  onUpdateSettings: (settings: AppSettings) => void;
  onUpdateLicense: (license: LicenseInfo) => void;
}

type SubSection = 'menu' | 'name' | 'code' | 'license' | 'password' | 'recovery' | 'forgot';

export function ModificationSection({
  isAuthenticated,
  onAuthenticate,
  onLogout,
  settings,
  license,
  onUpdateSettings,
  onUpdateLicense,
}: ModificationSectionProps) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [subSection, setSubSection] = useState<SubSection>('menu');
  const [newAppName, setNewAppName] = useState(settings.appName);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [recoveryEmail, setRecoveryEmail] = useState(settings.recoveryEmail);
  const [licenseText, setLicenseText] = useState(license.text);
  const [codePrompt, setCodePrompt] = useState('');

  const handleLogin = () => {
    setError('');
    const success = onAuthenticate(password);
    if (!success) {
      setError('Invalid password');
    }
    setPassword('');
  };

  const handleChangeAppName = () => {
    onUpdateSettings({ ...settings, appName: newAppName });
    setSubSection('menu');
  };

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    onUpdateSettings({ ...settings, modificationPassword: newPassword });
    setNewPassword('');
    setConfirmPassword('');
    setSubSection('menu');
  };

  const handleSaveRecoveryEmail = () => {
    onUpdateSettings({ ...settings, recoveryEmail });
    setSubSection('menu');
  };

  const handleSaveLicense = () => {
    onUpdateLicense({ ...license, text: licenseText, lastUpdated: new Date() });
    setSubSection('menu');
  };

  // Login Screen
  if (!isAuthenticated) {
    const isFirstTime = !settings.modificationPassword;
    
    return (
      <div className="h-full flex items-center justify-center p-6">
        <div className="w-full max-w-md cyber-card rounded-xl p-8 text-center animate-slide-up">
          <div className="w-16 h-16 rounded-2xl bg-primary/20 border border-primary/50 flex items-center justify-center mx-auto mb-6 animate-pulse-glow">
            <Lock className="h-8 w-8 text-primary" />
          </div>
          
          <h2 className="text-2xl font-display font-bold text-foreground mb-2">
            {isFirstTime ? 'Set Password' : 'Modification Access'}
          </h2>
          <p className="text-muted-foreground text-sm mb-6">
            {isFirstTime 
              ? 'Create a password to protect the Modification section'
              : 'Enter your password to access protected settings'}
          </p>

          <div className="space-y-4">
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
              placeholder={isFirstTime ? 'Create password...' : 'Enter password...'}
              className="text-center"
            />
            
            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}

            <Button
              variant="cyber"
              className="w-full"
              onClick={handleLogin}
              disabled={!password}
            >
              {isFirstTime ? 'Set Password' : 'Unlock'}
            </Button>

            {!isFirstTime && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSubSection('forgot')}
                className="text-muted-foreground"
              >
                Forgot Password?
              </Button>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Modification Menu
  if (subSection === 'menu') {
    const menuItems = [
      { id: 'name' as SubSection, label: 'Change App Name', icon: <Key className="h-4 w-4" />, desc: 'Modify the application name' },
      { id: 'code' as SubSection, label: 'Modify App Code', icon: <MessageSquare className="h-4 w-4" />, desc: 'Chat with Internal Technician AI' },
      { id: 'license' as SubSection, label: 'License Management', icon: <FileText className="h-4 w-4" />, desc: 'Edit license text' },
      { id: 'password' as SubSection, label: 'Change Password', icon: <Lock className="h-4 w-4" />, desc: 'Update modification password' },
      { id: 'recovery' as SubSection, label: 'Recovery Email', icon: <Mail className="h-4 w-4" />, desc: 'Set password recovery email' },
    ];

    return (
      <div className="h-full flex flex-col p-6 overflow-y-auto">
        <div className="max-w-2xl mx-auto w-full">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl font-display font-bold text-foreground">Modification</h2>
              <p className="text-muted-foreground text-sm">Protected app configuration</p>
            </div>
            <Button variant="outline" size="sm" onClick={onLogout}>
              <Lock className="h-4 w-4 mr-1" />
              Lock
            </Button>
          </div>

          <div className="grid gap-3">
            {menuItems.map((item) => (
              <button
                key={item.id}
                onClick={() => setSubSection(item.id)}
                className="cyber-card rounded-lg p-4 text-left hover:border-primary/50 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center group-hover:border-primary/50 transition-colors">
                    {item.icon}
                  </div>
                  <div>
                    <h3 className="font-medium text-foreground">{item.label}</h3>
                    <p className="text-xs text-muted-foreground">{item.desc}</p>
                  </div>
                </div>
              </button>
            ))}
          </div>

          <div className="mt-6 p-4 rounded-lg border border-destructive/30 bg-destructive/5">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-foreground font-medium">Security Warning</p>
                <p className="text-xs text-muted-foreground">
                  All changes in this section are protected and logged. Ensure you remember your password.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Sub-sections
  const renderSubSection = () => {
    switch (subSection) {
      case 'name':
        return (
          <div className="space-y-4">
            <h3 className="text-xl font-display font-bold text-foreground">Change App Name</h3>
            <Input
              value={newAppName}
              onChange={(e) => setNewAppName(e.target.value)}
              placeholder="App name..."
            />
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setSubSection('menu')} className="flex-1">
                Cancel
              </Button>
              <Button variant="cyber" onClick={handleChangeAppName} className="flex-1" disabled={!newAppName}>
                Save Name
              </Button>
            </div>
          </div>
        );

      case 'code':
        return (
          <div className="space-y-4">
            <h3 className="text-xl font-display font-bold text-foreground">Internal Technician AI</h3>
            <p className="text-sm text-muted-foreground">
              Describe what modifications you want to make to the app. The Internal AI will process your request.
            </p>
            <textarea
              value={codePrompt}
              onChange={(e) => setCodePrompt(e.target.value)}
              placeholder="Describe the changes you want to make..."
              className="w-full h-40 rounded-lg border border-primary/30 bg-muted/30 p-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50 resize-none font-mono text-sm"
            />
            <div className="p-3 rounded-lg bg-accent/10 border border-accent/30">
              <p className="text-xs text-accent">
                Note: Code modification requires backend integration. Currently in demo mode.
              </p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setSubSection('menu')} className="flex-1">
                Back
              </Button>
              <Button variant="cyber" className="flex-1" disabled={!codePrompt}>
                Send to AI
              </Button>
            </div>
          </div>
        );

      case 'license':
        return (
          <div className="space-y-4">
            <h3 className="text-xl font-display font-bold text-foreground">License Management</h3>
            <textarea
              value={licenseText}
              onChange={(e) => setLicenseText(e.target.value)}
              placeholder="Enter your license text..."
              className="w-full h-60 rounded-lg border border-primary/30 bg-muted/30 p-3 text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary focus:ring-2 focus:ring-primary/50 resize-none font-mono text-sm"
            />
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setSubSection('menu')} className="flex-1">
                Cancel
              </Button>
              <Button variant="cyber" onClick={handleSaveLicense} className="flex-1">
                Save License
              </Button>
            </div>
          </div>
        );

      case 'password':
        return (
          <div className="space-y-4">
            <h3 className="text-xl font-display font-bold text-foreground">Change Password</h3>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="New password..."
            />
            <Input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm password..."
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => { setSubSection('menu'); setError(''); }} className="flex-1">
                Cancel
              </Button>
              <Button variant="cyber" onClick={handleChangePassword} className="flex-1" disabled={!newPassword || !confirmPassword}>
                Update Password
              </Button>
            </div>
          </div>
        );

      case 'recovery':
        return (
          <div className="space-y-4">
            <h3 className="text-xl font-display font-bold text-foreground">Recovery Email</h3>
            <p className="text-sm text-muted-foreground">
              Set an email address for password recovery. An OTP will be sent to this email if you forget your password.
            </p>
            <Input
              type="email"
              value={recoveryEmail}
              onChange={(e) => setRecoveryEmail(e.target.value)}
              placeholder="email@example.com"
            />
            <div className="flex gap-2">
              <Button variant="outline" onClick={() => setSubSection('menu')} className="flex-1">
                Cancel
              </Button>
              <Button variant="cyber" onClick={handleSaveRecoveryEmail} className="flex-1" disabled={!recoveryEmail}>
                Save Email
              </Button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto">
      <div className="max-w-md mx-auto w-full cyber-card rounded-xl p-6">
        {(subSection === 'name' || subSection === 'code' || subSection === 'license' || subSection === 'password' || subSection === 'recovery') && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSubSection('menu')}
            className="mb-4"
          >
            ← Back to Menu
          </Button>
        )}
        {renderSubSection()}
      </div>
    </div>
  );
}
