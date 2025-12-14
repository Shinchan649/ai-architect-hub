import { Shield, Terminal, Lock, Wifi, Upload, Key, AlertTriangle } from 'lucide-react';

interface AboutSectionProps {
  appName: string;
}

export function AboutSection({ appName }: AboutSectionProps) {
  const features = [
    {
      icon: <Terminal className="h-5 w-5" />,
      title: 'Interaction Console',
      desc: 'AI-powered command interpretation with real-time execution logs',
    },
    {
      icon: <Lock className="h-5 w-5" />,
      title: 'Password Protected',
      desc: 'Modification section secured with password and recovery options',
    },
    {
      icon: <Key className="h-5 w-5" />,
      title: 'Multi-API Support',
      desc: 'Connect up to 4 external AI APIs with easy switching',
    },
    {
      icon: <Upload className="h-5 w-5" />,
      title: 'Custom Tool Loading',
      desc: 'Upload scripts, wordlists, and config files for AI use',
    },
    {
      icon: <Wifi className="h-5 w-5" />,
      title: 'Internet Toggle',
      desc: 'Control network access for online/offline operation',
    },
    {
      icon: <AlertTriangle className="h-5 w-5" />,
      title: 'Explicit Confirmation',
      desc: 'Every execution requires user approval before proceeding',
    },
  ];

  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto matrix-bg">
      <div className="max-w-2xl mx-auto w-full">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/10 border border-primary/30 flex items-center justify-center mx-auto mb-6 animate-float">
            <Shield className="h-12 w-12 text-primary" />
          </div>
          <h1 className="text-3xl font-display font-bold text-foreground mb-2">
            {appName}
          </h1>
          <p className="text-muted-foreground">
            AI-Driven Cybersecurity Testing Platform
          </p>
          <p className="text-sm text-primary mt-2">Version 1.0.0</p>
        </div>

        {/* Description */}
        <div className="cyber-card rounded-lg p-6 mb-8">
          <h2 className="font-display font-bold text-foreground mb-3">About</h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            {appName} is a fully automated AI-driven cybersecurity testing and simulation platform 
            designed strictly for private, controlled lab environments. Users provide natural-language 
            prompts, the AI interprets intent, determines required tools, and executes workflows with 
            full transparency and user confirmation.
          </p>
        </div>

        {/* Features */}
        <div className="mb-8">
          <h2 className="font-display font-bold text-foreground mb-4">Features</h2>
          <div className="grid gap-3">
            {features.map((feature, index) => (
              <div key={index} className="cyber-card rounded-lg p-4 flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center text-primary shrink-0">
                  {feature.icon}
                </div>
                <div>
                  <h3 className="font-medium text-foreground">{feature.title}</h3>
                  <p className="text-xs text-muted-foreground">{feature.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Safety Notice */}
        <div className="p-4 rounded-lg border border-primary/20 bg-primary/5 mb-8">
          <div className="flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 text-primary shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-foreground">Lab Environment Only</p>
              <p className="text-xs text-muted-foreground">
                This platform is intended for controlled testing environments only. 
                All operations require explicit user confirmation. No background or 
                silent execution is permitted.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center py-6 border-t border-primary/20">
          <p className="text-sm text-muted-foreground">
            Created by <span className="text-primary font-medium">0.x" vexX</span>
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            © 2024 All Rights Reserved
          </p>
        </div>
      </div>
    </div>
  );
}
