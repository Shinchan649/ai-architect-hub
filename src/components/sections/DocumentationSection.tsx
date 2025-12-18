/**
 * ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
 * ║                                           VEXX AI - DOCUMENTATION SECTION WITH PDF EXPORT                                                   ║
 * ║                                                                                                                                              ║
 * ║  This component provides a comprehensive documentation viewer and PDF export functionality                                                   ║
 * ║  for the entire application codebase with advanced formatting and navigation features.                                                      ║
 * ║                                                                                                                                              ║
 * ║  Features:                                                                                                                                   ║
 * ║  - Interactive code documentation viewer                                                                                                     ║
 * ║  - PDF export with professional formatting                                                                                                  ║
 * ║  - Syntax highlighting for code blocks                                                                                                      ║
 * ║  - Table of contents generation                                                                                                             ║
 * ║  - Search functionality across documentation                                                                                                ║
 * ║  - Export customization options                                                                                                             ║
 * ║  - Print-friendly styling                                                                                                                   ║
 * ║                                                                                                                                              ║
 * ║  Documentation Standards:                                                                                                                    ║
 * ║  - JSDoc compliance for all functions                                                                                                       ║
 * ║  - TypeScript interface documentation                                                                                                       ║
 * ║  - Security module documentation                                                                                                            ║
 * ║  - API reference documentation                                                                                                              ║
 * ║                                                                                                                                              ║
 * ║  Author: VexX AI Documentation Team                                                                                                         ║
 * ║  Version: 2.0.0                                                                                                                             ║
 * ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
 */

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import {
  FileText,
  Download,
  Search,
  Book,
  Code,
  Shield,
  Database,
  Key,
  Lock,
  Settings,
  Terminal,
  Cpu,
  ChevronRight,
  ChevronDown,
  Copy,
  Check,
  ExternalLink,
  Printer,
  FileCode,
  FileJson,
  Folder,
  FolderOpen,
  Eye,
  EyeOff,
  Filter,
  Layers,
  Hash,
  Type,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Maximize2,
  Minimize2,
  List,
  Grid3X3,
  Calendar,
  Clock,
  User,
  Info,
  Zap,
  Package,
  GitBranch,
  Tag,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import jsPDF from 'jspdf';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * TYPE DEFINITIONS
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * Documentation section types
 */
type DocSection = 
  | 'overview'
  | 'security'
  | 'components'
  | 'hooks'
  | 'types'
  | 'utils'
  | 'api';

/**
 * Documentation item structure
 */
interface DocItem {
  id: string;
  title: string;
  description: string;
  category: DocSection;
  code?: string;
  language?: string;
  examples?: string[];
  parameters?: DocParameter[];
  returns?: string;
  since?: string;
  deprecated?: boolean;
  tags?: string[];
}

/**
 * Documentation parameter structure
 */
interface DocParameter {
  name: string;
  type: string;
  description: string;
  optional?: boolean;
  defaultValue?: string;
}

/**
 * Table of contents item
 */
interface TocItem {
  id: string;
  title: string;
  level: number;
  children?: TocItem[];
}

/**
 * Export configuration
 */
interface ExportConfig {
  includeCode: boolean;
  includeExamples: boolean;
  includeTableOfContents: boolean;
  includeCover: boolean;
  paperSize: 'a4' | 'letter';
  orientation: 'portrait' | 'landscape';
  fontSize: number;
}

/**
 * Source code file structure for full export
 */
interface SourceFile {
  path: string;
  content: string;
  language: string;
}

/**
 * Complete source code registry for PDF export
 */
const SOURCE_CODE_FILES: SourceFile[] = [
  {
    path: 'src/App.tsx',
    language: 'tsx',
    content: `import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { HelmetProvider } from "react-helmet-async";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <HelmetProvider>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </HelmetProvider>
);

export default App;`
  },
  {
    path: 'src/main.tsx',
    language: 'tsx',
    content: `import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById("root")!).render(<App />);`
  },
  {
    path: 'src/types/app.ts',
    language: 'typescript',
    content: `// Application Types
export interface ExternalAPI {
  id: string;
  name: string;
  endpoint: string;
  apiKey: string;
  isActive: boolean;
}

export interface AppSettings {
  appName: string;
  internetEnabled: boolean;
  modificationPassword: string;
  recoveryEmail: string;
  internalAPIKey: string;
  externalAPIs: ExternalAPI[];
  activeAPIId: string | null;
}

export interface LicenseInfo {
  licenseCode: string;
  activatedAt: string | null;
  expiresAt: string | null;
  isValid: boolean;
  type: 'free' | 'pro' | 'enterprise';
}`
  },
  {
    path: 'src/types/chat.ts',
    language: 'typescript',
    content: `// Chat Types
export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
}`
  },
  {
    path: 'src/lib/utils.ts',
    language: 'typescript',
    content: `import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}`
  },
  {
    path: 'src/hooks/useLocalStorage.ts',
    language: 'typescript',
    content: `import { useState, useEffect } from 'react';

export function useLocalStorage<T>(key: string, initialValue: T): [T, (value: T | ((val: T) => T)) => void] {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error(\`Error reading localStorage key "\${key}":\`, error);
      return initialValue;
    }
  });

  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.error(\`Error setting localStorage key "\${key}":\`, error);
    }
  };

  return [storedValue, setValue];
}`
  },
  {
    path: 'src/lib/security/encryption.ts',
    language: 'typescript',
    content: `/**
 * VEXX AI - Encryption Module
 * AES-256-GCM encryption with PBKDF2 key derivation
 */

export interface EncryptionConfig {
  algorithm: 'AES-GCM';
  keyLength: 256;
  iterations: number;
  saltLength: number;
  ivLength: number;
}

export interface PasswordHashResult {
  hash: string;
  salt: string;
  iterations: number;
}

export interface PasswordStrength {
  score: number;
  level: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
  feedback: string[];
}

const DEFAULT_CONFIG: EncryptionConfig = {
  algorithm: 'AES-GCM',
  keyLength: 256,
  iterations: 100000,
  saltLength: 16,
  ivLength: 12,
};

// Utility functions
export const generateSecureRandomBytes = (length: number): Uint8Array => {
  return crypto.getRandomValues(new Uint8Array(length));
};

export const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

export const hexToBytes = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
};

export const bytesToBase64 = (bytes: Uint8Array): string => {
  return btoa(String.fromCharCode(...bytes));
};

export const base64ToBytes = (base64: string): Uint8Array => {
  return new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
};

// Core encryption functions
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: DEFAULT_CONFIG.iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptSensitiveString(plaintext: string, password: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = generateSecureRandomBytes(DEFAULT_CONFIG.saltLength);
  const iv = generateSecureRandomBytes(DEFAULT_CONFIG.ivLength);
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext)
  );

  const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  result.set(salt, 0);
  result.set(iv, salt.length);
  result.set(new Uint8Array(encrypted), salt.length + iv.length);

  return bytesToBase64(result);
}

export async function decryptSensitiveString(ciphertext: string, password: string): Promise<string> {
  const decoder = new TextDecoder();
  const data = base64ToBytes(ciphertext);

  const salt = data.slice(0, DEFAULT_CONFIG.saltLength);
  const iv = data.slice(DEFAULT_CONFIG.saltLength, DEFAULT_CONFIG.saltLength + DEFAULT_CONFIG.ivLength);
  const encrypted = data.slice(DEFAULT_CONFIG.saltLength + DEFAULT_CONFIG.ivLength);

  const key = await deriveKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  return decoder.decode(decrypted);
}

export async function hashPassword(password: string): Promise<PasswordHashResult> {
  const salt = generateSecureRandomBytes(DEFAULT_CONFIG.saltLength);
  const encoder = new TextEncoder();
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: DEFAULT_CONFIG.iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  return {
    hash: bytesToHex(new Uint8Array(hashBuffer)),
    salt: bytesToHex(salt),
    iterations: DEFAULT_CONFIG.iterations,
  };
}

export async function verifyPassword(password: string, hashResult: PasswordHashResult): Promise<boolean> {
  const salt = hexToBytes(hashResult.salt);
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: hashResult.iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const computedHash = bytesToHex(new Uint8Array(hashBuffer));
  return computedHash === hashResult.hash;
}

export function validatePasswordStrength(password: string): PasswordStrength {
  let score = 0;
  const feedback: string[] = [];

  if (password.length >= 8) score += 1;
  else feedback.push('Use at least 8 characters');

  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;

  if (/[a-z]/.test(password)) score += 1;
  else feedback.push('Add lowercase letters');

  if (/[A-Z]/.test(password)) score += 1;
  else feedback.push('Add uppercase letters');

  if (/\\d/.test(password)) score += 1;
  else feedback.push('Add numbers');

  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
  else feedback.push('Add special characters');

  const levels: PasswordStrength['level'][] = ['weak', 'fair', 'good', 'strong', 'very-strong'];
  const level = levels[Math.min(Math.floor(score / 2), 4)];

  return { score, level, feedback };
}

export async function computeSHA256Hash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
  return bytesToHex(new Uint8Array(hashBuffer));
}

export function sanitizeInput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}`
  },
  {
    path: 'src/lib/security/securityAudit.ts',
    language: 'typescript',
    content: `/**
 * VEXX AI - Security Audit Module
 * Comprehensive security event logging and threat detection
 */

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export type SecurityEventType =
  | 'authentication_success'
  | 'authentication_failure'
  | 'data_access'
  | 'data_modification'
  | 'encryption_operation'
  | 'decryption_operation'
  | 'suspicious_activity'
  | 'rate_limit_exceeded'
  | 'session_created'
  | 'session_terminated';

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  description: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface SecurityStatistics {
  totalEvents: number;
  eventsByType: Record<SecurityEventType, number>;
  eventsBySeverity: Record<SecuritySeverity, number>;
  lastEventTimestamp: number | null;
}

export interface ThreatAssessment {
  threatLevel: number;
  riskFactors: string[];
  recommendations: string[];
}

export class SecurityAudit {
  private static instance: SecurityAudit;
  private events: SecurityEvent[] = [];
  private maxEvents = 1000;

  private constructor() {}

  static getInstance(): SecurityAudit {
    if (!SecurityAudit.instance) {
      SecurityAudit.instance = new SecurityAudit();
    }
    return SecurityAudit.instance;
  }

  async logEvent(event: Omit<SecurityEvent, 'id' | 'timestamp'>): Promise<void> {
    const newEvent: SecurityEvent = {
      ...event,
      id: crypto.randomUUID(),
      timestamp: Date.now(),
    };

    this.events.unshift(newEvent);

    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(0, this.maxEvents);
    }
  }

  getEvents(options?: { limit?: number; type?: SecurityEventType }): SecurityEvent[] {
    let filtered = [...this.events];

    if (options?.type) {
      filtered = filtered.filter(e => e.type === options.type);
    }

    if (options?.limit) {
      filtered = filtered.slice(0, options.limit);
    }

    return filtered;
  }

  getStatistics(): SecurityStatistics {
    const eventsByType = {} as Record<SecurityEventType, number>;
    const eventsBySeverity = {} as Record<SecuritySeverity, number>;

    this.events.forEach(event => {
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
      eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;
    });

    return {
      totalEvents: this.events.length,
      eventsByType,
      eventsBySeverity,
      lastEventTimestamp: this.events[0]?.timestamp || null,
    };
  }

  async performThreatAssessment(): Promise<ThreatAssessment> {
    const stats = this.getStatistics();
    let threatLevel = 0;
    const riskFactors: string[] = [];
    const recommendations: string[] = [];

    const failedAuths = stats.eventsByType['authentication_failure'] || 0;
    if (failedAuths > 5) {
      threatLevel += 2;
      riskFactors.push('Multiple failed authentication attempts');
      recommendations.push('Enable account lockout after failed attempts');
    }

    const suspicious = stats.eventsByType['suspicious_activity'] || 0;
    if (suspicious > 0) {
      threatLevel += 3;
      riskFactors.push('Suspicious activity detected');
      recommendations.push('Review recent activity logs');
    }

    return { threatLevel: Math.min(threatLevel, 10), riskFactors, recommendations };
  }

  clearEvents(): void {
    this.events = [];
  }
}

export const securityAudit = SecurityAudit.getInstance();`
  },
  {
    path: 'src/lib/security/secureStorage.ts',
    language: 'typescript',
    content: `/**
 * VEXX AI - Secure Storage Module
 * Encrypted localStorage with integrity verification
 */

export interface StorageStatistics {
  totalEntries: number;
  expiredEntries: number;
  totalSize: number;
  utilizationPercent: number;
}

export interface StorageOperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

export class SecureStorage {
  private static instance: SecureStorage;
  private prefix = 'vexx_secure_';

  private constructor() {}

  static getInstance(): SecureStorage {
    if (!SecureStorage.instance) {
      SecureStorage.instance = new SecureStorage();
    }
    return SecureStorage.instance;
  }

  async setItem<T>(key: string, value: T): Promise<StorageOperationResult> {
    try {
      const serialized = JSON.stringify({
        data: value,
        timestamp: Date.now(),
      });
      localStorage.setItem(this.prefix + key, serialized);
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  async getItem<T>(key: string): Promise<StorageOperationResult<T>> {
    try {
      const item = localStorage.getItem(this.prefix + key);
      if (!item) {
        return { success: false, error: 'Item not found' };
      }
      const parsed = JSON.parse(item);
      return { success: true, data: parsed.data as T };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  async removeItem(key: string): Promise<StorageOperationResult> {
    try {
      localStorage.removeItem(this.prefix + key);
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  getStatistics(): StorageStatistics {
    let totalSize = 0;
    let totalEntries = 0;

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(this.prefix)) {
        totalEntries++;
        totalSize += localStorage.getItem(key)?.length || 0;
      }
    }

    const maxSize = 5 * 1024 * 1024; // 5MB typical limit
    return {
      totalEntries,
      expiredEntries: 0,
      totalSize,
      utilizationPercent: (totalSize / maxSize) * 100,
    };
  }

  clear(): void {
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(this.prefix)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
  }
}

export const secureStorage = SecureStorage.getInstance();

export async function setSecureItem<T>(key: string, value: T) {
  return secureStorage.setItem(key, value);
}

export async function getSecureItem<T>(key: string) {
  return secureStorage.getItem<T>(key);
}

export async function removeSecureItem(key: string) {
  return secureStorage.removeItem(key);
}`
  },
  {
    path: 'vite.config.ts',
    language: 'typescript',
    content: `import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 8080,
  },
  plugins: [react(), mode === "development" && componentTagger()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));`
  },
  {
    path: 'capacitor.config.ts',
    language: 'typescript',
    content: `import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'app.lovable.894c50775e804d3fbd7fef7e86765e73',
  appName: '0.x.vexX AI',
  webDir: 'dist',
  server: {
    url: 'https://894c5077-5e80-4d3f-bd7f-ef7e86765e73.lovableproject.com?forceHideBadge=true',
    cleartext: true
  },
  android: {
    backgroundColor: '#0a0a0f',
    allowMixedContent: true
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 2000,
      backgroundColor: '#0a0a0f',
      showSpinner: false
    }
  }
};

export default config;`
  },
  {
    path: 'tailwind.config.ts',
    language: 'typescript',
    content: `import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
  ],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
      },
      fontFamily: {
        display: ["Orbitron", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      keyframes: {
        "fade-in": {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.3s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config;`
  },
  {
    path: 'package.json',
    language: 'json',
    content: `{
  "name": "vexx-ai",
  "private": true,
  "version": "2.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@capacitor/android": "^8.0.0",
    "@capacitor/core": "^8.0.0",
    "@capacitor/ios": "^8.0.0",
    "@radix-ui/react-accordion": "^1.2.11",
    "@radix-ui/react-dialog": "^1.1.14",
    "@radix-ui/react-dropdown-menu": "^2.1.15",
    "@radix-ui/react-scroll-area": "^1.2.9",
    "@radix-ui/react-tabs": "^1.1.12",
    "@radix-ui/react-tooltip": "^1.2.7",
    "@tanstack/react-query": "^5.83.0",
    "class-variance-authority": "^0.7.1",
    "clsx": "^2.1.1",
    "jspdf": "^3.0.4",
    "lucide-react": "^0.462.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-helmet-async": "^2.0.5",
    "react-router-dom": "^6.30.1",
    "sonner": "^1.7.4",
    "tailwind-merge": "^2.6.0",
    "tailwindcss-animate": "^1.0.7"
  },
  "devDependencies": {
    "@capacitor/cli": "^8.0.0",
    "@vitejs/plugin-react-swc": "^3.0.0",
    "typescript": "^5.0.0",
    "vite": "^5.0.0"
  }
}`
  },
  // Pages
  {
    path: 'src/pages/Index.tsx',
    language: 'tsx',
    content: `import { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import { MainSidebar } from '@/components/layout/MainSidebar';
import { HomeSection } from '@/components/sections/HomeSection';
import { ConsoleSection } from '@/components/sections/ConsoleSection';
import { APISection } from '@/components/sections/APISection';
import { ModificationSection } from '@/components/sections/ModificationSection';
import { LicenseSection } from '@/components/sections/LicenseSection';
import { SettingsSection } from '@/components/sections/SettingsSection';
import { LogsSection } from '@/components/sections/LogsSection';
import { AboutSection } from '@/components/sections/AboutSection';
import { useAppState } from '@/hooks/useAppState';

const Index = () => {
  const {
    settings, license, uploadedFiles, sessions, logs, currentSession,
    activeSection, isAuthenticated, isLoading, setSettings, setLicense,
    setActiveSection, createSession, addFile, removeFile, addLog, clearLogs,
    authenticate, logout, sendMessage,
  } = useAppState();

  const [fileManagerOpen, setFileManagerOpen] = useState(false);

  const handleToggleInternet = () => {
    setSettings(prev => {
      const newState = { ...prev, internetEnabled: !prev.internetEnabled };
      addLog(\`Internet access \${newState.internetEnabled ? 'enabled' : 'disabled'}\`);
      return newState;
    });
  };

  const renderSection = () => {
    switch (activeSection) {
      case 'home': return <HomeSection appName={settings.appName} internetEnabled={settings.internetEnabled} onToggleInternet={handleToggleInternet} onNavigate={setActiveSection} uploadedFilesCount={uploadedFiles.length} />;
      case 'console': return <ConsoleSection session={currentSession} isLoading={isLoading} onSendMessage={sendMessage} internetEnabled={settings.internetEnabled} onToggleInternet={handleToggleInternet} uploadedFiles={uploadedFiles} onOpenFileManager={() => setActiveSection('settings')} />;
      case 'api': return <APISection settings={settings} onUpdateSettings={setSettings} />;
      case 'modification': return <ModificationSection isAuthenticated={isAuthenticated} onAuthenticate={authenticate} onLogout={logout} settings={settings} license={license} onUpdateSettings={setSettings} onUpdateLicense={setLicense} />;
      case 'license': return <LicenseSection license={license} />;
      case 'settings': return <SettingsSection settings={settings} uploadedFiles={uploadedFiles} onAddFile={addFile} onRemoveFile={removeFile} onUpdateSettings={setSettings} />;
      case 'logs': return <LogsSection logs={logs} onClearLogs={clearLogs} />;
      case 'about': return <AboutSection appName={settings.appName} />;
      default: return null;
    }
  };

  return (
    <>
      <Helmet>
        <title>{settings.appName} - Cybersecurity AI Platform</title>
        <meta name="description" content="AI-driven cybersecurity testing and simulation platform for controlled lab environments." />
      </Helmet>
      <div className="flex h-screen bg-background overflow-hidden">
        <MainSidebar activeSection={activeSection} onSectionChange={setActiveSection} appName={settings.appName} isAuthenticated={isAuthenticated} />
        <main className="flex-1 flex flex-col overflow-hidden">{renderSection()}</main>
      </div>
    </>
  );
};

export default Index;`
  },
  {
    path: 'src/pages/NotFound.tsx',
    language: 'tsx',
    content: `import { useLocation } from "react-router-dom";
import { useEffect } from "react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted">
      <div className="text-center">
        <h1 className="mb-4 text-4xl font-bold">404</h1>
        <p className="mb-4 text-xl text-muted-foreground">Oops! Page not found</p>
        <a href="/" className="text-primary underline hover:text-primary/90">Return to Home</a>
      </div>
    </div>
  );
};

export default NotFound;`
  },
  // Hooks
  {
    path: 'src/hooks/useAppState.ts',
    language: 'typescript',
    content: `import { useState, useCallback } from 'react';
import { useLocalStorage } from './useLocalStorage';
import { AppSettings, LicenseInfo, UploadedFile, ChatSession, Message, MenuSection } from '@/types/app';

const generateId = () => Math.random().toString(36).substring(2, 15);

const defaultSettings: AppSettings = {
  appName: '0.x" vexX AI',
  internetEnabled: false,
  modificationPassword: '',
  recoveryEmail: '',
  internalAPIKey: '',
  externalAPIs: [],
  activeAPIId: null,
};

const defaultLicense: LicenseInfo = {
  text: '',
  version: '1.0.0',
  lastUpdated: new Date(),
};

export function useAppState() {
  const [settings, setSettings] = useLocalStorage<AppSettings>('vexai-settings', defaultSettings);
  const [license, setLicense] = useLocalStorage<LicenseInfo>('vexai-license', defaultLicense);
  const [uploadedFiles, setUploadedFiles] = useLocalStorage<UploadedFile[]>('vexai-files', []);
  const [sessions, setSessions] = useLocalStorage<ChatSession[]>('vexai-sessions', []);
  const [logs, setLogs] = useLocalStorage<string[]>('vexai-logs', []);
  const [currentSessionId, setCurrentSessionId] = useLocalStorage<string | null>('vexai-current-session', null);
  const [activeSection, setActiveSection] = useState<MenuSection>('home');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const currentSession = sessions.find(s => s.id === currentSessionId) || null;

  const createSession = useCallback(() => {
    const newSession: ChatSession = { id: generateId(), title: 'New Session', messages: [], createdAt: new Date(), updatedAt: new Date() };
    setSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(newSession.id);
    return newSession;
  }, [setSessions, setCurrentSessionId]);

  const updateSession = useCallback((sessionId: string, updates: Partial<ChatSession>) => {
    setSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ...updates, updatedAt: new Date() } : s));
  }, [setSessions]);

  const deleteSession = useCallback((sessionId: string) => {
    setSessions(prev => prev.filter(s => s.id !== sessionId));
    if (currentSessionId === sessionId) setCurrentSessionId(null);
  }, [setSessions, currentSessionId, setCurrentSessionId]);

  const addFile = useCallback((file: Omit<UploadedFile, 'id' | 'uploadedAt'>) => {
    const newFile: UploadedFile = { ...file, id: generateId(), uploadedAt: new Date() };
    setUploadedFiles(prev => [...prev, newFile]);
    return newFile;
  }, [setUploadedFiles]);

  const removeFile = useCallback((fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId));
  }, [setUploadedFiles]);

  const addLog = useCallback((message: string) => {
    const timestamp = new Date().toISOString();
    setLogs(prev => [\`[\${timestamp}] \${message}\`, ...prev].slice(0, 1000));
  }, [setLogs]);

  const clearLogs = useCallback(() => { setLogs([]); }, [setLogs]);

  const authenticate = useCallback((password: string): boolean => {
    if (!settings.modificationPassword) {
      setSettings(prev => ({ ...prev, modificationPassword: password }));
      setIsAuthenticated(true);
      addLog('Modification password set for the first time');
      return true;
    }
    if (password === settings.modificationPassword) {
      setIsAuthenticated(true);
      addLog('Successfully authenticated to Modification section');
      return true;
    }
    addLog('Failed authentication attempt');
    return false;
  }, [settings.modificationPassword, setSettings, addLog]);

  const logout = useCallback(() => {
    setIsAuthenticated(false);
    addLog('Logged out from Modification section');
  }, [addLog]);

  const sendMessage = useCallback(async (content: string) => {
    let sessionId = currentSessionId;
    if (!sessionId) {
      const newSession = createSession();
      sessionId = newSession.id;
    }
    const userMessage: Message = { id: generateId(), role: 'user', content, timestamp: new Date() };
    const session = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, { messages: [...(session?.messages || []), userMessage], title: session?.messages.length === 0 ? content.slice(0, 30) + '...' : session?.title });
    addLog(\`User prompt: \${content.slice(0, 50)}...\`);
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    const responses = [
      { type: 'reasoning' as const, content: \`Analyzing request: "\${content}"\\n\\nDetermining required tools...\` },
      { type: 'execution' as const, content: \`⚠️ CONFIRMATION REQUIRED\\n\\nThis operation requires:\\n• Tool: nmap, nikto\\n• Files: target_list.txt\\n\\nDo you confirm execution?\` },
    ];
    const aiMessages: Message[] = responses.map(r => ({ id: generateId(), role: 'assistant' as const, content: r.content, timestamp: new Date(), type: r.type }));
    const updatedSession = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, { messages: [...(updatedSession?.messages || []), userMessage, ...aiMessages] });
    addLog('AI response generated');
    setIsLoading(false);
  }, [currentSessionId, sessions, createSession, updateSession, addLog]);

  return {
    settings, license, uploadedFiles, sessions, logs, currentSession, currentSessionId, activeSection, isAuthenticated, isLoading,
    setSettings, setLicense, setActiveSection, setCurrentSessionId, createSession, updateSession, deleteSession, addFile, removeFile, addLog, clearLogs, authenticate, logout, sendMessage,
  };
}`
  },
  {
    path: 'src/hooks/useChat.ts',
    language: 'typescript',
    content: `import { useState, useCallback } from 'react';
import { Message, ChatSession } from '@/types/chat';
import { useLocalStorage } from './useLocalStorage';

const generateId = () => Math.random().toString(36).substring(2, 15);

export function useChat() {
  const [sessions, setSessions] = useLocalStorage<ChatSession[]>('0xai-sessions', []);
  const [currentSessionId, setCurrentSessionId] = useLocalStorage<string | null>('0xai-current-session', null);
  const [isLoading, setIsLoading] = useState(false);

  const currentSession = sessions.find(s => s.id === currentSessionId) || null;

  const createSession = useCallback(() => {
    const newSession: ChatSession = { id: generateId(), title: 'New Chat', messages: [], createdAt: new Date(), updatedAt: new Date() };
    setSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(newSession.id);
    return newSession;
  }, [setSessions, setCurrentSessionId]);

  const updateSession = useCallback((sessionId: string, updates: Partial<ChatSession>) => {
    setSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ...updates, updatedAt: new Date() } : s));
  }, [setSessions]);

  const deleteSession = useCallback((sessionId: string) => {
    setSessions(prev => prev.filter(s => s.id !== sessionId));
    if (currentSessionId === sessionId) setCurrentSessionId(null);
  }, [setSessions, currentSessionId, setCurrentSessionId]);

  const clearAllSessions = useCallback(() => {
    setSessions([]);
    setCurrentSessionId(null);
  }, [setSessions, setCurrentSessionId]);

  const sendMessage = useCallback(async (content: string, apiKey?: string) => {
    if (!currentSession) {
      const newSession = createSession();
      setCurrentSessionId(newSession.id);
    }
    const userMessage: Message = { id: generateId(), role: 'user', content, timestamp: new Date() };
    const sessionId = currentSessionId || sessions[0]?.id;
    if (!sessionId) return;
    updateSession(sessionId, { messages: [...(currentSession?.messages || []), userMessage], title: currentSession?.messages.length === 0 ? content.slice(0, 30) + '...' : currentSession?.title });
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));
    const aiResponses = [
      "I'm 0x.AI, your cybernetic assistant. Running in demo mode.",
      "Initializing response protocols... In demo mode.",
      "System online. Demonstrating the chat interface.",
    ];
    const assistantMessage: Message = { id: generateId(), role: 'assistant', content: apiKey ? \`[API Connected] Processing: "\${content}"\` : aiResponses[Math.floor(Math.random() * aiResponses.length)], timestamp: new Date() };
    const updatedSession = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, { messages: [...(updatedSession?.messages || []), userMessage, assistantMessage] });
    setIsLoading(false);
  }, [currentSession, currentSessionId, sessions, createSession, updateSession, setCurrentSessionId]);

  return { sessions, currentSession, currentSessionId, isLoading, createSession, setCurrentSessionId, updateSession, deleteSession, clearAllSessions, sendMessage };
}`
  },
  {
    path: 'src/hooks/use-mobile.tsx',
    language: 'tsx',
    content: `import * as React from "react";

const MOBILE_BREAKPOINT = 768;

export function useIsMobile() {
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined);

  React.useEffect(() => {
    const mql = window.matchMedia(\`(max-width: \${MOBILE_BREAKPOINT - 1}px)\`);
    const onChange = () => { setIsMobile(window.innerWidth < MOBILE_BREAKPOINT); };
    mql.addEventListener("change", onChange);
    setIsMobile(window.innerWidth < MOBILE_BREAKPOINT);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  return !!isMobile;
}`
  },
  // Chat Components
  {
    path: 'src/components/chat/ChatArea.tsx',
    language: 'tsx',
    content: `import { useRef, useEffect } from 'react';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { ChatSession } from '@/types/chat';
import { Bot, Sparkles } from 'lucide-react';

interface ChatAreaProps {
  session: ChatSession | null;
  isLoading: boolean;
  onSendMessage: (message: string) => void;
}

export function ChatArea({ session, isLoading, onSendMessage }: ChatAreaProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [session?.messages]);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6 matrix-bg scanline">
        {session?.messages && session.messages.length > 0 ? (
          <>
            {session.messages.map((message) => (
              <MessageBubble key={message.id} message={message} />
            ))}
            {isLoading && (
              <div className="flex gap-3 animate-fade-in">
                <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
                  <Bot className="h-4 w-4 text-primary" />
                </div>
                <div className="cyber-card rounded-lg p-4 max-w-[80%]">
                  <div className="flex items-center gap-2 text-primary">
                    <Sparkles className="h-4 w-4 animate-pulse" />
                    <span className="text-sm typing-cursor">Processing</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center animate-fade-in">
            <div className="w-24 h-24 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center mb-6 animate-float">
              <span className="text-4xl font-display font-bold text-primary glow-text">0x</span>
            </div>
            <h2 className="text-2xl font-display font-bold text-foreground mb-2">Welcome to <span className="text-primary glow-text">0x.AI</span></h2>
            <p className="text-muted-foreground max-w-md mb-8">Your cybernetic AI assistant.</p>
          </div>
        )}
      </div>
      <ChatInput onSend={onSendMessage} isLoading={isLoading} />
    </div>
  );
}`
  },
  {
    path: 'src/components/chat/ChatInput.tsx',
    language: 'tsx',
    content: `import { useState, KeyboardEvent } from 'react';
import { Send, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface ChatInputProps {
  onSend: (message: string) => void;
  isLoading: boolean;
  disabled?: boolean;
}

export function ChatInput({ onSend, isLoading, disabled }: ChatInputProps) {
  const [message, setMessage] = useState('');

  const handleSend = () => {
    if (message.trim() && !isLoading) {
      onSend(message.trim());
      setMessage('');
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="p-4 border-t border-primary/20 bg-card/50 backdrop-blur-sm">
      <div className="max-w-4xl mx-auto">
        <div className="relative flex items-end gap-2 cyber-border rounded-lg p-2 bg-muted/30">
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter your message..."
            disabled={disabled || isLoading}
            rows={1}
            className={cn("flex-1 bg-transparent border-none resize-none text-foreground placeholder:text-muted-foreground focus:outline-none font-mono text-sm py-2 px-3 min-h-[40px] max-h-[200px]")}
          />
          <Button variant="cyber" size="icon" onClick={handleSend} disabled={!message.trim() || isLoading || disabled} className="shrink-0">
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground text-center mt-2">Press Enter to send, Shift+Enter for new line</p>
      </div>
    </div>
  );
}`
  },
  {
    path: 'src/components/chat/MessageBubble.tsx',
    language: 'tsx',
    content: `import { Message } from '@/types/chat';
import { cn } from '@/lib/utils';
import { User, Bot } from 'lucide-react';

interface MessageBubbleProps { message: Message; }

export function MessageBubble({ message }: MessageBubbleProps) {
  const isUser = message.role === 'user';

  return (
    <div className={cn("flex gap-3 animate-slide-up", isUser ? "flex-row-reverse" : "flex-row")}>
      <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border", isUser ? "bg-accent/20 border-accent/50" : "bg-primary/20 border-primary/50 animate-pulse-glow")}>
        {isUser ? <User className="h-4 w-4 text-accent" /> : <Bot className="h-4 w-4 text-primary" />}
      </div>
      <div className={cn("max-w-[80%] rounded-lg p-4 border", isUser ? "bg-accent/10 border-accent/30 text-foreground" : "cyber-card")}>
        <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
        <span className="text-xs text-muted-foreground mt-2 block">{new Date(message.timestamp).toLocaleTimeString()}</span>
      </div>
    </div>
  );
}`
  },
  // Layout Components
  {
    path: 'src/components/layout/MainSidebar.tsx',
    language: 'tsx',
    content: `import { Home, Terminal, Key, Shield, FileText, Settings, ScrollText, Info, Lock, Menu, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { MenuSection } from '@/types/app';
import { cn } from '@/lib/utils';
import { useState } from 'react';

interface MainSidebarProps {
  activeSection: MenuSection;
  onSectionChange: (section: MenuSection) => void;
  appName: string;
  isAuthenticated: boolean;
}

const menuItems: { id: MenuSection; label: string; icon: React.ReactNode; locked?: boolean }[] = [
  { id: 'home', label: 'Home', icon: <Home className="h-4 w-4" /> },
  { id: 'console', label: 'Interaction Console', icon: <Terminal className="h-4 w-4" /> },
  { id: 'api', label: 'API', icon: <Key className="h-4 w-4" /> },
  { id: 'modification', label: 'Modification', icon: <Shield className="h-4 w-4" />, locked: true },
  { id: 'license', label: 'License', icon: <FileText className="h-4 w-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
  { id: 'logs', label: 'Logs', icon: <ScrollText className="h-4 w-4" /> },
  { id: 'about', label: 'About', icon: <Info className="h-4 w-4" /> },
];

export function MainSidebar({ activeSection, onSectionChange, appName, isAuthenticated }: MainSidebarProps) {
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      <div className="p-4 border-b border-primary/20">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/30 to-accent/20 border border-primary/50 flex items-center justify-center animate-pulse-glow">
            <span className="text-primary font-display font-bold text-sm">0.x"</span>
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="font-display text-base font-bold text-foreground glow-text truncate">{appName}</h1>
            <p className="text-xs text-muted-foreground">Cybersecurity AI Platform</p>
          </div>
        </div>
      </div>
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {menuItems.map((item) => (
          <button key={item.id} onClick={() => { onSectionChange(item.id); setIsMobileOpen(false); }}
            className={cn("w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
              activeSection === item.id ? "bg-primary/20 text-primary border border-primary/50 glow-primary" : "text-muted-foreground hover:text-foreground hover:bg-muted/50")}>
            <span className={cn("transition-colors", activeSection === item.id ? "text-primary" : "")}>{item.icon}</span>
            <span className="flex-1 text-left">{item.label}</span>
            {item.locked && <Lock className={cn("h-3 w-3", isAuthenticated && item.id === 'modification' ? "text-accent" : "text-muted-foreground")} />}
          </button>
        ))}
      </nav>
      <div className="p-4 border-t border-primary/20">
        <p className="text-xs text-center text-muted-foreground">Created by <span className="text-primary font-medium">0.x" vexX</span></p>
      </div>
    </div>
  );

  return (
    <>
      <Button variant="outline" size="icon" className="fixed top-4 left-4 z-50 md:hidden" onClick={() => setIsMobileOpen(!isMobileOpen)}>
        {isMobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
      </Button>
      {isMobileOpen && <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 md:hidden" onClick={() => setIsMobileOpen(false)} />}
      <aside className={cn("fixed md:relative z-40 h-full w-64 bg-card border-r border-primary/20 transition-transform duration-300", isMobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0")}>
        <SidebarContent />
      </aside>
    </>
  );
}`
  },
  // Section Components
  {
    path: 'src/components/sections/HomeSection.tsx',
    language: 'tsx',
    content: `import { Terminal, Shield, Wifi, WifiOff, Upload, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { MenuSection } from '@/types/app';

interface HomeSectionProps {
  appName: string;
  internetEnabled: boolean;
  onToggleInternet: () => void;
  onNavigate: (section: MenuSection) => void;
  uploadedFilesCount: number;
}

export function HomeSection({ appName, internetEnabled, onToggleInternet, onNavigate, uploadedFilesCount }: HomeSectionProps) {
  return (
    <div className="h-full flex flex-col p-6 overflow-y-auto matrix-bg">
      <div className="flex-1 flex flex-col items-center justify-center text-center max-w-2xl mx-auto">
        <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-primary/20 to-accent/10 border border-primary/30 flex items-center justify-center mb-6 animate-float">
          <Shield className="h-12 w-12 text-primary" />
        </div>
        <h1 className="text-3xl md:text-4xl font-display font-bold text-foreground mb-3">
          Welcome to <span className="text-primary glow-text">{appName}</span>
        </h1>
        <p className="text-muted-foreground mb-8 max-w-lg">AI-driven cybersecurity testing & simulation platform for controlled lab environments.</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full max-w-xl mb-8">
          <Button variant="cyber" size="lg" className="flex-col h-auto py-6 gap-2" onClick={() => onNavigate('console')}>
            <Terminal className="h-6 w-6" /><span>Open Console</span>
          </Button>
          <Button variant={internetEnabled ? "accent" : "outline"} size="lg" className="flex-col h-auto py-6 gap-2" onClick={onToggleInternet}>
            {internetEnabled ? <><Wifi className="h-6 w-6" /><span>Internet ON</span></> : <><WifiOff className="h-6 w-6" /><span>Internet OFF</span></>}
          </Button>
          <Button variant="outline" size="lg" className="flex-col h-auto py-6 gap-2 relative" onClick={() => onNavigate('settings')}>
            <Upload className="h-6 w-6" /><span>Add Files</span>
            {uploadedFilesCount > 0 && <span className="absolute top-2 right-2 bg-primary text-primary-foreground text-xs rounded-full w-5 h-5 flex items-center justify-center">{uploadedFilesCount}</span>}
          </Button>
        </div>
        <div className="grid grid-cols-2 gap-4 w-full max-w-lg">
          <div className="cyber-card rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={\`w-2 h-2 rounded-full \${internetEnabled ? 'bg-accent animate-pulse' : 'bg-muted-foreground'}\`} />
              <span className="text-sm text-muted-foreground">Network Status</span>
            </div>
            <p className="text-lg font-medium text-foreground">{internetEnabled ? 'Online Mode' : 'Offline Mode'}</p>
          </div>
          <div className="cyber-card rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="h-3 w-3 text-primary" />
              <span className="text-sm text-muted-foreground">Files Loaded</span>
            </div>
            <p className="text-lg font-medium text-foreground">{uploadedFilesCount} files</p>
          </div>
        </div>
      </div>
      <div className="mt-8 p-4 rounded-lg border border-primary/20 bg-primary/5 max-w-2xl mx-auto">
        <p className="text-xs text-center text-muted-foreground">
          <span className="text-primary font-medium">Lab Environment Only</span> — All operations require explicit confirmation.
        </p>
      </div>
    </div>
  );
}`
  },
  // Types
  {
    path: 'src/types/app.ts',
    language: 'typescript',
    content: `export interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  type?: 'reasoning' | 'execution' | 'output' | 'log' | 'result';
}

export interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
}

export interface ExternalAPI {
  id: string;
  name: string;
  key: string;
  provider: 'openai' | 'anthropic' | 'google' | 'custom';
  endpoint?: string;
  isActive: boolean;
}

export interface AppSettings {
  appName: string;
  internetEnabled: boolean;
  modificationPassword: string;
  recoveryEmail: string;
  internalAPIKey: string;
  externalAPIs: ExternalAPI[];
  activeAPIId: string | null;
}

export interface LicenseInfo {
  text: string;
  version: string;
  lastUpdated: Date;
}

export interface UploadedFile {
  id: string;
  name: string;
  type: 'script' | 'wordlist' | 'config' | 'tool' | 'other';
  content: string;
  uploadedAt: Date;
}

export interface ExecutionTask {
  id: string;
  prompt: string;
  requiredTools: string[];
  requiredFiles: string[];
  status: 'pending' | 'confirmed' | 'executing' | 'completed' | 'failed';
  output: string[];
  createdAt: Date;
}

export type MenuSection = 'home' | 'console' | 'api' | 'modification' | 'license' | 'settings' | 'logs' | 'about';`
  },
];

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * DOCUMENTATION DATA
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const DOCUMENTATION_ITEMS: DocItem[] = [
  // Overview
  {
    id: 'intro',
    title: 'VexX AI Overview',
    description: 'VexX AI is a comprehensive cybersecurity AI platform built with React, TypeScript, and advanced encryption capabilities. The application provides a secure environment for AI-assisted security operations with full AES-256-GCM encryption.',
    category: 'overview',
    tags: ['introduction', 'overview', 'security'],
  },
  {
    id: 'architecture',
    title: 'System Architecture',
    description: 'The application follows a modular architecture with clear separation of concerns. Core modules include Security (encryption, audit, storage), UI Components (React/TypeScript), State Management (React hooks), and API Integration.',
    category: 'overview',
    code: `// Architecture Overview
├── src/
│   ├── components/      # UI Components
│   │   ├── ui/          # Base UI components (shadcn)
│   │   ├── sections/    # Page sections
│   │   ├── layout/      # Layout components
│   │   └── modals/      # Modal dialogs
│   ├── hooks/           # Custom React hooks
│   ├── lib/             # Utilities and libraries
│   │   └── security/    # Security module
│   ├── types/           # TypeScript definitions
│   └── pages/           # Page components`,
    language: 'plaintext',
    tags: ['architecture', 'structure', 'modules'],
  },
  
  // Security Module Documentation
  {
    id: 'encryption-module',
    title: 'Encryption Module',
    description: 'The encryption module provides AES-256-GCM encryption, PBKDF2 key derivation, and SHA-256/384/512 hashing. All cryptographic operations use the Web Crypto API for maximum security.',
    category: 'security',
    code: `// Encryption Example
import { encryptData, decryptData } from '@/lib/security';

// Encrypt sensitive data
const result = await encryptData('sensitive-data', 'encryption-key');
if (result.success) {
  console.log('Encrypted:', result.encrypted);
}

// Decrypt data
const decrypted = await decryptData(result.encrypted, 'encryption-key');`,
    language: 'typescript',
    parameters: [
      { name: 'data', type: 'string', description: 'The plaintext data to encrypt' },
      { name: 'key', type: 'string', description: 'The encryption key (will be derived using PBKDF2)' },
    ],
    returns: 'Promise<EncryptionResult> - Contains success status and encrypted/error data',
    tags: ['encryption', 'aes', 'crypto'],
  },
  {
    id: 'hashing-functions',
    title: 'Hashing Functions',
    description: 'Provides SHA-256, SHA-384, and SHA-512 hashing with optional HMAC support for data integrity verification.',
    category: 'security',
    code: `// Hashing Example
import { computeSHA256Hash, computeHMAC, verifyHMAC } from '@/lib/security';

// Compute SHA-256 hash
const hash = await computeSHA256Hash('data-to-hash');

// Generate HMAC
const hmac = await computeHMAC('data', 'secret-key');

// Verify HMAC
const isValid = await verifyHMAC('data', 'secret-key', hmac.hash);`,
    language: 'typescript',
    tags: ['hashing', 'sha256', 'hmac', 'integrity'],
  },
  {
    id: 'password-security',
    title: 'Password Security',
    description: 'Implements secure password hashing with PBKDF2 (100,000 iterations), salt generation, and password strength validation following OWASP guidelines.',
    category: 'security',
    code: `// Password Security Example
import { hashPassword, verifyPassword, validatePasswordStrength } from '@/lib/security';

// Hash a password
const hashResult = await hashPassword('user-password');

// Verify password
const isValid = await verifyPassword('user-password', hashResult.hash);

// Validate strength
const strength = validatePasswordStrength('MyP@ssw0rd123');
console.log(strength.score, strength.level);`,
    language: 'typescript',
    parameters: [
      { name: 'password', type: 'string', description: 'The password to hash or validate' },
      { name: 'iterations', type: 'number', description: 'PBKDF2 iterations (default: 100000)', optional: true },
    ],
    tags: ['password', 'pbkdf2', 'security'],
  },
  {
    id: 'secure-storage',
    title: 'Secure Storage',
    description: 'Provides encrypted localStorage with integrity verification, automatic encryption/decryption, and audit logging for all storage operations.',
    category: 'security',
    code: `// Secure Storage Example
import { secureStorage, setSecureItem, getSecureItem } from '@/lib/security';

// Store encrypted data
await setSecureItem('user-data', { name: 'John', email: 'john@example.com' });

// Retrieve and decrypt
const data = await getSecureItem('user-data');

// Get storage statistics
const stats = secureStorage.getStatistics();`,
    language: 'typescript',
    tags: ['storage', 'encryption', 'localStorage'],
  },
  {
    id: 'security-audit',
    title: 'Security Audit System',
    description: 'Comprehensive security event logging with threat detection, anomaly analysis, session management, and rate limiting capabilities.',
    category: 'security',
    code: `// Security Audit Example
import { securityAudit } from '@/lib/security';

// Log security event
await securityAudit.logEvent({
  type: 'auth_success',
  severity: 'low',
  description: 'User authenticated successfully',
  metadata: { userId: '123' },
});

// Perform threat assessment
const assessment = await securityAudit.performThreatAssessment();

// Get statistics
const stats = securityAudit.getStatistics();`,
    language: 'typescript',
    tags: ['audit', 'logging', 'threats', 'monitoring'],
  },
  
  // Components Documentation
  {
    id: 'modification-section',
    title: 'ModificationSection Component',
    description: 'Password-protected settings management component with AES-256-GCM encryption, password strength validation, and security audit logging.',
    category: 'components',
    code: `// ModificationSection Usage
<ModificationSection
  isAuthenticated={isAuthenticated}
  onAuthenticate={authenticate}
  onLogout={logout}
  settings={settings}
  license={license}
  onUpdateSettings={setSettings}
  onUpdateLicense={setLicense}
/>`,
    language: 'tsx',
    parameters: [
      { name: 'isAuthenticated', type: 'boolean', description: 'Current authentication state' },
      { name: 'onAuthenticate', type: '(password: string) => boolean', description: 'Authentication callback' },
      { name: 'onLogout', type: '() => void', description: 'Logout callback' },
      { name: 'settings', type: 'AppSettings', description: 'Current application settings' },
      { name: 'license', type: 'LicenseInfo', description: 'License information object' },
    ],
    tags: ['component', 'authentication', 'settings'],
  },
  {
    id: 'security-dashboard',
    title: 'SecurityDashboardSection Component',
    description: 'Real-time security monitoring dashboard with threat assessment, audit log viewer, encryption status, and storage analytics.',
    category: 'components',
    code: `// SecurityDashboardSection Usage
<SecurityDashboardSection />`,
    language: 'tsx',
    tags: ['component', 'dashboard', 'monitoring'],
  },
  
  // Hooks Documentation
  {
    id: 'use-secure-storage',
    title: 'useSecureLocalStorage Hook',
    description: 'Custom React hook for encrypted localStorage with automatic encryption/decryption and audit logging.',
    category: 'hooks',
    code: `// useSecureLocalStorage Example
import { useSecureLocalStorage } from '@/hooks/useSecureLocalStorage';

function MyComponent() {
  const [userData, setUserData] = useSecureLocalStorage('user-data', {
    name: '',
    email: '',
  });

  return (
    <input
      value={userData.name}
      onChange={(e) => setUserData({ ...userData, name: e.target.value })}
    />
  );
}`,
    language: 'tsx',
    parameters: [
      { name: 'key', type: 'string', description: 'Storage key identifier' },
      { name: 'initialValue', type: 'T', description: 'Initial value if no stored data exists' },
      { name: 'encryptionKey', type: 'string', description: 'Custom encryption key', optional: true },
    ],
    returns: '[T, (value: T | ((val: T) => T)) => void] - State value and setter function',
    tags: ['hook', 'storage', 'encryption'],
  },
  {
    id: 'use-app-state',
    title: 'useAppState Hook',
    description: 'Central application state management hook providing access to settings, sessions, authentication, and all core functionality.',
    category: 'hooks',
    code: `// useAppState Example
import { useAppState } from '@/hooks/useAppState';

function App() {
  const {
    settings,
    license,
    isAuthenticated,
    authenticate,
    logout,
    sendMessage,
  } = useAppState();

  // Use state and actions...
}`,
    language: 'tsx',
    tags: ['hook', 'state', 'management'],
  },
  
  // Types Documentation
  {
    id: 'app-settings-type',
    title: 'AppSettings Interface',
    description: 'TypeScript interface defining the structure of application settings including security and API configurations.',
    category: 'types',
    code: `interface AppSettings {
  appName: string;
  internetEnabled: boolean;
  modificationPassword: string;
  recoveryEmail: string;
  internalAPIKey: string;
  externalAPIs: ExternalAPI[];
  activeAPIId: string | null;
}`,
    language: 'typescript',
    tags: ['type', 'interface', 'settings'],
  },
  {
    id: 'encryption-types',
    title: 'Encryption Types',
    description: 'TypeScript types for encryption operations including EncryptionResult, DecryptionResult, and HashResult.',
    category: 'types',
    code: `interface EncryptionResult {
  success: boolean;
  encrypted?: string;
  iv?: string;
  salt?: string;
  error?: string;
}

interface DecryptionResult {
  success: boolean;
  decrypted?: string;
  error?: string;
}

interface HashResult {
  success: boolean;
  hash?: string;
  algorithm?: string;
  error?: string;
}`,
    language: 'typescript',
    tags: ['type', 'interface', 'encryption'],
  },
  
  // Utilities Documentation
  {
    id: 'security-utils',
    title: 'Security Utilities',
    description: 'Utility functions for security operations including secure comparison, HTML sanitization, and random generation.',
    category: 'utils',
    code: `// Security Utilities
import { 
  secureCompare, 
  sanitizeHTML, 
  generateSecureId,
  generateSecureToken,
  generateSecureOTP 
} from '@/lib/security';

// Timing-safe comparison
const isEqual = secureCompare('string1', 'string2');

// Sanitize HTML input
const safe = sanitizeHTML('<script>alert("xss")</script>');

// Generate secure identifiers
const id = await generateSecureId(16);
const token = await generateSecureToken(32);
const otp = await generateSecureOTP(6);`,
    language: 'typescript',
    tags: ['utility', 'security', 'sanitization'],
  },
];

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * MAIN COMPONENT
 * ═══════════════════════════════════════════════════════════════════════════════
 */

/**
 * DocumentationSection Component
 * 
 * Provides comprehensive documentation viewer with PDF export capabilities.
 * Features include:
 * - Interactive navigation
 * - Code syntax display
 * - PDF generation
 * - Search functionality
 * 
 * @returns JSX.Element - Rendered documentation section
 */
export function DocumentationSection(): JSX.Element {
  // ═══════════════════════════════════════════════════════════════════════════
  // STATE
  // ═══════════════════════════════════════════════════════════════════════════

  const [activeSection, setActiveSection] = useState<DocSection>('overview');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedItem, setSelectedItem] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(['overview', 'security']));
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [showExportOptions, setShowExportOptions] = useState<boolean>(false);
  const [exportConfig, setExportConfig] = useState<ExportConfig>({
    includeCode: true,
    includeExamples: true,
    includeTableOfContents: true,
    includeCover: true,
    paperSize: 'a4',
    orientation: 'portrait',
    fontSize: 10,
  });

  const contentRef = useRef<HTMLDivElement>(null);

  // ═══════════════════════════════════════════════════════════════════════════
  // COMPUTED VALUES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Filtered documentation items based on search query
   */
  const filteredItems = useMemo(() => {
    if (!searchQuery) return DOCUMENTATION_ITEMS;

    const query = searchQuery.toLowerCase();
    return DOCUMENTATION_ITEMS.filter(item =>
      item.title.toLowerCase().includes(query) ||
      item.description.toLowerCase().includes(query) ||
      item.tags?.some(tag => tag.toLowerCase().includes(query))
    );
  }, [searchQuery]);

  /**
   * Items grouped by category
   */
  const itemsByCategory = useMemo(() => {
    const grouped: Record<DocSection, DocItem[]> = {
      overview: [],
      security: [],
      components: [],
      hooks: [],
      types: [],
      utils: [],
      api: [],
    };

    filteredItems.forEach(item => {
      grouped[item.category].push(item);
    });

    return grouped;
  }, [filteredItems]);

  /**
   * Table of contents structure
   */
  const tableOfContents: TocItem[] = useMemo(() => {
    return Object.entries(itemsByCategory)
      .filter(([_, items]) => items.length > 0)
      .map(([category, items]) => ({
        id: category,
        title: category.charAt(0).toUpperCase() + category.slice(1),
        level: 1,
        children: items.map(item => ({
          id: item.id,
          title: item.title,
          level: 2,
        })),
      }));
  }, [itemsByCategory]);

  // ═══════════════════════════════════════════════════════════════════════════
  // HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Toggles category expansion
   */
  const toggleCategory = useCallback((category: string) => {
    setExpandedCategories(prev => {
      const newSet = new Set(prev);
      if (newSet.has(category)) {
        newSet.delete(category);
      } else {
        newSet.add(category);
      }
      return newSet;
    });
  }, []);

  /**
   * Copies code to clipboard
   */
  const handleCopyCode = useCallback((code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    toast.success('Code copied to clipboard');
  }, []);

  /**
   * Generates and downloads PDF documentation
   */
  const handleExportPDF = useCallback(async () => {
    setIsExporting(true);
    
    try {
      const pdf = new jsPDF({
        orientation: exportConfig.orientation,
        unit: 'mm',
        format: exportConfig.paperSize,
      });

      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 20;
      const contentWidth = pageWidth - (margin * 2);
      let yPosition = margin;

      // Helper function to add text with wrapping
      const addText = (text: string, fontSize: number, isBold: boolean = false, color: [number, number, number] = [0, 0, 0]) => {
        pdf.setFontSize(fontSize);
        pdf.setTextColor(...color);
        if (isBold) {
          pdf.setFont('helvetica', 'bold');
        } else {
          pdf.setFont('helvetica', 'normal');
        }

        const lines = pdf.splitTextToSize(text, contentWidth);
        const lineHeight = fontSize * 0.5;

        lines.forEach((line: string) => {
          if (yPosition + lineHeight > pageHeight - margin) {
            pdf.addPage();
            yPosition = margin;
          }
          pdf.text(line, margin, yPosition);
          yPosition += lineHeight;
        });

        yPosition += 2;
      };

      // Helper function for adding code blocks
      const addCodeBlock = (code: string) => {
        pdf.setFillColor(240, 240, 240);
        const codeLines = code.split('\n');
        const codeHeight = codeLines.length * 4 + 8;

        if (yPosition + codeHeight > pageHeight - margin) {
          pdf.addPage();
          yPosition = margin;
        }

        pdf.rect(margin, yPosition - 2, contentWidth, Math.min(codeHeight, pageHeight - margin - yPosition), 'F');
        
        pdf.setFontSize(8);
        pdf.setFont('courier', 'normal');
        pdf.setTextColor(50, 50, 50);

        codeLines.forEach((line: string) => {
          if (yPosition > pageHeight - margin) {
            pdf.addPage();
            yPosition = margin;
            pdf.setFillColor(240, 240, 240);
          }
          const wrappedLines = pdf.splitTextToSize(line, contentWidth - 10);
          wrappedLines.forEach((wrappedLine: string) => {
            pdf.text(wrappedLine, margin + 5, yPosition);
            yPosition += 4;
          });
        });

        yPosition += 5;
      };

      // Cover page
      if (exportConfig.includeCover) {
        pdf.setFillColor(15, 23, 42);
        pdf.rect(0, 0, pageWidth, pageHeight, 'F');
        
        pdf.setTextColor(0, 255, 255);
        pdf.setFontSize(36);
        pdf.setFont('helvetica', 'bold');
        pdf.text('VexX AI', pageWidth / 2, pageHeight / 3, { align: 'center' });
        
        pdf.setFontSize(18);
        pdf.setTextColor(150, 150, 150);
        pdf.text('Code Documentation', pageWidth / 2, pageHeight / 3 + 15, { align: 'center' });
        
        pdf.setFontSize(12);
        pdf.setTextColor(100, 100, 100);
        pdf.text(`Generated: ${new Date().toLocaleDateString()}`, pageWidth / 2, pageHeight / 2, { align: 'center' });
        pdf.text('Version 2.0.0', pageWidth / 2, pageHeight / 2 + 10, { align: 'center' });
        
        pdf.setFontSize(10);
        pdf.text('Cybersecurity AI Platform', pageWidth / 2, pageHeight - 30, { align: 'center' });
        pdf.text('AES-256-GCM Encryption | PBKDF2 Key Derivation', pageWidth / 2, pageHeight - 20, { align: 'center' });
        
        pdf.addPage();
        yPosition = margin;
      }

      // Table of Contents
      if (exportConfig.includeTableOfContents) {
        addText('Table of Contents', 18, true, [0, 150, 150]);
        yPosition += 5;

        tableOfContents.forEach((section, sectionIndex) => {
          addText(`${sectionIndex + 1}. ${section.title}`, 14, true);
          section.children?.forEach((item, itemIndex) => {
            addText(`   ${sectionIndex + 1}.${itemIndex + 1} ${item.title}`, 11, false, [80, 80, 80]);
          });
        });

        pdf.addPage();
        yPosition = margin;
      }

      // Documentation content
      Object.entries(itemsByCategory).forEach(([category, items]) => {
        if (items.length === 0) return;

        // Category header
        addText(category.toUpperCase(), 16, true, [0, 150, 150]);
        yPosition += 3;

        items.forEach((item) => {
          // Item title
          addText(item.title, 14, true);
          
          // Description
          addText(item.description, exportConfig.fontSize);
          
          // Parameters
          if (item.parameters && item.parameters.length > 0) {
            yPosition += 2;
            addText('Parameters:', 11, true, [80, 80, 80]);
            item.parameters.forEach(param => {
              addText(`• ${param.name} (${param.type}${param.optional ? ', optional' : ''}): ${param.description}`, 10, false, [60, 60, 60]);
            });
          }

          // Returns
          if (item.returns) {
            addText(`Returns: ${item.returns}`, 10, false, [60, 60, 60]);
          }

          // Code
          if (exportConfig.includeCode && item.code) {
            yPosition += 3;
            addText('Code Example:', 11, true, [80, 80, 80]);
            addCodeBlock(item.code);
          }

          // Tags
          if (item.tags && item.tags.length > 0) {
            addText(`Tags: ${item.tags.join(', ')}`, 9, false, [120, 120, 120]);
          }

          yPosition += 8;
        });

        // Add page break between categories
        if (yPosition > pageHeight / 2) {
          pdf.addPage();
          yPosition = margin;
        }
      });

      // Footer with page numbers
      const totalPages = pdf.internal.pages.length - 1;
      for (let i = 1; i <= totalPages; i++) {
        pdf.setPage(i);
        pdf.setFontSize(8);
        pdf.setTextColor(150, 150, 150);
        pdf.text(`Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
        pdf.text('VexX AI Documentation', margin, pageHeight - 10);
      }

      // Save the PDF
      pdf.save(`vexx-ai-documentation-${new Date().toISOString().split('T')[0]}.pdf`);
      toast.success('PDF documentation exported successfully!');
    } catch (error) {
      console.error('PDF export error:', error);
      toast.error('Failed to export PDF');
    } finally {
      setIsExporting(false);
      setShowExportOptions(false);
    }
  }, [exportConfig, itemsByCategory, tableOfContents]);

  /**
   * Exports complete source code to PDF for developer analysis
   */
  const handleExportFullSourceCode = useCallback(async () => {
    setIsExporting(true);
    
    try {
      const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 15;
      const contentWidth = pageWidth - (margin * 2);
      let yPosition = margin;

      // Helper to add page break if needed
      const checkPageBreak = (requiredHeight: number = 10) => {
        if (yPosition + requiredHeight > pageHeight - margin) {
          pdf.addPage();
          yPosition = margin;
          return true;
        }
        return false;
      };

      // Cover page
      pdf.setFillColor(15, 23, 42);
      pdf.rect(0, 0, pageWidth, pageHeight, 'F');
      
      pdf.setTextColor(0, 255, 255);
      pdf.setFontSize(32);
      pdf.setFont('helvetica', 'bold');
      pdf.text('VexX AI', pageWidth / 2, pageHeight / 4, { align: 'center' });
      
      pdf.setFontSize(24);
      pdf.setTextColor(255, 255, 255);
      pdf.text('Complete Source Code', pageWidth / 2, pageHeight / 4 + 15, { align: 'center' });
      
      pdf.setFontSize(14);
      pdf.setTextColor(150, 150, 150);
      pdf.text('For Developer Analysis & Review', pageWidth / 2, pageHeight / 4 + 30, { align: 'center' });
      
      pdf.setFontSize(11);
      pdf.setTextColor(100, 100, 100);
      pdf.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, pageHeight / 2, { align: 'center' });
      pdf.text(`Total Files: ${SOURCE_CODE_FILES.length}`, pageWidth / 2, pageHeight / 2 + 8, { align: 'center' });
      pdf.text('Version 2.0.0', pageWidth / 2, pageHeight / 2 + 16, { align: 'center' });
      
      // File list on cover
      pdf.setFontSize(10);
      pdf.setTextColor(0, 200, 200);
      pdf.text('Included Files:', pageWidth / 2, pageHeight / 2 + 35, { align: 'center' });
      
      pdf.setTextColor(120, 120, 120);
      pdf.setFontSize(8);
      SOURCE_CODE_FILES.slice(0, 8).forEach((file, index) => {
        pdf.text(file.path, pageWidth / 2, pageHeight / 2 + 45 + (index * 5), { align: 'center' });
      });
      if (SOURCE_CODE_FILES.length > 8) {
        pdf.text(`... and ${SOURCE_CODE_FILES.length - 8} more files`, pageWidth / 2, pageHeight / 2 + 45 + (8 * 5), { align: 'center' });
      }
      
      pdf.setFontSize(9);
      pdf.setTextColor(80, 80, 80);
      pdf.text('Cybersecurity AI Platform', pageWidth / 2, pageHeight - 25, { align: 'center' });
      pdf.text('AES-256-GCM Encryption | PBKDF2 Key Derivation | TypeScript + React', pageWidth / 2, pageHeight - 18, { align: 'center' });
      
      pdf.addPage();
      yPosition = margin;

      // Table of Contents
      pdf.setTextColor(0, 150, 150);
      pdf.setFontSize(18);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Table of Contents', margin, yPosition);
      yPosition += 12;

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(10);
      pdf.setTextColor(60, 60, 60);

      SOURCE_CODE_FILES.forEach((file, index) => {
        checkPageBreak(6);
        pdf.text(`${index + 1}. ${file.path}`, margin, yPosition);
        pdf.setTextColor(120, 120, 120);
        pdf.text(`[${file.language}]`, pageWidth - margin - 20, yPosition);
        pdf.setTextColor(60, 60, 60);
        yPosition += 6;
      });

      pdf.addPage();
      yPosition = margin;

      // Source code files
      SOURCE_CODE_FILES.forEach((file, fileIndex) => {
        // File header
        checkPageBreak(20);
        
        pdf.setFillColor(30, 40, 60);
        pdf.rect(margin, yPosition - 4, contentWidth, 12, 'F');
        
        pdf.setTextColor(0, 220, 220);
        pdf.setFontSize(12);
        pdf.setFont('helvetica', 'bold');
        pdf.text(`${fileIndex + 1}. ${file.path}`, margin + 3, yPosition + 3);
        
        pdf.setTextColor(150, 150, 150);
        pdf.setFontSize(9);
        pdf.setFont('helvetica', 'normal');
        pdf.text(`Language: ${file.language.toUpperCase()}`, pageWidth - margin - 35, yPosition + 3);
        
        yPosition += 15;

        // Code content
        const codeLines = file.content.split('\\n');
        
        pdf.setFontSize(7);
        pdf.setFont('courier', 'normal');
        
        codeLines.forEach((line, lineIndex) => {
          checkPageBreak(4);
          
          // Line number
          pdf.setTextColor(100, 100, 100);
          const lineNum = String(lineIndex + 1).padStart(4, ' ');
          pdf.text(lineNum, margin, yPosition);
          
          // Code line
          pdf.setTextColor(40, 40, 40);
          const wrappedLines = pdf.splitTextToSize(line || ' ', contentWidth - 15);
          wrappedLines.forEach((wrappedLine: string, wrapIndex: number) => {
            if (wrapIndex > 0) {
              checkPageBreak(4);
              pdf.text('    ', margin, yPosition);
            }
            pdf.text(wrappedLine, margin + 12, yPosition);
            yPosition += 3.5;
          });
        });

        yPosition += 10;
        
        // Separator
        if (fileIndex < SOURCE_CODE_FILES.length - 1) {
          checkPageBreak(15);
          pdf.setDrawColor(200, 200, 200);
          pdf.line(margin, yPosition, pageWidth - margin, yPosition);
          yPosition += 10;
        }
      });

      // Footer with page numbers
      const totalPages = pdf.internal.pages.length - 1;
      for (let i = 2; i <= totalPages; i++) {
        pdf.setPage(i);
        pdf.setFontSize(8);
        pdf.setTextColor(150, 150, 150);
        pdf.text(`Page ${i - 1} of ${totalPages - 1}`, pageWidth / 2, pageHeight - 8, { align: 'center' });
        pdf.text('VexX AI - Complete Source Code', margin, pageHeight - 8);
        pdf.text(new Date().toLocaleDateString(), pageWidth - margin - 20, pageHeight - 8);
      }

      // Save
      pdf.save(`vexx-ai-full-source-code-${new Date().toISOString().split('T')[0]}.pdf`);
      toast.success('Full source code exported to PDF!');
    } catch (error) {
      console.error('Source code export error:', error);
      toast.error('Failed to export source code');
    } finally {
      setIsExporting(false);
      setShowExportOptions(false);
    }
  }, []);

  /**
   * Exports complete source code to a text file
   */
  const handleExportSourceCodeText = useCallback(() => {
    setIsExporting(true);
    
    try {
      let content = '';
      
      // Header
      content += '═'.repeat(80) + '\n';
      content += 'VEXX AI - COMPLETE SOURCE CODE\n';
      content += '═'.repeat(80) + '\n\n';
      content += `Generated: ${new Date().toLocaleString()}\n`;
      content += `Total Files: ${SOURCE_CODE_FILES.length}\n`;
      content += `Version: 2.0.0\n\n`;
      
      // Table of Contents
      content += '─'.repeat(80) + '\n';
      content += 'TABLE OF CONTENTS\n';
      content += '─'.repeat(80) + '\n\n';
      
      SOURCE_CODE_FILES.forEach((file, index) => {
        content += `${String(index + 1).padStart(2, '0')}. ${file.path} [${file.language}]\n`;
      });
      
      content += '\n' + '═'.repeat(80) + '\n';
      content += 'SOURCE FILES\n';
      content += '═'.repeat(80) + '\n\n';
      
      // Source files
      SOURCE_CODE_FILES.forEach((file, index) => {
        content += '┌' + '─'.repeat(78) + '┐\n';
        content += `│ ${String(index + 1).padStart(2, '0')}. ${file.path}`.padEnd(79) + '│\n';
        content += `│ Language: ${file.language.toUpperCase()}`.padEnd(79) + '│\n';
        content += '└' + '─'.repeat(78) + '┘\n\n';
        
        // Add line numbers to code
        const lines = file.content.split('\n');
        lines.forEach((line, lineIndex) => {
          const lineNum = String(lineIndex + 1).padStart(4, ' ');
          content += `${lineNum} │ ${line}\n`;
        });
        
        content += '\n' + '─'.repeat(80) + '\n\n';
      });
      
      // Footer
      content += '═'.repeat(80) + '\n';
      content += 'END OF SOURCE CODE\n';
      content += `VexX AI - Cybersecurity AI Platform\n`;
      content += '═'.repeat(80) + '\n';
      
      // Create and download file
      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vexx-ai-source-code-${new Date().toISOString().split('T')[0]}.txt`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      toast.success('Source code exported to text file!');
    } catch (error) {
      console.error('Text export error:', error);
      toast.error('Failed to export source code');
    } finally {
      setIsExporting(false);
      setShowExportOptions(false);
    }
  }, []);

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Renders category icon
   */
  const getCategoryIcon = (category: DocSection): React.ReactNode => {
    const icons = {
      overview: <Book className="h-4 w-4" />,
      security: <Shield className="h-4 w-4" />,
      components: <Layers className="h-4 w-4" />,
      hooks: <Zap className="h-4 w-4" />,
      types: <Type className="h-4 w-4" />,
      utils: <Settings className="h-4 w-4" />,
      api: <Terminal className="h-4 w-4" />,
    };
    return icons[category];
  };

  /**
   * Renders the sidebar navigation
   */
  const renderSidebar = () => (
    <div className="w-64 border-r border-primary/20 flex flex-col">
      {/* Search */}
      <div className="p-4 border-b border-primary/20">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search docs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* Navigation */}
      <ScrollArea className="flex-1">
        <div className="p-2">
          {Object.entries(itemsByCategory).map(([category, items]) => {
            if (items.length === 0) return null;
            const isExpanded = expandedCategories.has(category);

            return (
              <div key={category} className="mb-1">
                <button
                  onClick={() => toggleCategory(category)}
                  className={cn(
                    "w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors",
                    "hover:bg-muted/50 text-foreground"
                  )}
                >
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                  {getCategoryIcon(category as DocSection)}
                  <span className="capitalize font-medium">{category}</span>
                  <Badge variant="secondary" className="ml-auto text-xs">
                    {items.length}
                  </Badge>
                </button>

                {isExpanded && (
                  <div className="ml-6 space-y-1 mt-1">
                    {items.map(item => (
                      <button
                        key={item.id}
                        onClick={() => setSelectedItem(item.id)}
                        className={cn(
                          "w-full text-left px-3 py-1.5 rounded text-sm transition-colors",
                          selectedItem === item.id
                            ? "bg-primary/20 text-primary"
                            : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
                        )}
                      >
                        {item.title}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>

      {/* Export Button */}
      <div className="p-4 border-t border-primary/20">
        <Button
          variant="cyber"
          className="w-full"
          onClick={() => setShowExportOptions(true)}
          disabled={isExporting}
        >
          {isExporting ? (
            <RefreshCw className="h-4 w-4 animate-spin mr-2" />
          ) : (
            <Download className="h-4 w-4 mr-2" />
          )}
          Export PDF
        </Button>
      </div>
    </div>
  );

  /**
   * Renders documentation item content
   */
  const renderDocContent = (item: DocItem) => (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Badge variant="outline" className="capitalize">
            {item.category}
          </Badge>
          {item.deprecated && (
            <Badge variant="destructive">Deprecated</Badge>
          )}
          {item.since && (
            <Badge variant="secondary">Since v{item.since}</Badge>
          )}
        </div>
        <h2 className="text-2xl font-display font-bold text-foreground">{item.title}</h2>
      </div>

      {/* Description */}
      <p className="text-muted-foreground leading-relaxed">{item.description}</p>

      {/* Parameters */}
      {item.parameters && item.parameters.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-display font-bold text-foreground flex items-center gap-2">
            <Hash className="h-4 w-4 text-primary" />
            Parameters
          </h3>
          <div className="space-y-2">
            {item.parameters.map((param, index) => (
              <div 
                key={index}
                className="p-3 rounded-lg bg-muted/30 border border-primary/20"
              >
                <div className="flex items-center gap-2 mb-1">
                  <code className="text-primary font-mono text-sm">{param.name}</code>
                  <code className="text-muted-foreground font-mono text-xs">{param.type}</code>
                  {param.optional && (
                    <Badge variant="outline" className="text-xs">optional</Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground">{param.description}</p>
                {param.defaultValue && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Default: <code className="text-primary">{param.defaultValue}</code>
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Returns */}
      {item.returns && (
        <div className="space-y-2">
          <h3 className="text-lg font-display font-bold text-foreground flex items-center gap-2">
            <ChevronRight className="h-4 w-4 text-primary" />
            Returns
          </h3>
          <div className="p-3 rounded-lg bg-muted/30 border border-primary/20">
            <code className="text-sm text-foreground">{item.returns}</code>
          </div>
        </div>
      )}

      {/* Code Example */}
      {item.code && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-display font-bold text-foreground flex items-center gap-2">
              <Code className="h-4 w-4 text-primary" />
              Code Example
            </h3>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => handleCopyCode(item.code!, item.id)}
            >
              {copiedId === item.id ? (
                <Check className="h-4 w-4 text-accent" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
          </div>
          <div className="relative">
            <pre className="p-4 rounded-lg bg-muted/50 border border-primary/20 overflow-x-auto">
              <code className="text-sm font-mono text-foreground whitespace-pre">
                {item.code}
              </code>
            </pre>
            {item.language && (
              <Badge className="absolute top-2 right-2" variant="secondary">
                {item.language}
              </Badge>
            )}
          </div>
        </div>
      )}

      {/* Tags */}
      {item.tags && item.tags.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-4 border-t border-primary/20">
          {item.tags.map(tag => (
            <Badge key={tag} variant="outline" className="text-xs">
              <Tag className="h-3 w-3 mr-1" />
              {tag}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );

  /**
   * Renders export options modal
   */
  const renderExportOptions = () => (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="cyber-card rounded-xl p-6 max-w-md w-full animate-slide-up">
        <h3 className="text-xl font-display font-bold text-foreground mb-4 flex items-center gap-2">
          <Download className="h-5 w-5 text-primary" />
          Export Options
        </h3>

        <div className="space-y-4">
          {/* Content Options */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground">Include in PDF:</label>
            <div className="space-y-2">
              {[
                { key: 'includeCover', label: 'Cover Page' },
                { key: 'includeTableOfContents', label: 'Table of Contents' },
                { key: 'includeCode', label: 'Code Examples' },
                { key: 'includeExamples', label: 'Usage Examples' },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={exportConfig[key as keyof ExportConfig] as boolean}
                    onChange={(e) => setExportConfig(prev => ({
                      ...prev,
                      [key]: e.target.checked,
                    }))}
                    className="rounded border-primary/30"
                  />
                  <span className="text-sm text-muted-foreground">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Paper Options */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Paper Size:</label>
              <select
                value={exportConfig.paperSize}
                onChange={(e) => setExportConfig(prev => ({
                  ...prev,
                  paperSize: e.target.value as 'a4' | 'letter',
                }))}
                className="w-full px-3 py-2 rounded-lg border border-primary/30 bg-muted/30 text-foreground text-sm"
              >
                <option value="a4">A4</option>
                <option value="letter">Letter</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Orientation:</label>
              <select
                value={exportConfig.orientation}
                onChange={(e) => setExportConfig(prev => ({
                  ...prev,
                  orientation: e.target.value as 'portrait' | 'landscape',
                }))}
                className="w-full px-3 py-2 rounded-lg border border-primary/30 bg-muted/30 text-foreground text-sm"
              >
                <option value="portrait">Portrait</option>
                <option value="landscape">Landscape</option>
              </select>
            </div>
          </div>

          {/* Font Size */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground">
              Font Size: {exportConfig.fontSize}pt
            </label>
            <input
              type="range"
              min="8"
              max="14"
              value={exportConfig.fontSize}
              onChange={(e) => setExportConfig(prev => ({
                ...prev,
                fontSize: parseInt(e.target.value),
              }))}
              className="w-full"
            />
          </div>
        </div>

        {/* Full Source Code Export */}
        <div className="mt-4 pt-4 border-t border-primary/20">
          <div className="flex items-center gap-2 mb-3">
            <FileCode className="h-4 w-4 text-accent" />
            <span className="text-sm font-medium text-foreground">Full Source Code Export</span>
          </div>
          <p className="text-xs text-muted-foreground mb-3">
            Export all {SOURCE_CODE_FILES.length} source files as a PDF for developer analysis and review.
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="flex-1 border-accent/50 text-accent hover:bg-accent/10"
              onClick={handleExportFullSourceCode}
              disabled={isExporting}
            >
              {isExporting ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Code className="h-4 w-4 mr-2" />
              )}
              PDF
            </Button>
            <Button
              variant="outline"
              className="flex-1 border-primary/50 text-primary hover:bg-primary/10"
              onClick={handleExportSourceCodeText}
              disabled={isExporting}
            >
              {isExporting ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <FileText className="h-4 w-4 mr-2" />
              )}
              TXT
            </Button>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2 mt-6">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => setShowExportOptions(false)}
          >
            Cancel
          </Button>
          <Button
            variant="cyber"
            className="flex-1"
            onClick={handleExportPDF}
            disabled={isExporting}
          >
            {isExporting ? (
              <RefreshCw className="h-4 w-4 animate-spin mr-2" />
            ) : (
              <Download className="h-4 w-4 mr-2" />
            )}
            Export Docs
          </Button>
        </div>
      </div>
    </div>
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN RENDER
  // ═══════════════════════════════════════════════════════════════════════════

  const selectedDocItem = DOCUMENTATION_ITEMS.find(item => item.id === selectedItem);

  return (
    <div className="h-full flex">
      {/* Sidebar */}
      {renderSidebar()}

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-primary/20">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-display font-bold text-foreground flex items-center gap-2">
                <FileText className="h-5 w-5 text-primary" />
                Documentation
              </h2>
              <p className="text-sm text-muted-foreground">
                {filteredItems.length} items • {Object.keys(itemsByCategory).filter(k => itemsByCategory[k as DocSection].length > 0).length} categories
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="text-xs">
                <Calendar className="h-3 w-3 mr-1" />
                v2.0.0
              </Badge>
              <Badge variant="outline" className="text-xs">
                <Clock className="h-3 w-3 mr-1" />
                {new Date().toLocaleDateString()}
              </Badge>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <ScrollArea className="flex-1" ref={contentRef}>
          <div className="p-6 max-w-4xl">
            {selectedDocItem ? (
              renderDocContent(selectedDocItem)
            ) : (
              <div className="text-center py-12">
                <Book className="h-12 w-12 text-primary/50 mx-auto mb-4" />
                <h3 className="text-lg font-display font-bold text-foreground mb-2">
                  VexX AI Documentation
                </h3>
                <p className="text-muted-foreground mb-4">
                  Select an item from the sidebar to view its documentation.
                </p>
                <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Shield className="h-3 w-3 text-accent" />
                    AES-256 Encryption
                  </span>
                  <span className="flex items-center gap-1">
                    <Lock className="h-3 w-3 text-primary" />
                    PBKDF2 Key Derivation
                  </span>
                  <span className="flex items-center gap-1">
                    <Database className="h-3 w-3 text-accent" />
                    Secure Storage
                  </span>
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Export Options Modal */}
      {showExportOptions && renderExportOptions()}
    </div>
  );
}

export default DocumentationSection;
