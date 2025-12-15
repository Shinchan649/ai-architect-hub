# VexX AI - Complete Source Code Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Security Module](#security-module)
   - [Encryption](#encryption)
   - [Secure Storage](#secure-storage)
   - [Security Audit](#security-audit)
3. [Application Types](#application-types)
4. [Core Hooks](#core-hooks)
5. [Components](#components)
6. [Styling](#styling)

---

## Project Overview

**VexX AI** is a cybersecurity AI platform built with React, TypeScript, Tailwind CSS, and Vite. The application features enterprise-grade security with AES-GCM 256-bit encryption, secure local storage, and comprehensive security auditing.

### Technology Stack
- **Frontend**: React 18, TypeScript, Tailwind CSS
- **State Management**: React Hooks, Local Storage
- **Security**: Web Crypto API, AES-GCM Encryption
- **Mobile**: Capacitor for Android/iOS
- **Build Tool**: Vite

---

## Security Module

### Encryption

Location: `src/lib/security/encryption.ts`

```typescript
/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - ADVANCED ENCRYPTION MODULE                       ║
 * ║                                                                                ║
 * ║  This module provides enterprise-grade encryption and decryption utilities    ║
 * ║  using the Web Crypto API with AES-GCM 256-bit encryption.                   ║
 * ║                                                                                ║
 * ║  Security Features:                                                           ║
 * ║  - AES-GCM 256-bit symmetric encryption                                       ║
 * ║  - PBKDF2 key derivation with 100,000 iterations                             ║
 * ║  - Cryptographically secure random IV generation                              ║
 * ║  - Salt-based key derivation for password protection                          ║
 * ║  - SHA-256 hashing for integrity verification                                 ║
 * ║  - Base64 encoding for safe string storage                                    ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

// TYPE DEFINITIONS AND INTERFACES

export interface EncryptionConfig {
  algorithm: 'AES-GCM' | 'AES-CBC' | 'AES-CTR';
  keyLength: 128 | 192 | 256;
  iterations: number;
  saltLength: number;
  ivLength: number;
  hashAlgorithm: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface EncryptionResult {
  ciphertext: string;
  iv: string;
  salt: string;
  timestamp: number;
  version: string;
  checksum: string;
}

export interface DecryptionResult {
  plaintext: string;
  success: boolean;
  error?: string;
  integrityVerified: boolean;
}

export interface HashResult {
  hash: string;
  algorithm: string;
  timestamp: number;
}

export interface DerivedKeyResult {
  key: CryptoKey;
  salt: Uint8Array;
  iterations: number;
}

export interface PasswordHashResult {
  hash: string;
  salt: string;
  iterations: number;
  version: string;
}

// DEFAULT CONFIGURATION

export const DEFAULT_ENCRYPTION_CONFIG: EncryptionConfig = {
  algorithm: 'AES-GCM',
  keyLength: 256,
  iterations: 100000,
  saltLength: 32,
  ivLength: 12,
  hashAlgorithm: 'SHA-256',
};

// UTILITY FUNCTIONS

export function arrayBufferToBase64(buffer: ArrayBuffer): string;
export function base64ToArrayBuffer(base64: string): Uint8Array;
export function stringToUint8Array(str: string): Uint8Array;
export function uint8ArrayToString(array: Uint8Array): string;
export function generateSecureRandomBytes(length: number): Uint8Array;
export function generateSecureId(length?: number): string;
export function generateSalt(length?: number): Uint8Array;
export function generateIV(length?: number): Uint8Array;

// HASHING FUNCTIONS

export async function computeSHA256Hash(data: string | ArrayBuffer): Promise<string>;
export async function computeSHA384Hash(data: string | ArrayBuffer): Promise<string>;
export async function computeSHA512Hash(data: string | ArrayBuffer): Promise<string>;
export async function computeHashWithMetadata(
  data: string,
  algorithm?: 'SHA-256' | 'SHA-384' | 'SHA-512'
): Promise<HashResult>;
export async function computeHMAC(key: string, data: string): Promise<string>;
export async function verifyHMAC(key: string, data: string, signature: string): Promise<boolean>;

// KEY DERIVATION FUNCTIONS

export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  config?: EncryptionConfig
): Promise<CryptoKey>;

export async function deriveKeyWithMetadata(
  password: string,
  existingSalt?: Uint8Array,
  config?: EncryptionConfig
): Promise<DerivedKeyResult>;

// ENCRYPTION FUNCTIONS

export async function encryptData(
  plaintext: string,
  password?: string,
  config?: EncryptionConfig
): Promise<EncryptionResult>;

export async function decryptData(
  encryptedData: EncryptionResult,
  password?: string,
  config?: EncryptionConfig
): Promise<DecryptionResult>;

export async function encryptJSON<T>(data: T, password?: string): Promise<EncryptionResult>;

export async function decryptJSON<T>(
  encryptedData: EncryptionResult,
  password?: string
): Promise<T | null>;

export async function encryptSensitiveString(sensitiveData: string): Promise<string>;
export async function decryptSensitiveString(encryptedString: string): Promise<string | null>;

// PASSWORD HASHING

export async function hashPassword(password: string): Promise<PasswordHashResult>;
export async function verifyPassword(
  password: string,
  storedHash: PasswordHashResult
): Promise<boolean>;

// SECURE RANDOM GENERATION

export function generateSecureToken(length?: number, charset?: string): string;
export function generateSecureOTP(length?: number): string;
export function generateSecureAPIKey(prefix?: string): string;

// SECURE COMPARISON

export function secureCompare(a: string, b: string): boolean;

// DATA SANITIZATION

export function sanitizeHTML(input: string): string;
export function sanitizeEmail(email: string): string | null;
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  score: number;
  feedback: string[];
};

// COMBINED UTILITIES EXPORT

export const SecurityUtils = {
  encryptData,
  decryptData,
  encryptJSON,
  decryptJSON,
  encryptSensitiveString,
  decryptSensitiveString,
  computeSHA256Hash,
  computeSHA384Hash,
  computeSHA512Hash,
  computeHashWithMetadata,
  computeHMAC,
  verifyHMAC,
  hashPassword,
  verifyPassword,
  validatePasswordStrength,
  deriveKeyFromPassword,
  deriveKeyWithMetadata,
  generateSecureRandomBytes,
  generateSecureId,
  generateSecureToken,
  generateSecureOTP,
  generateSecureAPIKey,
  generateSalt,
  generateIV,
  secureCompare,
  sanitizeHTML,
  sanitizeEmail,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToUint8Array,
  uint8ArrayToString,
};
```

### Secure Storage

Location: `src/lib/security/secureStorage.ts`

```typescript
/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURE STORAGE MODULE                            ║
 * ║                                                                                ║
 * ║  Features:                                                                    ║
 * ║  - Automatic encryption/decryption of stored data                            ║
 * ║  - Integrity verification on retrieval                                       ║
 * ║  - Secure key management                                                     ║
 * ║  - Session-based temporary storage                                           ║
 * ║  - Audit logging for all operations                                          ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

export interface StorageEntryMetadata {
  id: string;
  key: string;
  createdAt: number;
  updatedAt: number;
  expiresAt?: number;
  dataHash: string;
  encryptedSize: number;
  version: string;
}

export interface SecureStorageEntry<T = unknown> {
  metadata: StorageEntryMetadata;
  encryptedData: EncryptionResult;
  typeHint: string;
}

export interface StorageOperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  metadata?: StorageEntryMetadata;
}

export interface StorageAuditEntry {
  timestamp: number;
  operation: 'read' | 'write' | 'delete' | 'clear' | 'expire';
  key: string;
  success: boolean;
  details?: string;
}

export interface StorageStatistics {
  totalEntries: number;
  totalSize: number;
  expiredEntries: number;
  utilizationPercent: number;
  lastAuditTimestamp: number;
}

export class SecureStorage {
  private static instance: SecureStorage | null = null;
  
  public static getInstance(): SecureStorage;
  public cleanExpiredEntries(): number;
  public async setItem<T>(
    key: string,
    data: T,
    options?: { expiresIn?: number; password?: string }
  ): Promise<StorageOperationResult<T>>;
  public async getItem<T>(
    key: string,
    options?: { password?: string }
  ): Promise<StorageOperationResult<T>>;
  public removeItem(key: string): StorageOperationResult;
  public hasItem(key: string): boolean;
  public getKeys(): string[];
  public clear(): StorageOperationResult;
  public getStorageSize(): number;
  public getStatistics(): StorageStatistics;
  public getAuditLog(limit?: number): StorageAuditEntry[];
  public clearAuditLog(): void;
  public async exportData(password?: string): Promise<string>;
  public async importData(
    dataString: string,
    options?: { password?: string; overwrite?: boolean }
  ): Promise<StorageOperationResult>;
}

export const secureStorage: SecureStorage;

// Convenience functions
export async function setSecureItem<T>(
  key: string,
  data: T,
  options?: { expiresIn?: number; password?: string }
): Promise<boolean>;

export async function getSecureItem<T>(
  key: string,
  options?: { password?: string }
): Promise<T | null>;

export function removeSecureItem(key: string): boolean;
```

### Security Audit

Location: `src/lib/security/securityAudit.ts`

```typescript
/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                    VEXX AI - SECURITY AUDIT MODULE                            ║
 * ║                                                                                ║
 * ║  Features:                                                                    ║
 * ║  - Real-time security event monitoring                                       ║
 * ║  - Anomaly detection algorithms                                              ║
 * ║  - Brute force attack prevention                                             ║
 * ║  - Session management and validation                                         ║
 * ║  - Security incident reporting                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

export type SecurityEventType =
  | 'authentication_success'
  | 'authentication_failure'
  | 'authorization_denied'
  | 'brute_force_attempt'
  | 'session_created'
  | 'session_expired'
  | 'session_invalidated'
  | 'data_access'
  | 'data_modification'
  | 'data_deletion'
  | 'encryption_operation'
  | 'decryption_operation'
  | 'api_access'
  | 'rate_limit_exceeded'
  | 'suspicious_activity'
  | 'integrity_violation'
  | 'configuration_change'
  | 'system_alert';

export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: number;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  description: string;
  metadata?: Record<string, unknown>;
  handled: boolean;
  hash: string;
}

export interface SecuritySession {
  id: string;
  userId: string;
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  isValid: boolean;
  fingerprint: string;
  authAttempts: number;
  metadata: Record<string, unknown>;
}

export interface RateLimitEntry {
  identifier: string;
  requestCount: number;
  windowStart: number;
  isBlocked: boolean;
  blockExpiresAt?: number;
}

export interface SecurityConfig {
  maxAuthAttempts: number;
  lockoutDuration: number;
  sessionTimeout: number;
  rateLimitWindow: number;
  maxRequestsPerWindow: number;
  enableAnomalyDetection: boolean;
  maxEventsInMemory: number;
  eventRetentionPeriod: number;
}

export interface SecurityStatistics {
  totalEvents: number;
  eventsBySeverity: Record<SecuritySeverity, number>;
  eventsByType: Record<string, number>;
  activeSessions: number;
  blockedIdentifiers: number;
  lastScanTimestamp: number;
  securityScore: number;
}

export interface ThreatAssessment {
  threatLevel: number;
  threats: Array<{
    type: string;
    severity: SecuritySeverity;
    description: string;
    mitigations: string[];
  }>;
  recommendations: string[];
  timestamp: number;
}

export class SecurityAudit {
  public static getInstance(config?: Partial<SecurityConfig>): SecurityAudit;
  public async logEvent(
    event: Omit<SecurityEvent, 'id' | 'timestamp' | 'handled' | 'hash'>
  ): Promise<SecurityEvent>;
  public async recordAuthAttempt(
    identifier: string,
    success: boolean,
    metadata?: Record<string, unknown>
  ): Promise<{ allowed: boolean; remainingAttempts: number; lockoutExpires?: number }>;
  public async createSession(
    userId: string,
    metadata?: Record<string, unknown>
  ): Promise<SecuritySession>;
  public validateSession(sessionId: string): { 
    valid: boolean; 
    session?: SecuritySession; 
    error?: string 
  };
  public async invalidateSession(sessionId: string): Promise<boolean>;
  public checkRateLimit(identifier: string): { 
    allowed: boolean; 
    remaining: number; 
    resetAt: number 
  };
  public getEvents(options?: {
    type?: SecurityEventType;
    severity?: SecuritySeverity;
    userId?: string;
    sessionId?: string;
    since?: number;
    limit?: number;
  }): SecurityEvent[];
  public getStatistics(): SecurityStatistics;
  public async performThreatAssessment(): Promise<ThreatAssessment>;
  public clearAll(): void;
  public async exportSecurityReport(): Promise<string>;
}

export const securityAudit: SecurityAudit;
```

---

## Application Types

Location: `src/types/app.ts`

```typescript
export interface Message {
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

export type MenuSection = 
  | 'home' 
  | 'console' 
  | 'api' 
  | 'modification' 
  | 'license' 
  | 'settings' 
  | 'logs' 
  | 'about';
```

---

## Core Hooks

### useSecureLocalStorage

Location: `src/hooks/useSecureLocalStorage.ts`

```typescript
export interface SecureStorageOptions {
  password?: string;
  encrypt?: boolean;
  auditLog?: boolean;
  expiresIn?: number;
  validateIntegrity?: boolean;
}

export type SecureStorageReturn<T> = [
  T,
  (value: T | ((val: T) => T)) => Promise<void>,
  {
    loading: boolean;
    error: string | null;
    clearError: () => void;
    remove: () => void;
    refresh: () => Promise<void>;
    isEncrypted: boolean;
    lastUpdated: number | null;
  }
];

export function useSecureLocalStorage<T>(
  key: string,
  initialValue: T,
  options?: SecureStorageOptions
): SecureStorageReturn<T>;

export function useSecureStorage<T>(
  key: string,
  initialValue: T,
  options?: SecureStorageOptions
): [T, (value: T | ((val: T) => T)) => Promise<void>];

export function useSecureSensitiveString(
  key: string,
  initialValue?: string
): [string, (value: string) => Promise<void>, { loading: boolean; error: string | null }];
```

### useAppState

Location: `src/hooks/useAppState.ts`

```typescript
export function useAppState(): {
  // State
  settings: AppSettings;
  license: LicenseInfo;
  uploadedFiles: UploadedFile[];
  sessions: ChatSession[];
  logs: string[];
  currentSession: ChatSession | null;
  currentSessionId: string | null;
  activeSection: MenuSection;
  isAuthenticated: boolean;
  isLoading: boolean;
  
  // Setters
  setSettings: (settings: AppSettings | ((prev: AppSettings) => AppSettings)) => void;
  setLicense: (license: LicenseInfo) => void;
  setActiveSection: (section: MenuSection) => void;
  setCurrentSessionId: (id: string | null) => void;
  
  // Actions
  createSession: () => ChatSession;
  updateSession: (sessionId: string, updates: Partial<ChatSession>) => void;
  deleteSession: (sessionId: string) => void;
  addFile: (file: Omit<UploadedFile, 'id' | 'uploadedAt'>) => UploadedFile;
  removeFile: (fileId: string) => void;
  addLog: (message: string) => void;
  clearLogs: () => void;
  authenticate: (password: string) => boolean;
  logout: () => void;
  sendMessage: (content: string) => Promise<void>;
};
```

### useLocalStorage

Location: `src/hooks/useLocalStorage.ts`

```typescript
export function useLocalStorage<T>(
  key: string, 
  initialValue: T
): [T, (value: T | ((val: T) => T)) => void];
```

---

## Components

### Main Sections

| Component | Location | Description |
|-----------|----------|-------------|
| HomeSection | `src/components/sections/HomeSection.tsx` | Main dashboard view |
| ConsoleSection | `src/components/sections/ConsoleSection.tsx` | AI chat console |
| APISection | `src/components/sections/APISection.tsx` | API management |
| ModificationSection | `src/components/sections/ModificationSection.tsx` | Protected settings |
| LicenseSection | `src/components/sections/LicenseSection.tsx` | License display |
| SettingsSection | `src/components/sections/SettingsSection.tsx` | App settings |
| LogsSection | `src/components/sections/LogsSection.tsx` | Activity logs |
| AboutSection | `src/components/sections/AboutSection.tsx` | About information |

### Layout Components

| Component | Location | Description |
|-----------|----------|-------------|
| MainSidebar | `src/components/layout/MainSidebar.tsx` | Navigation sidebar |
| Sidebar | `src/components/layout/Sidebar.tsx` | Generic sidebar |

### Chat Components

| Component | Location | Description |
|-----------|----------|-------------|
| ChatArea | `src/components/chat/ChatArea.tsx` | Message display area |
| ChatInput | `src/components/chat/ChatInput.tsx` | User input area |
| MessageBubble | `src/components/chat/MessageBubble.tsx` | Individual message |

---

## Styling

### CSS Variables

Location: `src/index.css`

```css
:root {
  --background: 220 20% 4%;
  --foreground: 180 100% 90%;
  --card: 220 25% 8%;
  --card-foreground: 180 100% 90%;
  --popover: 220 25% 6%;
  --popover-foreground: 180 100% 90%;
  --primary: 180 100% 50%;
  --primary-foreground: 220 20% 4%;
  --secondary: 220 30% 15%;
  --secondary-foreground: 180 100% 85%;
  --muted: 220 25% 12%;
  --muted-foreground: 180 20% 60%;
  --accent: 120 100% 50%;
  --accent-foreground: 220 20% 4%;
  --destructive: 0 85% 60%;
  --destructive-foreground: 0 0% 100%;
  --border: 180 50% 20%;
  --input: 220 30% 12%;
  --ring: 180 100% 50%;
  --radius: 0.5rem;
  
  /* Custom tokens */
  --glow-primary: 0 0 20px hsl(180 100% 50% / 0.5);
  --glow-accent: 0 0 20px hsl(120 100% 50% / 0.5);
  --glow-destructive: 0 0 20px hsl(0 85% 60% / 0.5);
  --gradient-cyber: linear-gradient(135deg, hsl(180 100% 50% / 0.1) 0%, hsl(120 100% 50% / 0.05) 100%);
  --gradient-dark: linear-gradient(180deg, hsl(220 20% 4%) 0%, hsl(220 25% 8%) 100%);
  --gradient-card: linear-gradient(135deg, hsl(220 25% 10%) 0%, hsl(220 25% 6%) 100%);
  --font-display: 'Orbitron', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}
```

### Custom Utility Classes

```css
.glow-primary { box-shadow: var(--glow-primary); }
.glow-accent { box-shadow: var(--glow-accent); }
.glow-text { text-shadow: 0 0 10px hsl(var(--primary) / 0.8); }
.cyber-border { border: 1px solid hsl(var(--primary) / 0.3); }
.cyber-card { background: var(--gradient-card); }
.scanline { /* CRT scanline effect */ }
.matrix-bg { /* Matrix-style background */ }
.typing-cursor::after { /* Blinking cursor */ }
.animate-pulse-glow { animation: pulse-glow 2s ease-in-out infinite; }
.animate-float { animation: float 3s ease-in-out infinite; }
.animate-slide-up { animation: slide-up 0.5s ease-out forwards; }
.animate-fade-in { animation: fade-in 0.3s ease-out forwards; }
```

---

## File Structure

```
src/
├── App.tsx                     # Main application component
├── main.tsx                    # Application entry point
├── index.css                   # Global styles and CSS variables
├── components/
│   ├── chat/
│   │   ├── ChatArea.tsx
│   │   ├── ChatInput.tsx
│   │   └── MessageBubble.tsx
│   ├── layout/
│   │   ├── MainSidebar.tsx
│   │   └── Sidebar.tsx
│   ├── modals/
│   │   ├── LicenseModal.tsx
│   │   └── SettingsModal.tsx
│   ├── sections/
│   │   ├── AboutSection.tsx
│   │   ├── APISection.tsx
│   │   ├── ConsoleSection.tsx
│   │   ├── HomeSection.tsx
│   │   ├── LicenseSection.tsx
│   │   ├── LogsSection.tsx
│   │   ├── ModificationSection.tsx
│   │   └── SettingsSection.tsx
│   └── ui/                     # Shadcn UI components
├── hooks/
│   ├── useAppState.ts
│   ├── useChat.ts
│   ├── useLocalStorage.ts
│   ├── useSecureLocalStorage.ts
│   └── use-mobile.tsx
├── lib/
│   ├── utils.ts
│   └── security/
│       ├── index.ts
│       ├── encryption.ts
│       ├── secureStorage.ts
│       └── securityAudit.ts
├── pages/
│   ├── Index.tsx
│   └── NotFound.tsx
└── types/
    ├── app.ts
    └── chat.ts
```

---

## Security Best Practices

### Encryption

1. **Always use AES-GCM** for authenticated encryption
2. **Generate new IVs** for each encryption operation
3. **Use PBKDF2** with 100,000+ iterations for key derivation
4. **Store checksums** for integrity verification

### Storage

1. **Never store plain text** sensitive data
2. **Implement expiration** for sensitive entries
3. **Audit all operations** for security monitoring
4. **Verify integrity** on every read operation

### Authentication

1. **Hash passwords** before storage
2. **Implement lockout** after failed attempts
3. **Use secure comparison** to prevent timing attacks
4. **Log all authentication** events

### Input Validation

1. **Sanitize all inputs** before processing
2. **Validate email** format and length
3. **Check password strength** before accepting
4. **Escape HTML** to prevent XSS

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2024 | Added comprehensive security module |
| 1.0.0 | 2024 | Initial release |

---

*This documentation is auto-generated and may be converted to PDF for offline reference.*
