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
