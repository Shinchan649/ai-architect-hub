export interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
}

export interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
}

export interface AppSettings {
  appName: string;
  theme: 'dark' | 'light' | 'cyber';
  apiKey: string;
  apiProvider: 'openai' | 'anthropic' | 'custom';
  customApiUrl?: string;
  model: string;
}

export interface LicenseInfo {
  text: string;
  version: string;
  lastUpdated: Date;
}
