import { useState, useCallback } from 'react';
import { useLocalStorage } from './useLocalStorage';
import { 
  AppSettings, 
  LicenseInfo, 
  UploadedFile, 
  ChatSession, 
  Message,
  MenuSection 
} from '@/types/app';

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

  // Session management
  const createSession = useCallback(() => {
    const newSession: ChatSession = {
      id: generateId(),
      title: 'New Session',
      messages: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    setSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(newSession.id);
    return newSession;
  }, [setSessions, setCurrentSessionId]);

  const updateSession = useCallback((sessionId: string, updates: Partial<ChatSession>) => {
    setSessions(prev => prev.map(s => 
      s.id === sessionId 
        ? { ...s, ...updates, updatedAt: new Date() }
        : s
    ));
  }, [setSessions]);

  const deleteSession = useCallback((sessionId: string) => {
    setSessions(prev => prev.filter(s => s.id !== sessionId));
    if (currentSessionId === sessionId) {
      setCurrentSessionId(null);
    }
  }, [setSessions, currentSessionId, setCurrentSessionId]);

  // File management
  const addFile = useCallback((file: Omit<UploadedFile, 'id' | 'uploadedAt'>) => {
    const newFile: UploadedFile = {
      ...file,
      id: generateId(),
      uploadedAt: new Date(),
    };
    setUploadedFiles(prev => [...prev, newFile]);
    addLog(`File uploaded: ${file.name}`);
    return newFile;
  }, [setUploadedFiles]);

  const removeFile = useCallback((fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId));
  }, [setUploadedFiles]);

  // Logging
  const addLog = useCallback((message: string) => {
    const timestamp = new Date().toISOString();
    setLogs(prev => [`[${timestamp}] ${message}`, ...prev].slice(0, 1000));
  }, [setLogs]);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, [setLogs]);

  // Authentication for modification section
  const authenticate = useCallback((password: string): boolean => {
    if (!settings.modificationPassword) {
      // First time setup - set the password
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

  // Message handling
  const sendMessage = useCallback(async (content: string) => {
    let sessionId = currentSessionId;
    
    if (!sessionId) {
      const newSession = createSession();
      sessionId = newSession.id;
    }

    const userMessage: Message = {
      id: generateId(),
      role: 'user',
      content,
      timestamp: new Date(),
    };

    const session = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, {
      messages: [...(session?.messages || []), userMessage],
      title: session?.messages.length === 0 ? content.slice(0, 30) + '...' : session?.title,
    });

    addLog(`User prompt: ${content.slice(0, 50)}...`);
    setIsLoading(true);

    // Simulate AI response
    await new Promise(resolve => setTimeout(resolve, 1500));

    const responses = [
      {
        type: 'reasoning' as const,
        content: `Analyzing request: "${content}"\n\nDetermining required tools and files for this operation...`,
      },
      {
        type: 'execution' as const,
        content: `⚠️ CONFIRMATION REQUIRED\n\nThis operation requires:\n• Tool: nmap, nikto\n• Files: target_list.txt\n\nDo you confirm execution?`,
      },
    ];

    const aiMessages: Message[] = responses.map(r => ({
      id: generateId(),
      role: 'assistant' as const,
      content: r.content,
      timestamp: new Date(),
      type: r.type,
    }));

    const updatedSession = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, {
      messages: [...(updatedSession?.messages || []), userMessage, ...aiMessages],
    });

    addLog('AI response generated');
    setIsLoading(false);
  }, [currentSessionId, sessions, createSession, updateSession, addLog]);

  return {
    // State
    settings,
    license,
    uploadedFiles,
    sessions,
    logs,
    currentSession,
    currentSessionId,
    activeSection,
    isAuthenticated,
    isLoading,
    
    // Setters
    setSettings,
    setLicense,
    setActiveSection,
    setCurrentSessionId,
    
    // Actions
    createSession,
    updateSession,
    deleteSession,
    addFile,
    removeFile,
    addLog,
    clearLogs,
    authenticate,
    logout,
    sendMessage,
  };
}
