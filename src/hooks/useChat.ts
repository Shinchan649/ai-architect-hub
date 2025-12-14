import { useState, useCallback } from 'react';
import { Message, ChatSession } from '@/types/chat';
import { useLocalStorage } from './useLocalStorage';

const generateId = () => Math.random().toString(36).substring(2, 15);

export function useChat() {
  const [sessions, setSessions] = useLocalStorage<ChatSession[]>('0xai-sessions', []);
  const [currentSessionId, setCurrentSessionId] = useLocalStorage<string | null>('0xai-current-session', null);
  const [isLoading, setIsLoading] = useState(false);

  const currentSession = sessions.find(s => s.id === currentSessionId) || null;

  const createSession = useCallback(() => {
    const newSession: ChatSession = {
      id: generateId(),
      title: 'New Chat',
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

  const clearAllSessions = useCallback(() => {
    setSessions([]);
    setCurrentSessionId(null);
  }, [setSessions, setCurrentSessionId]);

  const sendMessage = useCallback(async (content: string, apiKey?: string) => {
    if (!currentSession) {
      const newSession = createSession();
      setCurrentSessionId(newSession.id);
    }

    const userMessage: Message = {
      id: generateId(),
      role: 'user',
      content,
      timestamp: new Date(),
    };

    const sessionId = currentSessionId || sessions[0]?.id;
    if (!sessionId) return;

    updateSession(sessionId, {
      messages: [...(currentSession?.messages || []), userMessage],
      title: currentSession?.messages.length === 0 ? content.slice(0, 30) + '...' : currentSession?.title,
    });

    setIsLoading(true);

    // Simulate AI response (replace with actual API call when backend is connected)
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));

    const aiResponses = [
      "I'm 0x.AI, your cybernetic assistant. I'm currently running in demo mode. Connect an AI API in settings to enable full functionality.",
      "Initializing response protocols... In demo mode, I can show you how the interface works. Configure your API key in settings for real AI interactions.",
      "System online. I'm demonstrating the chat interface. For actual AI responses, please add your API credentials in the settings panel.",
      "Greetings, user. This is a simulated response. The 0x.AI system is ready to connect to your preferred AI provider once configured.",
    ];

    const assistantMessage: Message = {
      id: generateId(),
      role: 'assistant',
      content: apiKey ? `[API Connected] Processing your request: "${content}"` : aiResponses[Math.floor(Math.random() * aiResponses.length)],
      timestamp: new Date(),
    };

    const updatedSession = sessions.find(s => s.id === sessionId);
    updateSession(sessionId, {
      messages: [...(updatedSession?.messages || []), userMessage, assistantMessage],
    });

    setIsLoading(false);
  }, [currentSession, currentSessionId, sessions, createSession, updateSession, setCurrentSessionId]);

  return {
    sessions,
    currentSession,
    currentSessionId,
    isLoading,
    createSession,
    setCurrentSessionId,
    updateSession,
    deleteSession,
    clearAllSessions,
    sendMessage,
  };
}
