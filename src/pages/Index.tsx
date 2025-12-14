import { useState } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { ChatArea } from '@/components/chat/ChatArea';
import { SettingsModal } from '@/components/modals/SettingsModal';
import { LicenseModal } from '@/components/modals/LicenseModal';
import { useChat } from '@/hooks/useChat';
import { useLocalStorage } from '@/hooks/useLocalStorage';
import { AppSettings, LicenseInfo } from '@/types/chat';
import { Helmet } from 'react-helmet-async';

const defaultSettings: AppSettings = {
  appName: '0x.AI',
  theme: 'cyber',
  apiKey: '',
  apiProvider: 'openai',
  model: 'gpt-4',
};

const defaultLicense: LicenseInfo = {
  text: '',
  version: '1.0.0',
  lastUpdated: new Date(),
};

const Index = () => {
  const {
    sessions,
    currentSession,
    currentSessionId,
    isLoading,
    createSession,
    setCurrentSessionId,
    deleteSession,
    clearAllSessions,
    sendMessage,
  } = useChat();

  const [settings, setSettings] = useLocalStorage<AppSettings>('0xai-settings', defaultSettings);
  const [license, setLicense] = useLocalStorage<LicenseInfo>('0xai-license', defaultLicense);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isLicenseOpen, setIsLicenseOpen] = useState(false);

  const handleNewChat = () => {
    createSession();
  };

  const handleSendMessage = (message: string) => {
    if (!currentSessionId) {
      createSession();
    }
    sendMessage(message, settings.apiKey);
  };

  return (
    <>
      <Helmet>
        <title>{settings.appName} - Cybernetic AI Assistant</title>
        <meta name="description" content="0x.AI is your advanced cybernetic AI assistant. Experience the future of AI interaction with our sleek, powerful interface." />
        <meta name="keywords" content="AI, artificial intelligence, chatbot, assistant, cyberpunk, 0x.AI" />
      </Helmet>

      <div className="flex h-screen bg-background overflow-hidden">
        <Sidebar
          sessions={sessions}
          currentSessionId={currentSessionId}
          onSelectSession={setCurrentSessionId}
          onNewChat={handleNewChat}
          onDeleteSession={deleteSession}
          onOpenSettings={() => setIsSettingsOpen(true)}
          onOpenLicense={() => setIsLicenseOpen(true)}
        />

        <main className="flex-1 flex flex-col overflow-hidden md:ml-0 ml-0">
          <ChatArea
            session={currentSession}
            isLoading={isLoading}
            onSendMessage={handleSendMessage}
          />
        </main>

        <SettingsModal
          isOpen={isSettingsOpen}
          onClose={() => setIsSettingsOpen(false)}
          settings={settings}
          onSaveSettings={setSettings}
          sessions={sessions}
          onClearSessions={clearAllSessions}
        />

        <LicenseModal
          isOpen={isLicenseOpen}
          onClose={() => setIsLicenseOpen(false)}
          license={license}
          onSaveLicense={setLicense}
          isAdmin={true}
        />
      </div>
    </>
  );
};

export default Index;
