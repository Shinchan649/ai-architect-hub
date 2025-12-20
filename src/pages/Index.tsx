import { useState } from 'react';
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
import { InstallBanner } from '@/components/InstallBanner';

const Index = () => {
  const {
    settings,
    license,
    uploadedFiles,
    sessions,
    logs,
    currentSession,
    activeSection,
    isAuthenticated,
    isLoading,
    setSettings,
    setLicense,
    setActiveSection,
    createSession,
    addFile,
    removeFile,
    addLog,
    clearLogs,
    authenticate,
    logout,
    sendMessage,
  } = useAppState();

  const [fileManagerOpen, setFileManagerOpen] = useState(false);

  const handleToggleInternet = () => {
    setSettings(prev => {
      const newState = { ...prev, internetEnabled: !prev.internetEnabled };
      addLog(`Internet access ${newState.internetEnabled ? 'enabled' : 'disabled'}`);
      return newState;
    });
  };

  const renderSection = () => {
    switch (activeSection) {
      case 'home':
        return (
          <HomeSection
            appName={settings.appName}
            internetEnabled={settings.internetEnabled}
            onToggleInternet={handleToggleInternet}
            onNavigate={setActiveSection}
            uploadedFilesCount={uploadedFiles.length}
          />
        );
      case 'console':
        return (
          <ConsoleSection
            session={currentSession}
            isLoading={isLoading}
            onSendMessage={sendMessage}
            internetEnabled={settings.internetEnabled}
            onToggleInternet={handleToggleInternet}
            uploadedFiles={uploadedFiles}
            onOpenFileManager={() => setActiveSection('settings')}
          />
        );
      case 'api':
        return (
          <APISection
            settings={settings}
            onUpdateSettings={setSettings}
          />
        );
      case 'modification':
        return (
          <ModificationSection
            isAuthenticated={isAuthenticated}
            onAuthenticate={authenticate}
            onLogout={logout}
            settings={settings}
            license={license}
            onUpdateSettings={setSettings}
            onUpdateLicense={setLicense}
          />
        );
      case 'license':
        return <LicenseSection license={license} />;
      case 'settings':
        return (
          <SettingsSection
            settings={settings}
            uploadedFiles={uploadedFiles}
            onAddFile={addFile}
            onRemoveFile={removeFile}
            onUpdateSettings={setSettings}
          />
        );
      case 'logs':
        return <LogsSection logs={logs} onClearLogs={clearLogs} />;
      case 'about':
        return <AboutSection appName={settings.appName} />;
      default:
        return null;
    }
  };

  return (
    <>
      <Helmet>
        <title>{settings.appName} - Cybersecurity AI Platform</title>
        <meta name="description" content="AI-driven cybersecurity testing and simulation platform for controlled lab environments." />
      </Helmet>

      <div className="flex h-screen bg-background overflow-hidden">
        <MainSidebar
          activeSection={activeSection}
          onSectionChange={setActiveSection}
          appName={settings.appName}
          isAuthenticated={isAuthenticated}
        />

        <main className="flex-1 flex flex-col overflow-hidden">
          <InstallBanner />
          {renderSection()}
        </main>
      </div>
    </>
  );
};

export default Index;
