import type { CapacitorConfig } from '@capacitor/cli';

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

export default config;
