import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App';
import { NavigationProvider } from './contexts/NavigationContext';

// Conditionally import MSAL if configured
let MsalWrapper = ({ children }) => children; // Default passthrough

const initializeMsal = async () => {
  const clientId = process.env.REACT_APP_AZURE_CLIENT_ID;

  // Only initialize MSAL if client ID is configured
  if (clientId) {
    try {
      const { PublicClientApplication } = await import('@azure/msal-browser');
      const { MsalProvider } = await import('@azure/msal-react');
      const { msalConfig } = await import('./authConfig');
      const { AuthProvider } = await import('./contexts/AuthContext');

      const msalInstance = new PublicClientApplication(msalConfig);
      await msalInstance.initialize();

      const accounts = msalInstance.getAllAccounts();
      if (accounts.length > 0) {
        msalInstance.setActiveAccount(accounts[0]);
      }

      // Create wrapper component with MSAL
      MsalWrapper = ({ children }) => (
        <MsalProvider instance={msalInstance}>
          <AuthProvider>
            {children}
          </AuthProvider>
        </MsalProvider>
      );

      console.log('MSAL initialized successfully');
    } catch (err) {
      console.warn('MSAL initialization failed, Sentinel lookup will be disabled:', err.message);
    }
  } else {
    console.log('REACT_APP_AZURE_CLIENT_ID not configured, Sentinel lookup disabled');
  }
};

// Initialize and render
initializeMsal().then(() => {
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(
    <React.StrictMode>
      <MsalWrapper>
        <BrowserRouter>
          <NavigationProvider>
            <App />
          </NavigationProvider>
        </BrowserRouter>
      </MsalWrapper>
    </React.StrictMode>
  );
}).catch(err => {
  console.error('App initialization failed:', err);
  // Render without MSAL on error
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(
    <React.StrictMode>
      <BrowserRouter>
        <NavigationProvider>
          <App />
        </NavigationProvider>
      </BrowserRouter>
    </React.StrictMode>
  );
});
