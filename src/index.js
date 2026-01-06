import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { PublicClientApplication } from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';
import './index.css';
import App from './App';
import { NavigationProvider } from './contexts/NavigationContext';
import { AuthProvider } from './contexts/AuthContext';
import { msalConfig } from './authConfig';

// Initialize MSAL instance
const msalInstance = new PublicClientApplication(msalConfig);

// Handle redirect callback (for redirect flows if used)
msalInstance.initialize().then(() => {
  // Account selection logic could go here
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) {
    msalInstance.setActiveAccount(accounts[0]);
  }
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <MsalProvider instance={msalInstance}>
      <AuthProvider>
        <BrowserRouter>
          <NavigationProvider>
            <App />
          </NavigationProvider>
        </BrowserRouter>
      </AuthProvider>
    </MsalProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
