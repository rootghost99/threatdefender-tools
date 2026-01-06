// MSAL Configuration for Azure AD Authentication
// Used for acquiring tokens to call Azure Resource Manager and Sentinel APIs

export const msalConfig = {
  auth: {
    // Client ID from Azure AD App Registration (set via environment variable or hardcode for dev)
    clientId: process.env.REACT_APP_AZURE_CLIENT_ID || '',
    // Tenant ID for threathuntermssp.com
    authority: 'https://login.microsoftonline.com/b97db93f-ba65-4ed8-8be9-15e047852060',
    // Redirect URI after authentication
    redirectUri: window.location.origin,
    // Where to navigate after logout
    postLogoutRedirectUri: window.location.origin,
    // Required for SPA
    navigateToLoginRequestUrl: true,
  },
  cache: {
    // Use sessionStorage for better security (cleared when browser closes)
    cacheLocation: 'sessionStorage',
    // Set to true for IE11 / Edge compatibility
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        switch (level) {
          case 0: // Error
            console.error('[MSAL]', message);
            break;
          case 1: // Warning
            console.warn('[MSAL]', message);
            break;
          case 2: // Info
            console.info('[MSAL]', message);
            break;
          case 3: // Verbose
            console.debug('[MSAL]', message);
            break;
          default:
            break;
        }
      },
      logLevel: 1, // Warning level in production
    },
  },
};

// Scopes for Azure Resource Manager API (list subscriptions, resource groups, workspaces)
export const armScopes = {
  scopes: ['https://management.azure.com/user_impersonation'],
};

// Scopes for Log Analytics API (run queries)
export const logAnalyticsScopes = {
  scopes: ['https://api.loganalytics.io/Data.Read'],
};

// Combined login request with all needed scopes
export const loginRequest = {
  scopes: [
    'User.Read',
    'https://management.azure.com/user_impersonation',
    'https://api.loganalytics.io/Data.Read',
  ],
};

// Graph API scopes (for user profile)
export const graphScopes = {
  scopes: ['User.Read'],
};
