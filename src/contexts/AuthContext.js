// AuthContext - Provides authentication state and token acquisition throughout the app
import React, { createContext, useContext, useState, useCallback } from 'react';
import { useMsal, useIsAuthenticated } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { armScopes, logAnalyticsScopes, loginRequest } from '../authConfig';

const AuthContext = createContext(null);

// Default values when auth is not available
const defaultAuthValue = {
  isAuthenticated: false,
  isLoading: false,
  isMsalAvailable: false,
  account: null,
  login: async () => { throw new Error('Auth not configured'); },
  logout: async () => { throw new Error('Auth not configured'); },
  acquireToken: async () => { throw new Error('Auth not configured'); },
  getArmToken: async () => { throw new Error('Auth not configured'); },
  getLogAnalyticsToken: async () => { throw new Error('Auth not configured'); },
  fetchFromArm: async () => { throw new Error('Auth not configured'); },
  fetchFromLogAnalytics: async () => { throw new Error('Auth not configured'); },
  getSentinelWorkspaces: async () => { throw new Error('Auth not configured'); },
  getSentinelIncident: async () => { throw new Error('Auth not configured'); },
  getIncidentLogs: async () => { throw new Error('Auth not configured'); },
};

export function AuthProvider({ children }) {
  const { instance, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();
  const [isLoading, setIsLoading] = useState(false);

  // Get the active account
  const account = accounts[0] || null;

  // Login with popup
  const login = useCallback(async () => {
    try {
      setIsLoading(true);
      const response = await instance.loginPopup(loginRequest);
      if (response?.account) {
        instance.setActiveAccount(response.account);
      }
      return response;
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  }, [instance]);

  // Logout
  const logout = useCallback(async () => {
    try {
      await instance.logoutPopup();
    } catch (error) {
      console.error('Logout failed:', error);
      throw error;
    }
  }, [instance]);

  // Acquire token silently, falling back to popup if needed
  const acquireToken = useCallback(async (scopes) => {
    if (!account) {
      throw new Error('No authenticated account found');
    }

    const request = {
      scopes: scopes.scopes || scopes,
      account,
    };

    try {
      const response = await instance.acquireTokenSilent(request);
      return response.accessToken;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        // Token expired or consent needed - use popup
        try {
          const response = await instance.acquireTokenPopup(request);
          return response.accessToken;
        } catch (popupError) {
          console.error('Popup token acquisition failed:', popupError);
          throw popupError;
        }
      }
      throw error;
    }
  }, [instance, account]);

  // Get token for Azure Resource Manager API
  const getArmToken = useCallback(async () => {
    return acquireToken(armScopes);
  }, [acquireToken]);

  // Get token for Log Analytics API
  const getLogAnalyticsToken = useCallback(async () => {
    return acquireToken(logAnalyticsScopes);
  }, [acquireToken]);

  // Fetch from Azure Resource Manager with auth
  const fetchFromArm = useCallback(async (url, options = {}) => {
    setIsLoading(true);
    try {
      const token = await getArmToken();
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`ARM API error ${response.status}: ${errorText}`);
      }

      return response.json();
    } finally {
      setIsLoading(false);
    }
  }, [getArmToken]);

  // Fetch from Log Analytics with auth
  const fetchFromLogAnalytics = useCallback(async (workspaceId, query) => {
    setIsLoading(true);
    try {
      const token = await getLogAnalyticsToken();
      const response = await fetch(
        `https://api.loganalytics.io/v1/workspaces/${workspaceId}/query`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ query }),
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Log Analytics API error ${response.status}: ${errorText}`);
      }

      return response.json();
    } finally {
      setIsLoading(false);
    }
  }, [getLogAnalyticsToken]);

  // Get list of Sentinel workspaces user has access to
  const getSentinelWorkspaces = useCallback(async () => {
    // First get subscriptions
    const subsResponse = await fetchFromArm(
      'https://management.azure.com/subscriptions?api-version=2022-12-01'
    );

    const workspaces = [];

    // For each subscription, get Log Analytics workspaces with Sentinel enabled
    for (const sub of subsResponse.value || []) {
      try {
        // Get all Log Analytics workspaces in this subscription
        const workspacesResponse = await fetchFromArm(
          `https://management.azure.com/subscriptions/${sub.subscriptionId}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01`
        );

        for (const ws of workspacesResponse.value || []) {
          // Check if Sentinel is enabled by looking for SecurityInsights solution
          try {
            await fetchFromArm(
              `https://management.azure.com${ws.id}/providers/Microsoft.SecurityInsights/settings?api-version=2023-11-01`
            );

            // If we can query Sentinel settings, it's a Sentinel workspace
            workspaces.push({
              id: ws.id,
              name: ws.name,
              customerId: ws.properties?.customerId, // Log Analytics workspace ID for queries
              location: ws.location,
              subscriptionId: sub.subscriptionId,
              subscriptionName: sub.displayName,
              resourceGroup: ws.id.split('/resourceGroups/')[1]?.split('/')[0],
            });
          } catch {
            // Sentinel not enabled on this workspace, skip it
          }
        }
      } catch (err) {
        console.warn(`Failed to get workspaces for subscription ${sub.subscriptionId}:`, err);
      }
    }

    return workspaces;
  }, [fetchFromArm]);

  // Get incident details from Sentinel
  const getSentinelIncident = useCallback(async (workspaceResourceId, incidentId) => {
    // Normalize incident ID (handle both formats: just number or full incident-GUID)
    const normalizedId = incidentId.toString().trim();

    // Get the incident
    const incidentResponse = await fetchFromArm(
      `https://management.azure.com${workspaceResourceId}/providers/Microsoft.SecurityInsights/incidents/${normalizedId}?api-version=2023-11-01`
    );

    // Get alerts related to this incident
    let alerts = [];
    try {
      const alertsResponse = await fetchFromArm(
        `https://management.azure.com${workspaceResourceId}/providers/Microsoft.SecurityInsights/incidents/${normalizedId}/alerts?api-version=2023-11-01`
      );
      alerts = alertsResponse.value || [];
    } catch (err) {
      console.warn('Failed to fetch incident alerts:', err);
    }

    // Get entities related to this incident
    let entities = [];
    try {
      const entitiesResponse = await fetchFromArm(
        `https://management.azure.com${workspaceResourceId}/providers/Microsoft.SecurityInsights/incidents/${normalizedId}/entities?api-version=2023-11-01`
      );
      entities = entitiesResponse.entities || [];
    } catch (err) {
      console.warn('Failed to fetch incident entities:', err);
    }

    return {
      incident: incidentResponse,
      alerts,
      entities,
    };
  }, [fetchFromArm]);

  // Run a Log Analytics query for incident-related logs
  const getIncidentLogs = useCallback(async (workspaceCustomerId, incidentId) => {
    // Query SecurityIncident and related tables
    const query = `
      // Get incident details
      SecurityIncident
      | where IncidentNumber == ${incidentId} or IncidentName contains "${incidentId}"
      | take 1
      | project IncidentNumber, Title, Description, Severity, Status, Classification,
                CreatedTime, LastModifiedTime, Owner, Labels, AlertIds

      // Union with related alerts
      | union (
        SecurityAlert
        | where SystemAlertId in (
          SecurityIncident
          | where IncidentNumber == ${incidentId} or IncidentName contains "${incidentId}"
          | mv-expand AlertIds
          | project tostring(AlertIds)
        )
        | project AlertName = AlertName, AlertSeverity = AlertSeverity,
                  Description, ProviderName, TimeGenerated, ExtendedProperties,
                  Entities, Tactics, Techniques
      )
    `;

    return fetchFromLogAnalytics(workspaceCustomerId, query);
  }, [fetchFromLogAnalytics]);

  const value = {
    isAuthenticated,
    isLoading,
    isMsalAvailable: true,
    account,
    login,
    logout,
    acquireToken,
    getArmToken,
    getLogAnalyticsToken,
    fetchFromArm,
    fetchFromLogAnalytics,
    getSentinelWorkspaces,
    getSentinelIncident,
    getIncidentLogs,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  // Return default values if context not available (no AuthProvider)
  if (!context) {
    return defaultAuthValue;
  }
  return context;
}

export default AuthContext;
