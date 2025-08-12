import { useState, useEffect, useCallback } from 'react';

type VPNStatus = "connected" | "connecting" | "disconnected" | "failed";

interface VPNConnection {
  endpoint: string;
  location: string;
  ipAddress?: string;
  latency?: number;
}

interface ElectronVPNAPI {
  connect: (provider: string) => Promise<boolean>;
  getStatus: () => Promise<string>;
  checkIP: () => Promise<{
    ip: string;
    country: string;
    countryName: string;
    region: string;
    city: string;
    isAustralia: boolean;
  }>;
}

interface ElectronAPI {
  vpn: ElectronVPNAPI;
  shell: {
    openPath: (path: string) => Promise<string | null>;
    showItemInFolder: (path: string) => Promise<string | null>;
  };
  downloads: {
    chooseLocal: (downloadId: string) => Promise<{ success: boolean; error?: string }>;
    chooseMeta: (downloadId: string) => Promise<{ success: boolean; error?: string }>;
  };
  metaStorage: {
    getStatus: () => Promise<{
      connected: boolean;
      accountName: string | null;
      storageQuota: { used: number; total: number } | null;
    }>;
    connect: (accessToken: string) => Promise<{
      success: boolean;
      accountName?: string;
      storageQuota?: { used: number; total: number };
    }>;
    disconnect: () => Promise<{ success: boolean }>;
  };
  on: (channel: string, func: (...args: any[]) => void) => void;
  removeListener: (channel: string, func: (...args: any[]) => void) => void;
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}

// Function to check actual IP geolocation - uses REAL Electron main process API
const checkIPGeolocation = async (): Promise<{ country: string; ip: string; isAustralia: boolean }> => {
  try {
    // Use the real Electron API for IP checking
    if (window.electronAPI?.vpn?.checkIP) {
      try {
        // console.log('🔍 Making REAL IP geolocation check...');
        const result = await window.electronAPI.vpn.checkIP();
        
        return { 
          country: result.countryName, 
          ip: result.ip, 
          isAustralia: result.isAustralia 
        };
      } catch (error) {
        // console.warn('⚠️ Real IP check failed:', error);
        return { 
          country: 'Unknown', 
          ip: 'Failed to check', 
          isAustralia: false
        };
      }
    }
    
    // Fallback if Electron API is not available
    // console.warn('⚠️ Electron API not available for IP checking');
    return { 
      country: 'API Unavailable', 
      ip: 'Unknown', 
      isAustralia: false 
    };
  } catch (error) {
    // console.warn('⚠️ IP check failed:', error);
    return { 
      country: 'Error', 
      ip: 'Failed', 
      isAustralia: false 
    };
  }
};

export const useVPN = (userAccessLevel?: number, enabled: boolean = true) => {
  const [vpnStatus, setVpnStatus] = useState<VPNStatus>("disconnected");
  const [connection, setConnection] = useState<VPNConnection>({
    endpoint: "au-sydney-01.vpn.provider.com",
    location: "Sydney, Australia"
  });
  const [retryCount, setRetryCount] = useState(0);
  const [lastError, setLastError] = useState<string | null>(null);
  const [isCheckingStatus, setIsCheckingStatus] = useState(true); // Start as checking
  const [autoReconnectAttempts, setAutoReconnectAttempts] = useState(0);
  const [isAutoReconnecting, setIsAutoReconnecting] = useState(false);
  const [actualIP, setActualIP] = useState<string>('');
  const [actualCountry, setActualCountry] = useState<string>('');
  const [ipVerified, setIPVerified] = useState<boolean>(false);

  const connectVPN = async (): Promise<void> => {
    if (!enabled) return;
    setVpnStatus("connecting");
    setLastError(null);
    setIsAutoReconnecting(false);
    
    try {
      // console.log("🔌 Fast VPN connection attempt...");
      const success = await window.electronAPI?.vpn?.connect('wireguard');
      
      if (success) {
        setVpnStatus("connected");
        setRetryCount(0);
        setAutoReconnectAttempts(0);
        // console.log("✅ VPN Connected successfully - browsing enabled");

        // Do IP check in background for display info
        checkIPGeolocation().then(ipInfo => {
          setActualIP(ipInfo.ip);
          setActualCountry(ipInfo.country);
          setIPVerified(ipInfo.isAustralia);
          
          setConnection(prev => ({
            ...prev,
            ipAddress: ipInfo.ip,
            latency: Math.floor(Math.random() * 30) + 15
          }));
        });
      } else {
        throw new Error("VPN connection failed");
      }
    } catch (error) {
      // console.error("❌ VPN connection failed:", error);
      setLastError("Failed to connect to Australian VPN via WireGuard");
      setVpnStatus("failed");
    }
  };

  const disconnectVPN = async (): Promise<void> => {
    if (!enabled) return;
    // console.log("Disconnecting VPN...");
    setVpnStatus("disconnected");
    setAutoReconnectAttempts(0);
    setIsAutoReconnecting(false);
    setConnection(prev => ({
      ...prev,
      ipAddress: undefined,
      latency: undefined
    }));
  };

  // Auto-reconnect function
  const autoReconnectVPN = useCallback(async (): Promise<void> => {
    setIsAutoReconnecting(prev => {
      if (prev) return prev; // Already reconnecting
      return true;
    });
    
    setAutoReconnectAttempts(prev => prev + 1);

    try {
      // Use IPC to connect VPN via main process
      const success = await window.electronAPI?.vpn?.connect('wireguard');
      
      if (success) {
        setVpnStatus("connected");
        setRetryCount(0);
        setAutoReconnectAttempts(0);
        setIsAutoReconnecting(false);

        // Update connection info
        setConnection(prev => ({
          ...prev,
          ipAddress: "134.199.169.102",
          latency: Math.floor(Math.random() * 30) + 15
        }));
      } else {
        throw new Error("Auto-reconnection failed");
      }
    } catch (error) {
      setIsAutoReconnecting(false);
      
      // Use functional update to avoid dependency
      setAutoReconnectAttempts(prev => {
        if (prev >= 5) {
          setVpnStatus("failed");
          setLastError("Auto-reconnection failed after multiple attempts");
        }
        return prev;
      });
    }
  }, []); // No dependencies to break the loop

  // Fast VPN status check - prioritizes WireGuard status over IP geolocation
  const checkVPNStatus = useCallback(async (): Promise<void> => {
    if (!enabled) return;
    setIsCheckingStatus(true);
    try {
      // Check WireGuard status first (faster and more reliable)
      const status = await window.electronAPI?.vpn?.getStatus();
      
      if (status === 'connected') {
        // If WireGuard says connected, trust it immediately for speed
        setVpnStatus("connected");
        setLastError(null);
        setAutoReconnectAttempts(0);
        setIsAutoReconnecting(false);
        
        // Do IP check in background (non-blocking for speed)
        checkIPGeolocation().then(ipInfo => {
          setActualIP(ipInfo.ip);
          setActualCountry(ipInfo.country);
          setIPVerified(ipInfo.isAustralia);
          
          // Update connection info with actual IP
          setConnection(prev => ({
            ...prev,
            ipAddress: ipInfo.ip,
            latency: Math.floor(Math.random() * 30) + 15
          }));
        });
        
        return;
      }
      
      // If not connected, check IP location to confirm
      const ipInfo = await checkIPGeolocation();
      setActualIP(ipInfo.ip);
      setActualCountry(ipInfo.country);
      setIPVerified(ipInfo.isAustralia);
      
      if (status === 'disconnected' || !ipInfo.isAustralia) {
        setVpnStatus("disconnected");
        setLastError(ipInfo.isAustralia ? 
          "WireGuard VPN disconnected" : 
          `Not connected to Australian VPN. Current location: ${ipInfo.country}`);
        
        setConnection(prev => ({
          ...prev,
          ipAddress: ipInfo.ip,
          latency: undefined
        }));
        
      } else if (status === 'connecting') {
        setVpnStatus("connecting");
      } else {
        setVpnStatus("failed");
        setLastError(`VPN status error: ${status}`);
      }
    } catch (error) {
      setVpnStatus("failed");
      setLastError("Failed to check VPN status");
    } finally {
      setIsCheckingStatus(false);
    }
  }, []); // No dependencies to break the loop

  // Fast initial VPN check on mount (only when enabled)
  useEffect(() => {
    if (!enabled) return;
    let mounted = true;
    let retryTimeout: NodeJS.Timeout;
    let maxRetries = 3;
    let currentRetry = 0;

    const checkInitialStatus = async () => {
      if (!mounted) return;
      
      try {
        // Quick check if electronAPI is ready
        if (!window.electronAPI?.vpn?.getStatus) {
          if (currentRetry < maxRetries) {
            currentRetry++;
            retryTimeout = setTimeout(checkInitialStatus, 2000); // Longer delay between retries
          } else {
            setVpnStatus("failed");
            setLastError("VPN API not available after multiple retries");
          }
          return;
        }

        // Prioritize WireGuard status for speed
        const status = await window.electronAPI?.vpn?.getStatus();
        
        if (status === 'connected') {
          // Allow browsing immediately if WireGuard is connected
          setVpnStatus("connected");
          setLastError(null);
          setIsCheckingStatus(false);
          
          // Single IP check for display purposes
          const ipInfo = await checkIPGeolocation();
          setActualIP(ipInfo.ip);
          setActualCountry(ipInfo.country);
          setIPVerified(ipInfo.isAustralia);
          
          setConnection(prev => ({
            ...prev,
            ipAddress: ipInfo.ip,
            latency: Math.floor(Math.random() * 30) + 15
          }));
          
        } else if (status === 'connecting') {
          setVpnStatus("connecting");
          
          // Only retry if within limits
          if (currentRetry < maxRetries) {
            currentRetry++;
            retryTimeout = setTimeout(checkInitialStatus, 5000); // 5 second delay between checks
          } else {
            setVpnStatus("failed");
            setLastError("VPN connection timeout after multiple retries");
            setIsCheckingStatus(false);
          }
        } else {
          // If not connected, do a single IP check
          setVpnStatus("disconnected");
          setLastError("WireGuard VPN not connected");
          setIsCheckingStatus(false);
          
          const ipInfo = await checkIPGeolocation();
          setActualIP(ipInfo.ip);
          setActualCountry(ipInfo.country);
          setIPVerified(ipInfo.isAustralia);
          
          setConnection(prev => ({
            ...prev,
            ipAddress: ipInfo.ip,
            latency: undefined
          }));
        }
      } catch (error) {
        setVpnStatus("failed");
        setLastError("Failed to check initial VPN status");
        setIsCheckingStatus(false);
      }
    };

    // Start checking with initial delay
    retryTimeout = setTimeout(checkInitialStatus, 1000);

    return () => {
      mounted = false;
      clearTimeout(retryTimeout);
    };
  }, [enabled]);

  // Removed periodic VPN status checks; rely on initial check and user actions (and only when enabled)
  useEffect(() => {
    if (!enabled) return;
    // intentionally no interval
  }, [enabled]);

  // Auto-reconnect logic - triggered when status changes to disconnected (only when enabled)
  useEffect(() => {
    if (!enabled) return;
    if (vpnStatus === "disconnected") {
      const autoReconnectTimeout = setTimeout(() => {
        // Only attempt reconnect if we haven't exceeded retry limits
        if (autoReconnectAttempts < 3 && !isAutoReconnecting) {
          autoReconnectVPN();
        } else if (autoReconnectAttempts >= 3) {
          setVpnStatus("failed");
          setLastError("Auto-reconnection failed after maximum retries");
        }
      }, 10000); // Increased delay to 10 seconds between reconnection attempts

      return () => clearTimeout(autoReconnectTimeout);
    }
  }, [vpnStatus, enabled, autoReconnectAttempts, isAutoReconnecting, autoReconnectVPN]);

  return {
    vpnStatus,
    connection,
    connectVPN,
    disconnectVPN,
    checkVPNStatus,
    retryCount,
    lastError,
    isConnected: vpnStatus === "connected",
    isConnecting: vpnStatus === "connecting" || isAutoReconnecting,
    isCheckingStatus,
    hasFailed: vpnStatus === "failed",
    autoReconnectAttempts,
    isAutoReconnecting,
    actualIP,
    actualCountry,
    ipVerified,
    // Allow browsing if WireGuard is connected OR if user has Level 3 access (unrestricted)
    allowBrowsing: vpnStatus === "connected" || userAccessLevel === 3,
  };
}; 