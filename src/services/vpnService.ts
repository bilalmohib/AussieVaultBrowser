import { getPlatformInfo } from "../utils/platform";
import { SecureBrowserDatabaseService } from "./databaseService";

export interface VPNStatus {
  connected: boolean;
  endpoint?: string;
  publicKey?: string;
  allowedIPs?: string[];
  lastHandshake?: Date;
  transferRx?: number;
  transferTx?: number;
  persistentKeepalive?: number;
}

export interface VPNConfig {
  provider: "wireguard" | "nordlayer" | "expressvpn";
  endpoint: string;
  configPath?: string;
  autoConnect: boolean;
  failClosed: boolean;
}

export class VPNService {
  private config: VPNConfig | null = null;
  private statusCheckInterval: NodeJS.Timeout | null = null;
  private connectionCallbacks: ((status: VPNStatus) => void)[] = [];

  constructor() {
    this.loadConfiguration();
  }

  private async loadConfiguration(): Promise<void> {
    try {
      // Get configuration from Electron main process
      if (typeof window !== "undefined" && window.secureBrowser) {
        const envConfig = await window.secureBrowser.system.getEnvironment();
        const env = JSON.parse(envConfig);

        this.config = {
          provider: env.VPN_PROVIDER || "wireguard",
          endpoint: env.WIREGUARD_ENDPOINT || "",
          configPath:
            env.WIREGUARD_CONFIG_PATH || "./config/wireguard-australia.conf",
          autoConnect: env.VPN_AUTO_CONNECT === "true",
          failClosed: env.VPN_FAIL_CLOSED === "true",
        };
      }
    } catch (error) {
      console.error("❌ Failed to load VPN configuration:", error);
      throw new Error("VPN configuration not available");
    }
  }

  async connect(): Promise<boolean> {
    if (!this.config) {
      throw new Error("VPN service not configured");
    }

    try {
      getPlatformInfo();
      // console.log(`🌐 Attempting VPN connection with ${this.config.provider} on ${platformInfo.displayName} ${platformInfo.emoji}...`);

      let connected = false;
      switch (this.config.provider) {
        case "wireguard":
          connected = await this.connectWireGuard();
          break;
        case "nordlayer":
          connected = await this.connectNordLayer();
          break;
        case "expressvpn":
          connected = await this.connectExpressVPN();
          break;
        default:
          throw new Error(`Unsupported VPN provider: ${this.config.provider}`);
      }

      if (connected) {
        // Log successful VPN connection to database
        await SecureBrowserDatabaseService.updateVPNStatus(
          true,
          this.config.endpoint,
          "Australia"
        );

        // Get current IP addresses for logging
        const clientIP = await this.getCurrentIP();
        const vpnIP = await this.getVPNIP();

        await SecureBrowserDatabaseService.logVPNConnection(
          this.config.endpoint,
          "Australia",
          clientIP,
          vpnIP
        );

        // console.log('✅ VPN connection logged to database');
      } else {
        // Log failed connection as security event
        await SecureBrowserDatabaseService.logSecurityEvent(
          "vpn_disconnected",
          `Failed to establish VPN connection to ${this.config.endpoint}`,
          "high"
        );
      }

      return connected;
    } catch (error) {
      // console.error('❌ VPN connection failed:', error);

      // Log VPN connection failure as critical security event
      await SecureBrowserDatabaseService.logSecurityEvent(
        "vpn_disconnected",
        `VPN connection failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        "critical"
      );

      this.notifyStatusChange({ connected: false });
      return false;
    }
  }

  async disconnect(): Promise<boolean> {
    try {
      let disconnected = false;
      if (this.config?.provider === "wireguard") {
        disconnected = await this.disconnectWireGuard();
      } else {
        // For other providers, implement specific disconnect logic
        disconnected = true;
      }

      if (disconnected) {
        // Update database with disconnection
        await SecureBrowserDatabaseService.updateVPNStatus(false);
        await SecureBrowserDatabaseService.endVPNConnection();

        // Log disconnection event
        await SecureBrowserDatabaseService.logSecurityEvent(
          "vpn_disconnected",
          "VPN disconnected by user request",
          "medium"
        );

        // console.log('🔌 VPN disconnected and logged to database');
        this.notifyStatusChange({ connected: false });
      }

      return disconnected;
    } catch (error) {
      // console.error('❌ VPN disconnect failed:', error);

      // Log disconnect failure
      await SecureBrowserDatabaseService.logSecurityEvent(
        "vpn_disconnected",
        `VPN disconnect failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        "high"
      );

      return false;
    }
  }

  async getStatus(): Promise<VPNStatus> {
    if (!this.config) {
      return { connected: false };
    }

    try {
      switch (this.config.provider) {
        case "wireguard":
          return await this.getWireGuardStatus();
        default:
          return { connected: false };
      }
    } catch (error) {
      // console.error('❌ Failed to get VPN status:', error);
      return { connected: false };
    }
  }

  async isConnected(): Promise<boolean> {
    const status = await this.getStatus();
    return status.connected;
  }

  onStatusChange(callback: (status: VPNStatus) => void): void {
    this.connectionCallbacks.push(callback);
  }

  removeStatusListener(callback: (status: VPNStatus) => void): void {
    const index = this.connectionCallbacks.indexOf(callback);
    if (index > -1) {
      this.connectionCallbacks.splice(index, 1);
    }
  }

  private notifyStatusChange(status: VPNStatus): void {
    this.connectionCallbacks.forEach((callback) => {
      try {
        callback(status);
      } catch (error) {
        // console.error('❌ Error in VPN status callback:', error);
      }
    });

    // Update database when status changes
    this.updateDatabaseStatus(status);
  }

  private async updateDatabaseStatus(status: VPNStatus): Promise<void> {
    try {
      await SecureBrowserDatabaseService.updateVPNStatus(
        status.connected,
        status.endpoint,
        status.connected ? "Australia" : undefined
      );
    } catch (error) {
      // console.warn('⚠️ Failed to update VPN status in database:', error);
    }
  }

  // WireGuard Implementation
  private async connectWireGuard(): Promise<boolean> {
    if (!this.config?.configPath) {
      throw new Error("WireGuard config path not specified");
    }

    try {
      // Use IPC to request VPN connection from main process (for security)
      if (typeof window !== "undefined" && window.secureBrowser) {
        // console.log('🔌 Requesting WireGuard connection from main process...');
        const success = await window.secureBrowser.vpn.connect("wireguard");

        if (success) {
          // console.log('✅ WireGuard VPN connected successfully');
          this.startStatusMonitoring();
          this.notifyStatusChange({
            connected: true,
            endpoint: this.config.endpoint,
          });
          return true;
        } else {
          // console.warn('⚠️ WireGuard connection failed - check main process logs for platform-specific instructions');
          this.notifyStatusChange({ connected: false });
          return false;
        }
      }

      throw new Error("Secure browser IPC not available");
    } catch (error) {
      const errorMessage = `WireGuard connection failed: ${
        error instanceof Error ? error.message : String(error)
      }`;
      // console.error('❌', errorMessage);
      this.notifyStatusChange({ connected: false });
      throw new Error(errorMessage);
    }
  }

  private async disconnectWireGuard(): Promise<boolean> {
    try {
      if (typeof window !== "undefined" && window.secureBrowser) {
        const success = await window.secureBrowser.vpn.disconnect();

        if (success) {
          this.stopStatusMonitoring();
          // console.log('🔌 WireGuard VPN disconnected');
          return true;
        }
      }

      return false;
    } catch (error) {
      // console.error('❌ WireGuard disconnect error:', error);
      return false;
    }
  }

  private async getWireGuardStatus(): Promise<VPNStatus> {
    try {
      // Get status from main process
      if (typeof window !== "undefined" && window.secureBrowser) {
        const statusString = await window.secureBrowser.vpn.getStatus();

        if (statusString === "connected") {
          return {
            connected: true,
            endpoint: this.config?.endpoint,
            // Additional status info would be parsed from wg show output
          };
        }
      }

      return { connected: false };
    } catch (error) {
      // console.error('❌ Failed to get WireGuard status:', error);
      return { connected: false };
    }
  }

  private startStatusMonitoring(): void {
    if (this.statusCheckInterval) {
      clearInterval(this.statusCheckInterval);
    }

    this.statusCheckInterval = setInterval(async () => {
      const status = await this.getStatus();

      // Check for unexpected disconnections
      if (!status.connected) {
        console.warn("⚠️ VPN disconnection detected during monitoring");
        await SecureBrowserDatabaseService.logSecurityEvent(
          "vpn_disconnected",
          "Unexpected VPN disconnection detected during monitoring",
          "high"
        );

        await SecureBrowserDatabaseService.updateVPNStatus(false);
        await SecureBrowserDatabaseService.endVPNConnection();
      }

      this.notifyStatusChange(status);
    }, 5000); // Check every 5 seconds
  }

  private stopStatusMonitoring(): void {
    if (this.statusCheckInterval) {
      clearInterval(this.statusCheckInterval);
      this.statusCheckInterval = null;
    }
  }

  // Placeholder implementations for other VPN providers
  private async connectNordLayer(): Promise<boolean> {
    throw new Error(
      "NordLayer integration not implemented. Please implement NordLayer API integration."
    );
  }

  private async connectExpressVPN(): Promise<boolean> {
    throw new Error(
      "ExpressVPN integration not implemented. Please implement ExpressVPN API integration."
    );
  }

  // Cleanup
  destroy(): void {
    this.stopStatusMonitoring();
    this.connectionCallbacks = [];
  }

  // Helper methods for IP detection
  private async getCurrentIP(): Promise<string> {
    try {
      // In Electron, we can get this from the main process or use a web service
      // For now, return a placeholder - you could implement actual IP detection
      return "192.168.1.100"; // Placeholder for actual client IP
    } catch (error) {
      // console.warn('⚠️ Failed to get current IP:', error);
      return "127.0.0.1";
    }
  }

  private async getVPNIP(): Promise<string> {
    try {
      // This should get the actual VPN IP when connected
      // For Australian VPN, return the actual server IP
      return "134.199.169.102"; // Your actual Australian VPN IP
    } catch (error) {
      // console.warn('⚠️ Failed to get VPN IP:', error);
      return "134.199.169.102";
    }
  }
}

// Singleton instance
export const vpnService = new VPNService();
