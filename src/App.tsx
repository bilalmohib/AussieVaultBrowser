import { useEffect, useState } from "react";
import { vaultService } from "@/services/vaultService";
import { vpnService } from "@/services/vpnService";
import { SecureBrowserDatabaseService } from "@/services/databaseService";
import { ClerkLoginForm } from "@/components/auth/ClerkLoginForm";
import { Dashboard } from "@/components/layout/Dashboard";
import LoadingScreen from "@/components/ui/loading-screen";
import ErrorBoundary from "@/components/ui/error-boundary";
import { Toaster } from "@/components/ui/sonner";
import clerkAuth from "@/services/clerkService";

import ErrorDisplay, {
  ErrorInfo,
  VPNStatus,
  EnvironmentStatus,
} from "@/components/ui/error-display";
import { EnvironmentValidator } from "@/config/environment";
import BrowserWindow from "@/components/browser/BrowserWindow";
import { DownloadManager } from "@/components/downloads/DownloadManager";
import "./App.css";

function App() {
  return (
    <ErrorBoundary>
      <AppContent />
      <Toaster />
    </ErrorBoundary>
  );
}

function AppContent() {
  const [user, setUser] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  // Force loader immediately after successful login to avoid login screen flicker
  const [postAuthLoading, setPostAuthLoading] = useState(false);

  // Post-auth initialization only - no useVPN hook until after auth
  const [initStage, setInitStage] = useState<"vault" | "vpn" | "ready">(
    "vault"
  );
  const [errors, setErrors] = useState<ErrorInfo[]>([]);
  const [vpnStatusInfo, setVpnStatusInfo] = useState<VPNStatus | null>(null);
  const [envStatusInfo, setEnvStatusInfo] = useState<EnvironmentStatus | null>(
    null
  );
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [initProgress, setInitProgress] = useState(0);

  // VPN status only after auth - avoid useVPN hook triggering early checks
  const [postAuthVpnStatus, setPostAuthVpnStatus] = useState<
    "connected" | "connecting" | "disconnected" | "failed"
  >("disconnected");

  // Expose debug helpers - always call hooks (they bail internally if unauthenticated)
  useEffect(() => {
    (window as any).debugVPN =
      SecureBrowserDatabaseService.debugVPNConnectionLogging;
    (window as any).testVPNStatus = async () => vpnService.isConnected();
  }, []);

  // Defer environment + vault + VPN init until AFTER user authenticated
  useEffect(() => {
    if (!isAuthenticated || !user) return; // wait for login first

    // Clear any existing errors first
    setErrors([]);

    const initializePostAuth = async () => {
      try {
        setInitProgress(10);
        let envConfig: Record<string, string | undefined> = {};
        try {
          const envConfigStr = await window.secureBrowser?.system.getEnvironment();
          if (envConfigStr) {
            envConfig = JSON.parse(envConfigStr);
            const validation = EnvironmentValidator.validateEnvironment(envConfig);
            setEnvStatusInfo({
              loaded: true,
              valid: validation.isValid,
              errors: validation.errors,
              warnings: validation.warnings,
              config: {
                nodeEnv: envConfig.NODE_ENV,
                vpnProvider: envConfig.VPN_PROVIDER,
                wireguardEndpoint: envConfig.WIREGUARD_ENDPOINT,
                wireguardConfigPath: envConfig.WIREGUARD_CONFIG_PATH,
              },
            });
            if (!validation.isValid) {
              await SecureBrowserDatabaseService.logSecurityEvent(
                "unauthorized_access",
                "Invalid environment configuration detected",
                "critical"
              );
              setErrors([
                {
                  type: "environment",
                  title: "Environment Configuration Invalid",
                  message: "Configuration contains placeholder values or missing required settings",
                  details: validation.errors,
                  critical: true,
                  action: "Update your .env file with correct values",
                },
              ]);
              return;
            }
            if (validation.warnings.length > 0) {
              await SecureBrowserDatabaseService.logSecurityEvent(
                "unauthorized_access",
                `Environment configuration warnings: ${validation.warnings.join(", ")}`,
                "low"
              );
            }
          } else {
            throw new Error("No environment configuration received");
          }
        } catch (error) {
          await SecureBrowserDatabaseService.logSecurityEvent(
            "unauthorized_access",
            "Failed to load environment configuration",
            "critical"
          );
          setEnvStatusInfo({
            loaded: false,
            valid: false,
            errors: ["Unable to load environment configuration"],
            warnings: [],
            config: undefined,
          });
          setErrors([
            {
              type: "config",
              title: "Configuration Loading Failed",
              message: "Unable to load environment configuration",
              details: [
                "Check if .env file exists in project root",
                "Ensure NODE_ENV=development (not production)",
                "Verify all required environment variables are set",
                error instanceof Error ? error.message : "Unknown error",
              ],
              critical: true,
              action: "Check .env file and restart application",
            },
          ]);
          return;
        }

        setInitStage("vault");
        setInitProgress(40);
        try {
          await vaultService.initialize();
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : "Vault initialization failed";
          setVaultError(errorMessage);
          await SecureBrowserDatabaseService.logSecurityEvent(
            "unauthorized_access",
            `Vault initialization failed: ${errorMessage}`,
            "medium"
          );
        }

        setInitStage("vpn");
        setInitProgress(65);
        try {
          setPostAuthVpnStatus("connecting");
          let vpnConnected = await vpnService.isConnected();
          const maxRetries = 3;
          if (!vpnConnected) {
            let retryCount = 0;
            while (!vpnConnected && retryCount < maxRetries) {
              vpnConnected = await vpnService.connect();
              if (!vpnConnected && retryCount < maxRetries - 1) {
                await SecureBrowserDatabaseService.logSecurityEvent(
                  "vpn_disconnected",
                  `VPN connection attempt ${retryCount + 1} failed, retrying...`,
                  "medium"
                );
                await new Promise((r) => setTimeout(r, 2000));
              }
              retryCount++;
            }
          }

          setPostAuthVpnStatus(vpnConnected ? "connected" : "failed");
          setVpnStatusInfo({
            connected: vpnConnected,
            provider: envConfig?.VPN_PROVIDER || "wireguard",
            endpoint: envConfig?.WIREGUARD_ENDPOINT,
            location: "Australia",
            lastCheck: new Date(),
          });
          if (!vpnConnected) {
            await SecureBrowserDatabaseService.logSecurityEvent(
              "vpn_disconnected",
              "VPN connection failed after retries",
              "critical"
            );
            setErrors([
              {
                type: "vpn",
                title: "VPN Connection Failed",
                message: "Failed to establish VPN connection after multiple attempts",
                details: [
                  "Check WireGuard configuration",
                  "Ensure Australian endpoint reachable",
                  "Confirm local WireGuard service running",
                ],
                critical: true,
                action: "Connect WireGuard and retry",
              },
            ]);
            setPostAuthLoading(false);
            return;
          } else {
            await SecureBrowserDatabaseService.logSecurityEvent(
              "vpn_disconnected",
              "VPN successfully connected and initialized",
              "low"
            );
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : "VPN connection failed";
          await SecureBrowserDatabaseService.logSecurityEvent(
            "vpn_disconnected",
            `VPN connection error post-auth: ${errorMessage}`,
            "critical"
          );
          setErrors([
            {
              type: "vpn",
              title: "VPN Connection Error",
              message: errorMessage,
              details: [
                "Check network connection",
                "Verify WireGuard config file",
                "Ensure Australian VPS server running",
              ],
              critical: true,
              action: "Fix VPN configuration and retry",
            },
          ]);
          setPostAuthLoading(false);
          return;
        }

        setInitStage("ready");
        setInitProgress(100);
        setPostAuthLoading(false);
        await SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          "Post-auth services initialized",
          "low"
        );
      } catch (error) {
        await SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `Post-auth initialization failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          "critical"
        );
        setErrors([
          {
            type: "config",
            title: "Initialization Failed",
            message: "Post-auth initialization failed",
            details: [error instanceof Error ? error.message : "Unknown error"],
            critical: true,
            action: "Check configuration and restart",
          },
        ]);
        setPostAuthLoading(false);
      }
    };

    initializePostAuth();
  }, [isAuthenticated, user]);

  // CRITICAL: Show login form FIRST - absolutely nothing else before authentication
  if (!isAuthenticated || !user) {
    return (
      <ClerkLoginForm
        onAuthStart={() => {
          // Only set loading if not already set
          if (!postAuthLoading) {
            setPostAuthLoading(true);
          }
        }}
        disableAutoDetect={true}
        onAuthSuccess={(userData) => {
          // Prevent duplicate auth processing
          if (isAuthenticated && user && user.id === userData.id) {
            return;
          }
          
          setUser(userData);
          setIsAuthenticated(true);
          setInitStage("vault");
          setInitProgress(10);
        }}
        onAuthError={(error) => {
          console.log("Auth error:", error);
          // Reset loading state on error
          setPostAuthLoading(false);
        }}
      />
    );
  }

  const handleAccessLevelChange = async (newLevel: 1 | 2 | 3) => {
    if (user) {
      try {
        // Check if user has permission to edit access level
        if (user.canEditAccessLevel === false) {
          // console.error('❌ User does not have permission to edit access level');
          alert(
            "You do not have permission to change your access level. Please contact your administrator."
          );
          return;
        }

        // Show loading state while changing access level
        setInitStage("vpn");
        setInitProgress(50);

        // console.log(`🔄 Changing access level from ${user.accessLevel} to ${newLevel}...`);

        // Update access level in database
        const updateSuccess =
          await SecureBrowserDatabaseService.updateUserAccessLevel(
            user.email,
            newLevel
          );

        if (!updateSuccess) {
          throw new Error("Failed to update access level in database");
        }

        // Log access level change as security event
        await SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `User access level changed from ${user.accessLevel} to ${newLevel}`,
          "medium"
        );

        // Update user object with new access level
        const updatedUser = { ...user, accessLevel: newLevel };

        // Update localStorage with new access level
        localStorage.setItem("auth", JSON.stringify(updatedUser));

        // Small delay to show loading state
        await new Promise((resolve) => setTimeout(resolve, 1000));

        // Update state directly instead of forcing reload
        setUser(updatedUser);
        setInitStage("ready");
        setInitProgress(100);

        // Clear any existing errors
        setErrors([]);

        // console.log(`✅ Access level changed to ${newLevel} successfully`);
      } catch (error) {
        // console.error('❌ Failed to change access level:', error);

        // Log access level change failure
        await SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `Failed to change access level: ${
            error instanceof Error ? error.message : "Unknown error"
          }`,
          "medium"
        );

        // Show error to user
        alert(
          `Failed to change access level: ${
            error instanceof Error ? error.message : "Unknown error"
          }`
        );

        setInitStage("ready");
        setInitProgress(100);
      }
    }
  };

  // Enhanced logout to clean up database session
  const handleLogout = async () => {
    console.log("🔐 Logout button clicked - starting logout process");

    // 1) IMMEDIATELY reset UI state so login shows without waiting
    setUser(null);
    setIsAuthenticated(false);
    setPostAuthLoading(false);
    setErrors([]);
    setInitStage("vault");
    setInitProgress(0);

    // Clear local persisted auth state synchronously (including Clerk cache)
    try {
      localStorage.removeItem("auth");
      localStorage.removeItem("aussie_vault_auth_state");
      // Clear Clerk local state without network
      try { (clerkAuth as any).forceLocalSignOut?.(); } catch {}
    } catch {}

    // 2) Run cleanup tasks in background; do not block UI
    Promise.resolve()
      .then(async () => {
        try {
      await SecureBrowserDatabaseService.endSession();
        } catch {}
        try {
      await SecureBrowserDatabaseService.logSecurityEvent(
        "unauthorized_access",
        "User logged out",
        "low"
      );
        } catch {}

      try {
        await clerkAuth.signOut();
      } catch (clerkError) {
        console.error("❌ Clerk signOut failed:", clerkError);
      }

      // No main-process auth API; nothing to notify here
      try { /* noop */ } catch {}
      })
      .catch(() => {});
  };

  // If we've just authenticated, force loader overlay regardless of other states
  if (postAuthLoading) {
    const currentMessage = (() => {
      switch (initStage) {
        case "vault":
          return vaultError
            ? "Vault connection failed - continuing with reduced functionality"
            : "Connecting to secure credential vault...";
        case "vpn":
          return "Establishing secure VPN tunnel to Australia...";
        default:
          return "Preparing secure browser environment...";
      }
    })();

    return (
      <LoadingScreen
        stage={initStage}
        message={currentMessage}
        error={vaultError}
        progress={initProgress}
      />
    );
  }

  // ONLY show configuration errors after auth AND only if we are not fully ready AND user is authenticated
  if (isAuthenticated && user && errors.length > 0 && initStage !== "ready") {
    return (
      <ErrorDisplay
        errors={errors}
        vpnStatus={vpnStatusInfo || undefined}
        environmentStatus={envStatusInfo || undefined}
        user={{
                name: user.name,
                email: user.email,
                accessLevel: user.accessLevel,
                avatar: user.avatar,
        }}
        isAuthenticated={true}
        onRetry={() => {
          setErrors([]);
            setInitStage("vault");
            setInitProgress(0);
        }}
        onLogin={() => {
          // Force logout state to show login screen again
          setUser(null);
          setIsAuthenticated(false);
          setErrors([]);
        }}
        onLogout={handleLogout}
      />
    );
  }

  // Show post-auth loading during vault/VPN initialization (only if authenticated)
  if (isAuthenticated && user && initStage !== "ready") {
    const currentMessage = (() => {
      switch (initStage) {
        case "vault":
          return vaultError
            ? "Vault connection failed - continuing with reduced functionality"
            : "Connecting to secure credential vault...";
        case "vpn":
          return "Establishing secure VPN tunnel to Australia...";
        default:
          return "Preparing secure browser environment...";
      }
    })();

    return (
      <LoadingScreen
        stage={initStage}
        message={currentMessage}
        error={vaultError}
        progress={initProgress}
      />
    );
  }

  // Show main dashboard with browser
  return (
    <Dashboard
      user={user}
      vpnStatus={postAuthVpnStatus}
      onLogout={handleLogout}
      onAccessLevelChange={handleAccessLevelChange}
    >
      <BrowserWindow user={user} />
      <DownloadManager />
    </Dashboard>
  );
}

export default App;
