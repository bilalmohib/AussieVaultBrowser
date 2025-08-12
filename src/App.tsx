import { useVPN } from "@/hooks/useVPN";
import { useEffect, useState } from "react";
import { vaultService } from "@/services/vaultService";
import { vpnService } from "@/services/vpnService";
import { SecureBrowserDatabaseService } from "@/services/databaseService";
import { ClerkLoginForm } from "@/components/auth/ClerkLoginForm";
import { Dashboard } from "@/components/layout/Dashboard";
import LoadingScreen from "@/components/ui/loading-screen";
import ErrorBoundary from "@/components/ui/error-boundary";
import { Toaster } from "@/components/ui/sonner";
import { QueryProvider } from "@/providers/QueryProvider";
import clerkAuth from "@/services/clerkService";

import ErrorDisplay, { ErrorInfo, VPNStatus, EnvironmentStatus } from "@/components/ui/error-display";
import { EnvironmentValidator } from "@/config/environment";
import BrowserWindow from "@/components/browser/BrowserWindow";
import { DownloadManager } from "@/components/downloads/DownloadManager";
import "./App.css";

function App() {
  return (
    <ErrorBoundary>
      <QueryProvider>
        <AppContent />
        <Toaster />
      </QueryProvider>
    </ErrorBoundary>
  );
}

function AppContent() {
  const { vpnStatus } = useVPN();
  const [user, setUser] = useState<any>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  
  // Make debug functions available globally for testing
  useEffect(() => {
    (window as any).debugVPN = SecureBrowserDatabaseService.debugVPNConnectionLogging;
    (window as any).testVPNStatus = async () => {
      const status = await vpnService.isConnected();
      // console.log('🔧 DEBUG: VPN Status check result:', status);
      return status;
    };
  }, []);
  const [initStage, setInitStage] = useState<'auth' | 'vault' | 'vpn' | 'ready'>('auth');
  const [errors, setErrors] = useState<ErrorInfo[]>([]);
  const [vpnStatusInfo, setVpnStatusInfo] = useState<VPNStatus | null>(null);
  const [envStatusInfo, setEnvStatusInfo] = useState<EnvironmentStatus | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [initProgress, setInitProgress] = useState(0);

  // Initialize services in sequence
  useEffect(() => {
    const initializeServices = async () => {
      try {
        // Stage 1: Environment validation
        setInitStage('auth');
        setInitProgress(10);
        
        // Validate environment configuration first
        let envConfig: Record<string, string | undefined> = {};
        
        try {
          const envConfigStr = await window.secureBrowser?.system.getEnvironment();
          if (envConfigStr) {
            envConfig = JSON.parse(envConfigStr);
            // console.log('🔍 Environment config loaded:', {
            //   NODE_ENV: envConfig.NODE_ENV,
            //   VPN_PROVIDER: envConfig.VPN_PROVIDER,
            //   WIREGUARD_ENDPOINT: envConfig.WIREGUARD_ENDPOINT ? 'Set ✅' : 'Missing ❌'
            // });
            
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
                wireguardConfigPath: envConfig.WIREGUARD_CONFIG_PATH
              }
            });
            
            if (!validation.isValid) {
              // Log configuration error as security event
              await SecureBrowserDatabaseService.logSecurityEvent(
                'unauthorized_access',
                'Invalid environment configuration detected',
                'critical'
              );
              
              setErrors([{
                type: 'environment',
                title: 'Environment Configuration Invalid',
                message: 'Configuration contains placeholder values or missing required settings',
                details: validation.errors,
                critical: true,
                action: 'Update your .env file with correct values'
              }]);
              return;
            }
            
            if (validation.warnings.length > 0) {
              // console.warn('⚠️ Environment warnings:', validation.warnings);
              // Log warnings as low-severity security events
              await SecureBrowserDatabaseService.logSecurityEvent(
                'unauthorized_access',
                `Environment configuration warnings: ${validation.warnings.join(', ')}`,
                'low'
              );
            }
          } else {
            throw new Error('No environment configuration received');
          }
        } catch (error) {
          // Log configuration loading failure
          await SecureBrowserDatabaseService.logSecurityEvent(
            'unauthorized_access',
            'Failed to load environment configuration',
            'critical'
          );
          
          setEnvStatusInfo({
            loaded: false,
            valid: false,
            errors: ['Unable to load environment configuration'],
            warnings: [],
            config: undefined
          });
          
          setErrors([{
            type: 'config',
            title: 'Configuration Loading Failed',
            message: 'Unable to load environment configuration',
            details: [
              'Check if .env file exists in project root',
              'Ensure NODE_ENV=development (not production)',
              'Verify all required environment variables are set',
              error instanceof Error ? error.message : 'Unknown error'
            ],
            critical: true,
            action: 'Check .env file and restart application'
          }]);
          return;
        }
        
        // Auth is handled by Clerk service, no need to wait
        
        setInitProgress(25);
        
        // Stage 2: Vault initialization  
        setInitStage('vault');
        setInitProgress(50);
        
        try {
          await vaultService.initialize();
          // console.log('✅ Vault service initialized successfully');
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Vault initialization failed';
          setVaultError(errorMessage);
          // console.error('❌ Vault initialization failed:', error);
          
          // Log vault initialization failure
          await SecureBrowserDatabaseService.logSecurityEvent(
            'unauthorized_access',
            `Vault initialization failed: ${errorMessage}`,
            'medium'
          );
          
          // Only set as critical error if vault is required
          // For now, allow continuation without vault
        }
        
        // Stage 3: VPN initialization
        setInitStage('vpn');
        setInitProgress(75);
        
        // Real VPN connection with retry logic and proper error handling
        try {
          // First check if VPN is already connected (to avoid unnecessary reconnection attempts)
          // console.log('🔍 Checking existing VPN connection status...');
          let vpnConnected = await vpnService.isConnected();
          
          const maxRetries = 3;
          
          if (vpnConnected) {
            // console.log('✅ VPN is already connected, skipping connection attempt');
            
            // Update database with existing connection status
            await SecureBrowserDatabaseService.updateVPNStatus(
              true, 
              envConfig?.WIREGUARD_ENDPOINT, 
              'Australia'
            );
          } else {
            let retryCount = 0;
            
            // Try connecting with retries - don't show error immediately
            while (!vpnConnected && retryCount < maxRetries) {
              // console.log(`🔄 VPN connection attempt ${retryCount + 1}/${maxRetries}...`);
              
              // Use the enhanced VPN service that integrates with database
              vpnConnected = await vpnService.connect();
              
              if (!vpnConnected && retryCount < maxRetries - 1) {
                // console.log(`⏳ VPN connection attempt ${retryCount + 1} failed, retrying in 2 seconds...`);
                
                // Log retry attempt
                await SecureBrowserDatabaseService.logSecurityEvent(
                  'vpn_disconnected',
                  `VPN connection attempt ${retryCount + 1} failed, retrying...`,
                  'medium'
                );
                
                await new Promise(resolve => setTimeout(resolve, 2000));
              }
              retryCount++;
            }
          }
          
          setVpnStatusInfo({
            connected: vpnConnected,
            provider: envConfig?.VPN_PROVIDER || 'wireguard',
            endpoint: envConfig?.WIREGUARD_ENDPOINT,
            location: 'Australia',
            lastCheck: new Date()
          });
          
          if (!vpnConnected) {
            // Log final VPN connection failure
            await SecureBrowserDatabaseService.logSecurityEvent(
              'vpn_disconnected',
              `VPN connection failed after ${maxRetries} attempts`,
              'critical'
            );
            
            // Only show error after all retries failed
            // console.log(`❌ VPN connection failed after ${maxRetries} attempts`);

            setErrors([{
              type: 'vpn',
              title: 'VPN Connection Failed',
              message: 'Failed to establish VPN connection to Australian servers after multiple attempts',
              details: [
                'VPN connection is required for security compliance',
                'All browsing must be routed through Australian servers',
                'Check your WireGuard configuration and server status',
                'Ensure WireGuard GUI is running and tunnel is active'
              ],
              critical: true,
              action: 'Connect WireGuard and retry'
            }]);
            return;
          }

          // console.log('✅ VPN connected successfully');

          // Log successful VPN initialization
          await SecureBrowserDatabaseService.logSecurityEvent(
            'vpn_disconnected', // Note: We use vpn_disconnected type but with positive message
            'VPN successfully connected and initialized',
            'low'
          );
          
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'VPN connection failed';
          
          // Log VPN connection error
          await SecureBrowserDatabaseService.logSecurityEvent(
            'vpn_disconnected',
            `VPN connection error during startup: ${errorMessage}`,
            'critical'
          );
          
          setVpnStatusInfo({
            connected: false,
            provider: envConfig?.VPN_PROVIDER || 'wireguard',
            endpoint: envConfig?.WIREGUARD_ENDPOINT,
            location: 'Australia',
            lastCheck: new Date()
          });
          
          setErrors([{
            type: 'vpn',
            title: 'VPN Connection Error',
            message: errorMessage,
            details: [
              'VPN connection failed during startup',
              'Check your network connection',
              'Verify WireGuard configuration file',
              'Ensure your Australian VPS server is running',
              'Make sure WireGuard GUI is installed and running'
            ],
            critical: true,
            action: 'Fix VPN configuration and retry'
          }]);
          return;
        }
        
        // Stage 4: Ready
        setInitStage('ready');
        setInitProgress(100);
        
        // Log successful app initialization
        await SecureBrowserDatabaseService.logSecurityEvent(
          'unauthorized_access', // Using this type for positive security events
          'Secure browser application successfully initialized',
          'low'
        );
        
      } catch (error) {
        // console.error('❌ Service initialization failed:', error);
        
        // Log general initialization failure
        await SecureBrowserDatabaseService.logSecurityEvent(
          'unauthorized_access',
          `Application initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'critical'
        );
        
        setErrors([{
          type: 'config',
          title: 'Application Initialization Failed',
          message: 'Application initialization failed',
          details: [error instanceof Error ? error.message : 'Unknown error occurred'],
          critical: true,
          action: 'Check configuration and restart application'
        }]);
      }
    };

    initializeServices();
  }, []);

  // Monitor VPN status changes and log to database
  useEffect(() => {
    const handleVPNStatusChange = async () => {
      if (vpnStatus) {
        const isCurrentlyConnected = vpnStatus === 'connected';
        
        // Use functional update to avoid dependency on vpnStatusInfo
        setVpnStatusInfo(prev => {
          if (!prev) {
            return { connected: isCurrentlyConnected };
          }
          
          const wasConnected = prev.connected;
          
          // Only log if status actually changed
          if (isCurrentlyConnected !== wasConnected) {
            // Log async without blocking
            (async () => {
              if (isCurrentlyConnected) {
                await SecureBrowserDatabaseService.logSecurityEvent(
                  'vpn_disconnected', // Using this type but with positive message
                  'VPN connection restored',
                  'low'
                );
              } else {
                await SecureBrowserDatabaseService.logSecurityEvent(
                  'vpn_disconnected',
                  'VPN connection lost during session',
                  'high'
                );
              }
            })();
          }
          
          return { ...prev, connected: isCurrentlyConnected };
        });
      }
    };
    
    handleVPNStatusChange();
  }, [vpnStatus]);

  const handleAccessLevelChange = async (newLevel: 1 | 2 | 3) => {
    if (user) {
      try {
        // Check if user has permission to edit access level
        if (user.canEditAccessLevel === false) {
          // console.error('❌ User does not have permission to edit access level');
          alert('You do not have permission to change your access level. Please contact your administrator.');
          return;
        }

        // Show loading state while changing access level
        setInitStage('vpn');
        setInitProgress(50);
        
        // console.log(`🔄 Changing access level from ${user.accessLevel} to ${newLevel}...`);
        
        // Update access level in database
        const updateSuccess = await SecureBrowserDatabaseService.updateUserAccessLevel(user.email, newLevel);
        
        if (!updateSuccess) {
          throw new Error('Failed to update access level in database');
        }
        
        // Log access level change as security event
        await SecureBrowserDatabaseService.logSecurityEvent(
          'unauthorized_access',
          `User access level changed from ${user.accessLevel} to ${newLevel}`,
          'medium'
        );
        
        // Update user object with new access level
        const updatedUser = { ...user, accessLevel: newLevel };
        
        // Update localStorage with new access level
        localStorage.setItem("auth", JSON.stringify(updatedUser));
        
        // Small delay to show loading state
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Update state directly instead of forcing reload
        setUser(updatedUser);
        setInitStage('ready');
        setInitProgress(100);
        
        // Clear any existing errors
        setErrors([]);

        // console.log(`✅ Access level changed to ${newLevel} successfully`);

      } catch (error) {
        // console.error('❌ Failed to change access level:', error);

        // Log access level change failure
        await SecureBrowserDatabaseService.logSecurityEvent(
          'unauthorized_access',
          `Failed to change access level: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'medium'
        );
        
        // Show error to user
        alert(`Failed to change access level: ${error instanceof Error ? error.message : 'Unknown error'}`);
        
        setInitStage('ready');
        setInitProgress(100);
      }
    }
  };

  // Show error screen if initialization failed
  if (errors.length > 0) {
    // Check if errors are critical (require reload) or can be cleared
    const hasCriticalErrors = errors.some(error => error.critical || error.type === 'config');
    
    return (
      <ErrorDisplay
        errors={errors}
        vpnStatus={vpnStatusInfo || undefined}
        environmentStatus={envStatusInfo || undefined}
        onRetry={() => {
          // console.log('🔄 Retry clicked - clearing errors without reload for non-critical issues');
          setErrors([]);
          
          // Only reload for critical errors, otherwise just retry initialization
          if (hasCriticalErrors) {
            // console.log('⚠️ Critical error detected - performing full reload');
            window.location.reload();
          } else {
            // console.log('✅ Non-critical error - retrying without reload');
            setInitStage('auth');
            setInitProgress(0);
            // Re-run initialization without reload
            // The useEffect will handle re-initialization when initStage changes
          }
        }}
        onOpenSettings={() => {
          // console.log('Opening settings...');
          // TODO: Implement settings modal
        }}
      />
    );
  }

  // Show loading screen during initialization
  if (initStage !== 'ready') {
    const currentMessage = (() => {
      switch (initStage) {
        case 'auth':
          return 'Validating configuration and starting secure browser environment...';
        case 'vault':
          return vaultError ? 'Vault connection failed - continuing with reduced functionality' : 'Connecting to secure credential vault...';
        case 'vpn':
          return 'Establishing secure VPN tunnel to Australia...';
        default:
          return 'Initializing...';
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

  // Show login form if not authenticated
  if (!isAuthenticated || !user) {
    return (
      <ClerkLoginForm 
        onAuthSuccess={async (userData) => {
          // console.log('✅ User authenticated via Clerk:', userData);

          // Initialize database session for the authenticated user
          try {
            // console.log('🔑 Initializing database session for Clerk user...');
            const sessionSuccess = await SecureBrowserDatabaseService.initializeUserSession(
              userData.email, 
              userData.name
            );
            
            if (sessionSuccess) {
              // console.log('✅ Database session initialized successfully');
              
              // Now that we have a session, update VPN status if connected
              try {
                const vpnConnected = await vpnService.isConnected();
                // console.log('🔍 Checking VPN status after session creation:', vpnConnected);

                if (vpnConnected) {
                  // Get current environment config
                  const envConfigStr = await window.secureBrowser?.system.getEnvironment();
                  const currentEnvConfig = envConfigStr ? JSON.parse(envConfigStr) : {};
                  const endpoint = currentEnvConfig?.WIREGUARD_ENDPOINT || '134.199.169.102:59926';
                  
                  // Update session with VPN status
                  await SecureBrowserDatabaseService.updateVPNStatus(
                    true,
                    endpoint,
                    'Australia'
                  );
                  
                  // Create VPN connection record for admin panel monitoring
                  await SecureBrowserDatabaseService.logVPNConnection(
                    endpoint,
                    'Sydney, Australia',
                    '127.0.0.1', // Will be updated with actual client IP
                    '134.199.169.102' // VPN IP
                  );
                  
                  // console.log('✅ VPN status synchronized to database');
                } else {
                  // console.log('⚠️ VPN not connected during session initialization');
                }
              } catch (error) {
                // console.error('❌ Failed to sync VPN status after session creation:', error);
              }
              
              // Start session monitoring
              SecureBrowserDatabaseService.startSessionMonitoring();
            } else {
              // console.warn('⚠️ Database session initialization failed, but continuing with authentication');
              // Log the failure but don't block authentication
              await SecureBrowserDatabaseService.logSecurityEvent(
                'unauthorized_access',
                `Database session init failed for ${userData.email} - continuing without DB tracking`,
                'medium'
              );
            }
          } catch (error) {
            // console.error('❌ Failed to initialize database session:', error);
            // Log the error but don't block authentication
            await SecureBrowserDatabaseService.logSecurityEvent(
              'unauthorized_access',
              `Database session init error for ${userData.email}: ${error instanceof Error ? error.message : 'Unknown error'}`,
              'high'
            );
          }
          
          // Set authentication state
          setUser(userData);
          setIsAuthenticated(true);
        }}
        onAuthError={(error) => {
          // console.error('❌ Clerk authentication failed:', error);
          setErrors([{
            type: 'config',
            title: 'Authentication Failed',
            message: error,
            details: ['Check your internet connection', 'Verify Clerk configuration'],
            critical: false
          }]);
        }}
      />
    );
  }

  // Enhanced logout to clean up database session
  const handleLogout = async () => {
    try {
      // End database session before logout
      await SecureBrowserDatabaseService.endSession();
      
      // Log logout event
      await SecureBrowserDatabaseService.logSecurityEvent(
        'unauthorized_access',
        'User logged out',
        'low'
      );
      
      // Sign out from Clerk
      await clerkAuth.signOut();
      
      // Clear local state
      setUser(null);
      setIsAuthenticated(false);

      // console.log('✅ User logged out successfully');
    } catch (error) {
      // console.error('❌ Failed to clean up session during logout:', error);
      // Still proceed with logout even if database cleanup fails
      setUser(null);
      setIsAuthenticated(false);
    }
  };

  // Show main dashboard with browser
  return (
    <Dashboard
      user={user}
      vpnStatus={vpnStatus}
      onLogout={handleLogout}
      onAccessLevelChange={handleAccessLevelChange}
    >
      <BrowserWindow user={user} />
      <DownloadManager />
    </Dashboard>
  );
}

export default App;
