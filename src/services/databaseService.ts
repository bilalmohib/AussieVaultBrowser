import {
  DatabaseService,
  User,
  UserSession,
  VPNConnection,
  supabase,
} from "@/lib/supabase";

// Generate unique device ID for this Electron instance
const DEVICE_ID = `electron-${Date.now()}-${Math.random()
  .toString(36)
  .substr(2, 9)}`;

export class SecureBrowserDatabaseService {
  private static currentUser: User | null = null;
  private static currentSession: UserSession | null = null;
  private static currentVPNConnection: VPNConnection | null = null;

  // Initialize user session when authentication succeeds
  static async initializeUserSession(
    email: string,
    name: string
  ): Promise<boolean> {
    try {
      // console.log('🔑 Initializing user session for:', email)
      // console.log('🔍 Database connection check - Supabase URL exists:', !!import.meta.env?.NEXT_PUBLIC_SUPABASE_URL)

      // Clear any existing user data to prevent stale data issues
      this.currentUser = null;
      
      // Direct database check if user exists to ensure we get fresh data
      const { data: existingUser, error: userError } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();
        
      if (userError && userError.code !== 'PGRST116') { // PGRST116 = no rows returned
        console.error("❌ Error checking if user exists:", userError);
        return false;
      }
      
      let user = existingUser;

      if (!user) {
        // console.log('📝 Creating new user in database')
        // Create user in database if doesn't exist
        // Get default access level from system settings or use 3 (highest level for best functionality)
        const { data: settingsData } = await supabase
          .from("system_settings")
          .select("value")
          .eq("key", "sharepoint_default_access_level")
          .single();
        
        const defaultAccessLevel = settingsData?.value ? parseInt(settingsData.value) : 3;
        
        const { data, error } = await supabase
          .from("users")
          .insert({
            email,
            name,
            access_level: defaultAccessLevel,
            status: "active",
            device_id: DEVICE_ID,
            vpn_required: true,
            can_edit_access_level: true, // Allow users to edit their access level
          })
          .select()
          .single();

        if (error) {
          // console.error('❌ Failed to create user:', error)
          return false;
        }
        user = data;
      }

      if (!user) {
        // console.error('❌ User data is null after creation/retrieval')
        return false;
      }

      this.currentUser = user;
      // console.log('✅ User session initialized:', {
      //   id: user.id,
      //   email: user.email,
      //   access_level: user.access_level
      // })

      // Create session record
      await this.createSession();

      return true;
    } catch (error) {
      // console.error('❌ Failed to initialize user session:', error)
      return false;
    }
  }

  // Create a new session record
  static async createSession(): Promise<UserSession | null> {
    if (!this.currentUser) {
      // console.warn('⚠️ Cannot create session: no current user')
      return null;
    }

    try {
      const sessionData = {
        user_id: this.currentUser.id,
        device_id: DEVICE_ID,
        login_time: new Date().toISOString(),
        ip_address: await this.getCurrentIP(),
        location: "Unknown", // Will be updated when VPN connects
        user_agent: navigator.userAgent,
        vpn_status: "disconnected" as const,
      };

      const session = await DatabaseService.createUserSession(sessionData);
      if (session) {
        this.currentSession = session;
        // console.log('✅ Session created:', session.id)
      }

      return session;
    } catch (error) {
      // console.error('❌ Failed to create session:', error)
      return null;
    }
  }

  // Update session when VPN status changes
  static async updateVPNStatus(
    connected: boolean,
    endpoint?: string,
    location?: string
  ) {
    if (!this.currentSession) return;

    try {
      const updates = {
        vpn_status: connected
          ? ("connected" as const)
          : ("disconnected" as const),
        vpn_endpoint: endpoint,
        location: location || this.currentSession.location,
      };

      await DatabaseService.updateUserSession(this.currentSession.id, updates);

      // Update local session data
      this.currentSession = { ...this.currentSession, ...updates };

      // console.log('✅ Session VPN status updated:', { connected, endpoint, location })
    } catch (error) {
      console.error("❌ Failed to update VPN status:", error);
    }
  }

  // Log VPN connection details
  static async logVPNConnection(
    endpoint: string,
    serverLocation: string,
    clientIP: string,
    vpnIP: string
  ) {
    // console.log('🔧 logVPNConnection called with:', { endpoint, serverLocation, clientIP, vpnIP })
    // console.log('🔧 Current user exists:', !!this.currentUser)
    // console.log('🔧 Current user details:', this.currentUser ? { id: this.currentUser.id, email: this.currentUser.email } : 'null')

    if (!this.currentUser) {
      console.error("❌ Cannot log VPN connection: no current user");
      return null;
    }

    try {
      // Get actual current IP if not provided
      let actualClientIP = clientIP;
      let actualVpnIP = vpnIP;

      if (clientIP === "127.0.0.1") {
        try {
          actualClientIP = await this.getCurrentIP();
          // For VPN IP, we know it's the Australian endpoint IP
          actualVpnIP = endpoint.split(":")[0]; // Extract IP from endpoint
        } catch (error) {
          console.warn("⚠️ Could not get actual IP addresses, using defaults");
        }
      }

      const connectionData = {
        user_id: this.currentUser.id,
        device_id: DEVICE_ID,
        endpoint,
        server_location: serverLocation,
        client_ip: actualClientIP,
        vpn_ip: actualVpnIP,
        status: "connected" as const,
      };

      // console.log('🔧 Calling DatabaseService.logVPNConnection with:', connectionData)
      const connection = await DatabaseService.logVPNConnection(connectionData);
      // console.log('🔧 VPN connection result:', connection)

      if (connection) {
        this.currentVPNConnection = connection;
        // console.log('✅ VPN connection logged successfully:', connection.id, {
        //   endpoint,
        //   client_ip: actualClientIP,
        //   vpn_ip: actualVpnIP,
        //   location: serverLocation
        // })
      } else {
        // console.error('❌ VPN connection logging failed: no connection returned')
      }

      return connection;
    } catch (error) {
      // console.error('❌ Failed to log VPN connection:', error)
      return null;
    }
  }

  // End VPN connection
  static async endVPNConnection() {
    if (!this.currentVPNConnection) return;

    try {
      await supabase
        .from("vpn_connections")
        .update({
          connection_end: new Date().toISOString(),
          status: "disconnected",
        })
        .eq("id", this.currentVPNConnection.id);

      // console.log('✅ VPN connection ended:', this.currentVPNConnection.id)
      this.currentVPNConnection = null;
    } catch (error) {
      // console.error('❌ Failed to end VPN connection:', error)
    }
  }

  // Log security events
  static async logSecurityEvent(
    eventType:
      | "download_blocked"
      | "domain_blocked"
      | "vpn_disconnected"
      | "unauthorized_access"
      | "session_timeout",
    description: string,
    severity: "low" | "medium" | "high" | "critical" = "medium",
    url?: string
  ) {
    try {
      const eventData = {
        user_id: this.currentUser?.id,
        device_id: DEVICE_ID,
        event_type: eventType,
        description,
        severity,
        url,
        ip_address: await this.getCurrentIP(),
        user_agent: navigator.userAgent,
      };

      const success = await DatabaseService.logSecurityEvent(eventData);
      if (success) {
        // console.log('🔒 Security event logged:', { eventType, severity, description })
      }

      return success;
    } catch (error) {
      // console.error('❌ Failed to log security event:', error)
      return false;
    }
  }

  // Log navigation attempts
  static async logNavigation(
    url: string,
    allowed: boolean,
    blockedReason?: string
  ) {
    if (!this.currentUser) return false;

    try {
      const domain = new URL(url).hostname;

      const navigationData = {
        user_id: this.currentUser.id,
        device_id: DEVICE_ID,
        url,
        domain,
        allowed,
        access_level: this.currentUser.access_level,
        vpn_active: this.currentSession?.vpn_status === "connected",
        blocked_reason: blockedReason,
      };

      const success = await DatabaseService.logNavigation(navigationData);
      if (success && !allowed) {
        // console.log('🚫 Navigation blocked and logged:', { url, domain, blockedReason })
      }

      return success;
    } catch (error) {
      // console.error('❌ Failed to log navigation:', error)
      return false;
    }
  }

  // End session when user logs out
  static async endSession() {
    if (!this.currentSession) return;

    try {
      const endTime = new Date().toISOString();
      const sessionDuration = Math.floor(
        (Date.now() - new Date(this.currentSession.login_time).getTime()) / 1000
      );

      await DatabaseService.updateUserSession(this.currentSession.id, {
        logout_time: endTime,
        session_duration: sessionDuration,
      });

      // console.log('✅ Session ended:', {
      //   sessionId: this.currentSession.id,
      //   duration: sessionDuration
      // })

      // Clean up
      this.currentSession = null;
      this.currentUser = null;

      // End VPN connection if active
      await this.endVPNConnection();
    } catch (error) {
      // console.error('❌ Failed to end session:', error)
    }
  }

  // Get current user data
  static getCurrentUser(): User | null {
    // First check if we already have a user in memory
    if (this.currentUser) {
      return this.currentUser;
    }

    // If not, try to get the user from localStorage as a fallback
    const storedAuth = localStorage.getItem("auth");
    if (storedAuth) {
      try {
        const user = JSON.parse(storedAuth);
        
        // Validate required user fields
        if (!user.id || !user.email || user.accessLevel === undefined) {
          console.error("❌ Invalid user data in localStorage, missing required fields");
          localStorage.removeItem("auth"); // Clear invalid data
          return null;
        }
        
        // Set as current user to maintain consistency
        this.currentUser = user;
        
        // Schedule a background refresh to ensure data is up to date
        this.scheduleUserDataRefresh(user.email);
        
        return user;
      } catch (error) {
        console.error("❌ Failed to parse stored user:", error);
        localStorage.removeItem("auth"); // Clear corrupted data
      }
    }
    
    return null;
  }
  
  // Schedule a background refresh of user data without blocking
  private static scheduleUserDataRefresh(email: string): void {
    // Use setTimeout to make this asynchronous and non-blocking
    setTimeout(async () => {
      try {
        // Fetch latest user data from database
        const { data, error } = await supabase
          .from("users")
          .select("*")
          .eq("email", email)
          .single();
          
        if (error || !data) {
          console.error("❌ Failed to refresh user data in background:", error);
          return;
        }
        
        // Check if the data is different from what we have
        if (this.currentUser && 
            (this.currentUser.access_level !== data.access_level || 
             this.currentUser.can_edit_access_level !== data.can_edit_access_level)) {
          console.log("🔄 User data updated from database");
          
          // Update current user
          this.currentUser = data;
          
          // Update localStorage
          const authUser = {
            id: data.id,
            name: data.name,
            email: data.email,
            accessLevel: data.access_level,
            avatar: undefined
          };
          localStorage.setItem("auth", JSON.stringify(authUser));
          
          // Show dialog for user confirmation instead of force reloading
          if (this.currentUser && this.currentUser.access_level !== data.access_level) {
            console.log("🔄 Access level changed, showing reload dialog");
            
            const oldLevel = this.currentUser.access_level;
            const newLevel = data.access_level;
            
            const message = `Your access level has been changed from Level ${oldLevel} to Level ${newLevel}. 
            The browser needs to reload to apply these changes.`;
            
            this.showReloadConfirmationDialog("Access Level Updated", message);
          }
        }
      } catch (error) {
        console.error("❌ Error in background refresh:", error);
      }
    }, 0);
  }
  
  // Refresh user data from the database
  static async refreshCurrentUser(): Promise<User | null> {
    if (!this.currentUser) {
      return null;
    }
    
    try {
      const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", this.currentUser.email)
        .single();
        
      if (error || !data) {
        console.error("❌ Failed to refresh user data:", error);
        return this.currentUser;
      }
      
      // Update the current user with fresh data from database
      this.currentUser = data;
      
      // Also update localStorage
      const authUser = {
        id: data.id,
        name: data.name,
        email: data.email,
        accessLevel: data.access_level,
        avatar: undefined
      };
      localStorage.setItem("auth", JSON.stringify(authUser));
      
      return this.currentUser;
    } catch (error) {
      console.error("❌ Error refreshing user data:", error);
      return this.currentUser;
    }
  }

  // Get current session data
  static getCurrentSession(): UserSession | null {
    return this.currentSession;
  }

  // Update user's last login time
  static async updateLastLogin() {
    if (!this.currentUser) return;

    try {
      await supabase
        .from("users")
        .update({ last_login: new Date().toISOString() })
        .eq("id", this.currentUser.id);

      // console.log('✅ Last login updated for user:', this.currentUser.email)
    } catch (error) {
      // console.error('❌ Failed to update last login:', error)
    }
  }

  // Helper function to get current IP (simplified)
  private static async getCurrentIP(): Promise<string> {
    try {
      // In Electron, we can get this from the main process
      // For now, return a placeholder
      return "127.0.0.1";
    } catch (error) {
      return "127.0.0.1";
    }
  }

  // Check if user exists and get their access level
  static async getUserAccessLevel(email: string): Promise<number> {
    try {
      const user = await DatabaseService.getCurrentUser(email);
      return user?.access_level || 1;
    } catch (error) {
      // console.error('❌ Failed to get user access level:', error)
      return 1; // Default to most restrictive
    }
  }

  // Monitor session health and VPN status
  static startSessionMonitoring() {
    // Monitor session and VPN status every 2 minutes
    setInterval(async () => {
      if (this.currentUser && this.currentSession) {
        try {
          // Check current VPN status
          const vpnStatus = await window.secureBrowser?.vpn.getStatus();
          const isVpnConnected = vpnStatus === "connected";

          // Update session heartbeat and VPN status
          const updates: any = {
            // Add a heartbeat timestamp or extend session
          };

          // Only update VPN status if it has changed
          if (
            this.currentSession.vpn_status !==
            (isVpnConnected ? "connected" : "disconnected")
          ) {
            updates.vpn_status = isVpnConnected ? "connected" : "disconnected";

            // console.log(`🔄 VPN status changed: ${this.currentSession.vpn_status} → ${updates.vpn_status}`);

            // Log the status change as a security event
            await this.logSecurityEvent(
              "vpn_disconnected",
              `VPN status changed to ${updates.vpn_status} during session monitoring`,
              isVpnConnected ? "low" : "high"
            );

            // If VPN disconnected, end current VPN connection record
            if (!isVpnConnected && this.currentVPNConnection) {
              await this.endVPNConnection();
            }
            // If VPN reconnected, create new VPN connection record
            else if (isVpnConnected && !this.currentVPNConnection) {
              const envConfigStr =
                await window.secureBrowser?.system.getEnvironment();
              const envConfig = envConfigStr ? JSON.parse(envConfigStr) : {};
              const endpoint =
                envConfig?.WIREGUARD_ENDPOINT || "134.199.169.102:59926";

              await this.logVPNConnection(
                endpoint,
                "Sydney, Australia",
                "127.0.0.1", // Will be resolved to actual IP
                "134.199.169.102"
              );
            }
          }

          if (Object.keys(updates).length > 0) {
            await DatabaseService.updateUserSession(
              this.currentSession.id,
              updates
            );
            // Update local session data
            this.currentSession = { ...this.currentSession, ...updates };
          }
        } catch (error) {
          // console.warn('⚠️ Session monitoring error:', error)
        }
      }
    }, 2 * 60 * 1000); // 2 minutes
  }

  // Get device ID for this session
  static getDeviceId(): string {
    return DEVICE_ID;
  }
  
  // Show a user-friendly dialog for reload confirmation
  static showReloadConfirmationDialog(title: string, message: string): void {
    // Create dialog container
    const dialogContainer = document.createElement('div');
    dialogContainer.style.position = 'fixed';
    dialogContainer.style.top = '0';
    dialogContainer.style.left = '0';
    dialogContainer.style.width = '100%';
    dialogContainer.style.height = '100%';
    dialogContainer.style.backgroundColor = 'rgba(0,0,0,0.5)';
    dialogContainer.style.display = 'flex';
    dialogContainer.style.alignItems = 'center';
    dialogContainer.style.justifyContent = 'center';
    dialogContainer.style.zIndex = '10000';
    
    // Create dialog box
    const dialogBox = document.createElement('div');
    dialogBox.style.backgroundColor = '#fff';
    dialogBox.style.borderRadius = '8px';
    dialogBox.style.padding = '20px';
    dialogBox.style.maxWidth = '450px';
    dialogBox.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    
    // Add content
    dialogBox.innerHTML = `
      <h3 style="margin-top: 0; font-size: 18px; color: #333;">${title}</h3>
      <p style="margin-bottom: 20px; color: #555;">${message}</p>
      <div style="display: flex; justify-content: flex-end; gap: 10px;">
        <button id="dialog-later" style="padding: 8px 16px; border: 1px solid #ddd; background: #f5f5f5; border-radius: 4px; cursor: pointer;">
          Later
        </button>
        <button id="dialog-reload" style="padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer;">
          Reload Now
        </button>
      </div>
    `;
    
    // Add to DOM
    dialogContainer.appendChild(dialogBox);
    document.body.appendChild(dialogContainer);
    
    // Set up event listeners
    document.getElementById('dialog-reload')?.addEventListener('click', () => {
      document.body.removeChild(dialogContainer);
      window.location.reload();
    });
    
    document.getElementById('dialog-later')?.addEventListener('click', () => {
      document.body.removeChild(dialogContainer);
    });
  }

  // Debug function to manually test VPN connection logging
  static async debugVPNConnectionLogging(): Promise<void> {
    // console.log('🔧 DEBUG: Manual VPN connection logging test')
    // console.log('🔧 Current user:', this.currentUser)
    // console.log('🔧 Current session:', this.currentSession)

    if (!this.currentUser) {
      // console.error('❌ DEBUG: No current user for VPN logging test')
      return;
    }

    try {
      await this.logVPNConnection(
        "134.199.169.102:59926",
        "Sydney, Australia (DEBUG TEST)",
        "127.0.0.1",
        "134.199.169.102"
      );

      // console.log('🔧 DEBUG: VPN connection logging test result:', result)
    } catch (error) {
      // console.error('❌ DEBUG: VPN connection logging test failed:', error)
    }
  }

  // Get user data with access level permissions
  static async getUserWithPermissions(email: string): Promise<{
    id: number;
    name: string;
    email: string;
    accessLevel: 1 | 2 | 3;
    canEditAccessLevel: boolean;
    vpnRequired: boolean;
    status: "active" | "suspended" | "inactive";
  } | null> {
    try {
      // console.log('🔍 Fetching user data with permissions for:', email)

      const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .eq("status", "active")
        .single();

      if (error) {
        // console.error('❌ Failed to fetch user data:', error)
        return null;
      }

      if (!data) {
        // console.log('⚠️ User not found in database:', email)
        return null;
      }

      const userData = {
        id: data.id,
        name: data.name,
        email: data.email,
        accessLevel: data.access_level as 1 | 2 | 3,
        canEditAccessLevel: data.can_edit_access_level ?? false,
        vpnRequired: data.vpn_required,
        status: data.status as "active" | "suspended" | "inactive",
      };

      // console.log('✅ User data fetched successfully:', {
      //   id: userData.id,
      //   name: userData.name,
      //   accessLevel: userData.accessLevel,
      //   canEditAccessLevel: userData.canEditAccessLevel
      // })

      return userData;
    } catch (error) {
      // console.error('❌ Error fetching user data:', error)
      return null;
    }
  }

  // Update user access level if user has permission
  static async updateUserAccessLevel(
    email: string,
    newAccessLevel: 1 | 2 | 3
  ): Promise<boolean> {
    try {
      // console.log('🔄 Attempting to update access level for:', email, 'to level:', newAccessLevel)

      // First check if user can edit their access level
      const userData = await this.getUserWithPermissions(email);
      if (!userData) {
        // console.error('❌ User not found for access level update')
        return false;
      }

      if (!userData.canEditAccessLevel) {
        // console.error('❌ User does not have permission to edit access level')
        return false;
      }

      const { error } = await supabase
        .from("users")
        .update({
          access_level: newAccessLevel,
          updated_at: new Date().toISOString(),
        })
        .eq("email", email);

      if (error) {
        // console.error('❌ Failed to update user access level:', error)
        return false;
      }

      // console.log('✅ User access level updated successfully')

      // Update current user if it's the same user
      if (this.currentUser && this.currentUser.email === email) {
        this.currentUser.access_level = newAccessLevel;
        
        // Also update localStorage to reflect new access level
        const storedAuth = localStorage.getItem("auth");
        if (storedAuth) {
          try {
            const authUser = JSON.parse(storedAuth);
            authUser.accessLevel = newAccessLevel;
            localStorage.setItem("auth", JSON.stringify(authUser));
            
            // Show dialog asking user permission to reload
            const message = `Your access level has been successfully changed to Level ${newAccessLevel}.
            The browser needs to reload to apply these changes.`;
            
            this.showReloadConfirmationDialog("Access Level Changed", message);
          } catch (error) {
            console.error("❌ Failed to update stored auth:", error);
          }
        }
      }

      return true;
    } catch (error) {
      // console.error('❌ Error updating user access level:', error)
      return false;
    }
  }
}
