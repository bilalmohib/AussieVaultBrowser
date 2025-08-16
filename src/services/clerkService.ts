import { Clerk } from '@clerk/clerk-js';
import type { ClerkUser, AuthState } from '../types/clerk';

class ClerkAuthService {
  private clerk: Clerk | null = null;
  private initializationPromise: Promise<void> | null = null;
  private authStateCallbacks: ((state: AuthState) => void)[] = [];
  
  // 🔐 SINGLETON AUTH STATE: Global authentication state shared between windows
  private static globalAuthState: AuthState = {
    user: null,
    isLoaded: false,
    isSignedIn: false
  };
  
  // 🔐 STATIC INITIALIZATION FLAG: Prevent multiple initializations across windows
  private static isGloballyInitialized = false;
  private static globalInitPromise: Promise<void> | null = null;
  
  // 🔐 PERSISTENCE KEY: LocalStorage key for auth state persistence
  private static readonly AUTH_STATE_KEY = 'aussie_vault_auth_state';
  
  // 🔐 LOAD PERSISTED STATE: Load authentication state from localStorage
  private static loadPersistedAuthState(): void {
    try {
      const persistedState = localStorage.getItem(ClerkAuthService.AUTH_STATE_KEY);
      if (persistedState) {
        const parsed = JSON.parse(persistedState);
        if (parsed && parsed.isSignedIn && parsed.user) {
          // console.log('✅ Loaded persisted authentication state from localStorage');
          ClerkAuthService.globalAuthState = parsed;
        }
      }
    } catch (error) {
      // console.warn('⚠️ Failed to load persisted auth state:', error);
    }
  }
  
  // 🔐 PERSIST STATE: Save authentication state to localStorage
  private static persistAuthState(state: AuthState): void {
    try {
      if (state.isSignedIn && state.user) {
        localStorage.setItem(ClerkAuthService.AUTH_STATE_KEY, JSON.stringify(state));
        // console.log('💾 Authentication state persisted to localStorage');
      } else {
        localStorage.removeItem(ClerkAuthService.AUTH_STATE_KEY);
        // console.log('🗑️ Authentication state cleared from localStorage');
      }
    } catch (error) {
      // console.warn('⚠️ Failed to persist auth state:', error);
    }
  }
  
  async initialize(): Promise<void> {
    // 🔐 LOAD PERSISTED STATE: Load any existing authentication from localStorage
    ClerkAuthService.loadPersistedAuthState();
    
    // 🔐 CHECK GLOBAL INITIALIZATION: If already initialized globally, just set up local listeners
         if (ClerkAuthService.isGloballyInitialized && this.clerk) {
       // console.log('✅ Clerk already initialized globally - setting up window listeners');
       
       // Immediately notify with current state
       this.notifyAuthStateChange(ClerkAuthService.globalAuthState);
       return;
     }
    
    // 🔐 SINGLETON PATTERN: Only allow one initialization across all windows
         if (ClerkAuthService.globalInitPromise) {
       // console.log('🔄 Waiting for global Clerk initialization to complete...');
       await ClerkAuthService.globalInitPromise;
       this.notifyAuthStateChange(ClerkAuthService.globalAuthState);
       return;
     }
    
    if (this.initializationPromise) {
      await this.initializationPromise;
      return;
    }

    // 🔐 START GLOBAL INITIALIZATION: This window will handle the initialization
    // console.log('🔄 Starting global Clerk initialization...');
    ClerkAuthService.globalInitPromise = this.performInitialization();
    this.initializationPromise = ClerkAuthService.globalInitPromise;
    
    await ClerkAuthService.globalInitPromise;
  }
  
  private async performInitialization(): Promise<void> {
    try {
      // Get publishable key from database using config-manager
      let publishableKey = '';
      
      try {
        // Import config-manager dynamically to avoid circular dependencies
        const { getConfig } = await import('../utils/config-manager');
        publishableKey = await getConfig('NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY', '');
        
              // If not found in database, fall back to environment variables (only for development)
      if (!publishableKey) {
        publishableKey = import.meta.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || '';
        console.log('WARNING: Using local environment variable for Clerk publishable key because database value not found');
        console.log('This may indicate that use_database_env_variables=true but NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY is not in the database');
      }
      } catch (error) {
        console.error('Failed to get Clerk key from database:', error);
        // Fall back to environment variables as last resort
        publishableKey = import.meta.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || '';
        console.log('WARNING: Using local environment variable for Clerk publishable key due to database error');
        console.log('This is a fallback mechanism and may indicate database connectivity issues');
      }
      
      if (!publishableKey) {
        throw new Error('Clerk publishable key is required but not found in database or environment variables');
      }

      // 🔐 CHECK FOR EXISTING AUTH: Look for existing Clerk session in localStorage
      const existingSession = localStorage.getItem('__clerk_db_jwt') || 
                            localStorage.getItem('__clerk_client_jwt') ||
                            sessionStorage.getItem('__clerk_db_jwt');

      // console.log('🔍 Checking for existing authentication state...');
      // console.log('🔍 Local storage keys:', Object.keys(localStorage));
      // console.log('🔍 Found existing session token:', !!existingSession);

      if (existingSession) {
        // console.log('🔍 Found existing Clerk session, initializing with existing state...');
      } else {
        // console.log('🔍 No existing session found, user will need to authenticate');
      }

      // Initialize Clerk using the constructor with OAuth popup configuration
      this.clerk = new Clerk(publishableKey);
      await this.clerk.load({
        // Configure OAuth to use popups in Electron
        allowedRedirectOrigins: [window.location.origin],
        // Enable popup mode for OAuth
        signInFallbackRedirectUrl: window.location.origin,
        signUpFallbackRedirectUrl: window.location.origin,
        // 🔐 FORCE SHARED SESSION: Ensure Clerk checks for existing sessions
        // Force immediate session loading from storage
        standardBrowser: true
      });

      // Set up auth state listener using proper Clerk listener pattern
      this.clerk.addListener((resources) => {
        const newState = {
          user: resources.user as ClerkUser | null,
          isLoaded: true,
          isSignedIn: !!resources.session
        };
        
        // 🔐 UPDATE GLOBAL STATE: Sync across all windows
        ClerkAuthService.globalAuthState = newState;
        ClerkAuthService.persistAuthState(newState);
        this.notifyAuthStateChange(newState);
      });

      // 🔐 FORCE SESSION SYNC: Immediately check if user is already signed in
      if (this.clerk.user && this.clerk.session) {
        // console.log('✅ Found existing authentication session for:', this.clerk.user.primaryEmailAddress?.emailAddress);
        const initialState = {
          user: this.clerk.user as unknown as ClerkUser | null,
          isLoaded: true,
          isSignedIn: true
        };
        
        ClerkAuthService.globalAuthState = initialState;
        ClerkAuthService.persistAuthState(initialState);
        this.notifyAuthStateChange(initialState);
      }

             // 🔐 MARK AS GLOBALLY INITIALIZED
       ClerkAuthService.isGloballyInitialized = true;
       // console.log('✅ Clerk authentication initialized globally');
    } catch (error) {
      // console.error('❌ Failed to initialize Clerk:', error);
      ClerkAuthService.globalInitPromise = null; // Reset on failure
      throw error;
    }
  }

  async signIn(): Promise<void> {
    if (!this.clerk) throw new Error('Clerk not initialized');

    try {
      await this.clerk.openSignIn({        
        redirectUrl: window.location.origin,
        // Force popup mode for OAuth providers in Electron
        appearance: {
          elements: {
            socialButtonsBlockButton: {
              '&:hover': {
                backgroundColor: '#f5f5f5'
              }
            }
          }
        },
        // Configure OAuth to work better in Electron
        routing: 'hash'
      });
    } catch (error) {
      // console.error('❌ Sign in failed:', error);
      throw error;
    }
  }

  async signUp(): Promise<void> {
    if (!this.clerk) throw new Error('Clerk not initialized');

    try {
      await this.clerk.openSignUp({
        redirectUrl: window.location.origin
      });
    } catch (error) {
      console.error('❌ Sign up failed:', error);
      throw error;
    }
  }

  async signOut(): Promise<void> {
    if (!this.clerk) throw new Error('Clerk not initialized');

    try {
      await this.clerk.signOut();
      
      // 🔐 CLEAR GLOBAL STATE: Reset authentication across all windows
      const clearedState = {
        user: null,
        isLoaded: true,
        isSignedIn: false
      };
      ClerkAuthService.globalAuthState = clearedState;
      ClerkAuthService.persistAuthState(clearedState);
      
      // 🔐 RESET GLOBAL INITIALIZATION: Allow re-initialization after sign out
      ClerkAuthService.isGloballyInitialized = false;
      ClerkAuthService.globalInitPromise = null;

      // console.log('✅ User signed out successfully');
    } catch (error) {
      // console.error('❌ Sign out failed:', error);
      throw error;
    }
  }

  // Optional helper to clear local state without calling network
  forceLocalSignOut(): void {
    const clearedState = { user: null, isLoaded: true, isSignedIn: false };
    ClerkAuthService.globalAuthState = clearedState as any;
    ClerkAuthService.persistAuthState(clearedState as any);
    ClerkAuthService.isGloballyInitialized = false;
    ClerkAuthService.globalInitPromise = null;
    this.authStateCallbacks.forEach(cb => {
      try { cb(clearedState as any); } catch {}
    });
  }

  // 🔐 ENHANCED METHOD: Force authentication state refresh for new windows
  async refreshAuthenticationState(): Promise<AuthState> {
    if (!this.clerk) throw new Error('Clerk not initialized');

    try {
      // 🔐 RETURN GLOBAL STATE: If we have global auth state, return it immediately
      if (ClerkAuthService.globalAuthState.isSignedIn) {
        // console.log('🔄 Returning cached global authentication state');
        this.notifyAuthStateChange(ClerkAuthService.globalAuthState);
        return ClerkAuthService.globalAuthState;
      }
      
      // Force Clerk to reload session from storage
      await this.clerk.load();
      
      const currentState = {
        user: this.clerk.user as unknown as ClerkUser | null,
        isLoaded: true,
        isSignedIn: !!this.clerk.session
      };

      // 🔐 UPDATE GLOBAL STATE
      ClerkAuthService.globalAuthState = currentState;
      ClerkAuthService.persistAuthState(currentState);
      
      // Notify listeners of current state
      this.notifyAuthStateChange(currentState);

      // console.log('🔄 Authentication state refreshed:', {
      //   isSignedIn: currentState.isSignedIn,
      //   userEmail: currentState.user?.emailAddresses?.[0]?.emailAddress
      // });

      return currentState;
    } catch (error) {
      // console.error('❌ Failed to refresh authentication state:', error);
      throw error;
    }
  }
  
  // 🔐 NEW METHOD: Get current global auth state without initialization
  getCurrentAuthState(): AuthState {
    return ClerkAuthService.globalAuthState;
  }
  
  // 🔐 NEW METHOD: Check if any window has authentication
  isGloballyAuthenticated(): boolean {
    return ClerkAuthService.globalAuthState.isSignedIn;
  }

  getCurrentUser(): ClerkUser | null {
    // 🔐 USE CACHED GLOBAL STATE: If we have cached user data, use it first
    if (ClerkAuthService.globalAuthState.isSignedIn && ClerkAuthService.globalAuthState.user) {
      return ClerkAuthService.globalAuthState.user;
    }
    
    // Fallback to Clerk instance if available
    if (!this.clerk || !this.clerk.user) return null;
    
    // Convert Clerk's UserResource to our ClerkUser interface
    const clerkUser = this.clerk.user;
    return {
      id: clerkUser.id,
      emailAddresses: clerkUser.emailAddresses || [],
      firstName: clerkUser.firstName,
      lastName: clerkUser.lastName,
      imageUrl: clerkUser.imageUrl || '',
      publicMetadata: clerkUser.publicMetadata,
      createdAt: clerkUser.createdAt ? new Date(clerkUser.createdAt).getTime() : Date.now(),
      lastSignInAt: clerkUser.lastSignInAt ? new Date(clerkUser.lastSignInAt).getTime() : null,
    };
  }

  isSignedIn(): boolean {
    // 🔐 USE GLOBAL STATE: Check global auth state first
    if (ClerkAuthService.globalAuthState.isSignedIn) {
      return true;
    }
    
    // Fallback to Clerk instance
    return !!this.clerk?.session;
  }

  isLoaded(): boolean {
    // 🔐 USE GLOBAL STATE: Check if globally loaded
    if (ClerkAuthService.globalAuthState.isLoaded) {
      return true;
    }
    
    // Fallback to Clerk instance
    return !!this.clerk?.loaded;
  }

  getUserAccessLevel(): number {
    const user = this.getCurrentUser();
    return (user?.publicMetadata as { accessLevel?: number })?.accessLevel || 1;
  }

  onAuthStateChange(callback: (state: AuthState) => void): void {
    this.authStateCallbacks.push(callback);
  }

  removeAuthStateListener(callback: (state: AuthState) => void): void {
    const index = this.authStateCallbacks.indexOf(callback);
    if (index > -1) {
      this.authStateCallbacks.splice(index, 1);
    }
  }

  private notifyAuthStateChange(state: AuthState): void {
    this.authStateCallbacks.forEach(callback => callback(state));
  }

  // Get user email for SharePoint integration
  getUserEmail(): string | null {
    const user = this.getCurrentUser();
    return user?.emailAddresses?.[0]?.emailAddress || null;
  }

  // Get user display name
  getUserDisplayName(): string {
    const user = this.getCurrentUser();
    if (!user) return 'User';
    
    const firstName = user.firstName || '';
    const lastName = user.lastName || '';
    const fullName = `${firstName} ${lastName}`.trim();
    
    if (fullName) return fullName;
    
    // Fallback to email username
    const email = this.getUserEmail();
    if (email) {
      return email.split('@')[0];
    }
    
    return 'User';
  }
}

// Export singleton instance
export const clerkAuth = new ClerkAuthService();
export default clerkAuth; 