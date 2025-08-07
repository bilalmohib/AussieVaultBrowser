import React, { useState, useEffect } from "react";
import { Button } from "../ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../ui/card";
import { Badge } from "../ui/badge";
import { Separator } from "../ui/separator";
import { LoadingScreen } from "../ui/loading-screen";
import { ErrorDisplay } from "../ui/error-display";
import clerkAuth from "../../services/clerkService";
import { SecureBrowserDatabaseService } from "../../services/databaseService";
import type { AuthState } from "../../types/clerk";
import { Shield, Users, Lock, Chrome, Globe } from "lucide-react";

interface ClerkLoginFormProps {
  onAuthSuccess: (user: any) => void;
  onAuthError: (error: string) => void;
}

export const ClerkLoginForm: React.FC<ClerkLoginFormProps> = ({
  onAuthSuccess,
  onAuthError,
}) => {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isLoaded: false,
    isSignedIn: false,
  });
  const [isInitializing, setIsInitializing] = useState(true);
  const [initError, setInitError] = useState<string | null>(null);
  const [isSigningIn, setIsSigningIn] = useState(false);
  const [isSigningUp, setIsSigningUp] = useState(false);

  useEffect(() => {
    const initializeClerk = async () => {
      try {
        setIsInitializing(true);
        setInitError(null);

        // 🔐 CHECK GLOBAL AUTH STATE FIRST: If user is already authenticated globally, use that
        // console.log('🔍 Checking for existing global authentication state...');
        const globalAuthState = clerkAuth.getCurrentAuthState();

        if (globalAuthState.isSignedIn && globalAuthState.user) {
          // console.log('✅ Found existing global authentication - user already signed in!');
          setAuthState(globalAuthState);

          // Notify parent immediately with existing auth
          try {
            // 🔐 GET EMAIL FROM CACHED STATE: Use cached user data directly
            const userEmail =
              globalAuthState.user.emailAddresses?.[0]?.emailAddress;
            if (!userEmail) {
              onAuthError("No email address found for this user");
              return;
            }
            // console.log('🔍 Using cached user data for:', userEmail);

            // Fetch user data from database with permissions
            const dbUserData =
              await SecureBrowserDatabaseService.getUserWithPermissions(
                userEmail
              );

            if (dbUserData) {
              // console.log('✅ Database user data loaded from cache:', dbUserData);
              onAuthSuccess({
                id: globalAuthState.user.id,
                dbId: dbUserData.id,
                name: dbUserData.name,
                email: dbUserData.email,
                accessLevel: dbUserData.accessLevel,
                canEditAccessLevel: dbUserData.canEditAccessLevel,
              });
            } else {
              // console.warn('⚠️ User not found in database, using Clerk defaults from cache');
              // 🔐 USE CACHED DATA: Get user info from cached state directly
              const firstName = globalAuthState.user.firstName || "";
              const lastName = globalAuthState.user.lastName || "";
              const displayName =
                `${firstName} ${lastName}`.trim() || userEmail.split("@")[0];
              const accessLevel =
                (
                  globalAuthState.user.publicMetadata as {
                    accessLevel?: number;
                  }
                )?.accessLevel || 1;

              onAuthSuccess({
                id: globalAuthState.user.id,
                name: displayName,
                email: userEmail,
                accessLevel: accessLevel,
                canEditAccessLevel: false,
                avatar: globalAuthState.user.imageUrl,
              });
            }
          } catch (error) {
            // console.error('❌ Error processing cached user data:', error);
            // 🔐 FALLBACK WITH CACHED DATA: Use cached user data directly as fallback
            const userEmail =
              globalAuthState.user.emailAddresses?.[0]?.emailAddress ||
              "unknown@example.com";
            const firstName = globalAuthState.user.firstName || "";
            const lastName = globalAuthState.user.lastName || "";
            const displayName =
              `${firstName} ${lastName}`.trim() || userEmail.split("@")[0];
            const accessLevel =
              (globalAuthState.user.publicMetadata as { accessLevel?: number })
                ?.accessLevel || 1;

            onAuthSuccess({
              id: globalAuthState.user.id,
              name: displayName,
              email: userEmail,
              accessLevel: accessLevel,
              canEditAccessLevel: false,
              avatar: globalAuthState.user.imageUrl,
            });
          }

          setIsInitializing(false);
          return; // Exit early - no need to initialize
        }

        // 🔐 NO EXISTING AUTH: Initialize Clerk for first time
        // console.log('🔄 No existing authentication found - initializing Clerk...');
        await clerkAuth.initialize();

        // 🔐 REFRESH AUTH STATE: Check for session after initialization
        // console.log('🔄 Refreshing authentication state after initialization...');
        await clerkAuth.refreshAuthenticationState();

        // Set up auth state listener for future changes
        clerkAuth.onAuthStateChange(async (state) => {
          setAuthState(state);

          // If user is signed in, notify parent
          if (state.isSignedIn && state.user) {
            try {
              const userEmail = clerkAuth.getUserEmail();
              if (!userEmail) {
                onAuthError("No email address found for this user");
                return;
              }
              // console.log('🔍 Fetching user data from database for:', userEmail);

              // Fetch user data from database with permissions
              const dbUserData =
                await SecureBrowserDatabaseService.getUserWithPermissions(
                  userEmail
                );

              if (dbUserData) {
                // console.log('✅ Database user data loaded:', dbUserData);
                onAuthSuccess({
                  id: state.user.id,
                  dbId: dbUserData.id,
                  name: dbUserData.name,
                  email: dbUserData.email,
                  accessLevel: dbUserData.accessLevel,
                  canEditAccessLevel: dbUserData.canEditAccessLevel,
                });
              } else {
                console.warn(
                  "⚠️ User not found in database, using Clerk defaults"
                );
                onAuthSuccess({
                  id: state.user.id,
                  name: clerkAuth.getUserDisplayName(),
                  email: clerkAuth.getUserEmail(),
                  accessLevel: clerkAuth.getUserAccessLevel(),
                  canEditAccessLevel: false,
                  avatar: state.user.imageUrl,
                });
              }
            } catch (error) {
              console.error(
                "❌ Error fetching user data from database:",
                error
              );
              // Fallback to Clerk data if database fetch fails
              onAuthSuccess({
                id: state.user.id,
                name: clerkAuth.getUserDisplayName(),
                email: clerkAuth.getUserEmail(),
                accessLevel: clerkAuth.getUserAccessLevel(),
                canEditAccessLevel: false,
                avatar: state.user.imageUrl,
              });
            }
          }
        });

        setIsInitializing(false);
      } catch (error) {
        console.error("Failed to initialize Clerk auth:", error);
        setInitError(
          error instanceof Error
            ? error.message
            : "Authentication initialization failed"
        );
        setIsInitializing(false);
        onAuthError("Authentication service unavailable");
      }
    };

    initializeClerk();

    return () => {
      // Cleanup listeners
      clerkAuth.removeAuthStateListener(() => {});
    };
  }, [onAuthSuccess, onAuthError]);

  useEffect(() => {
    window.secureBrowser.auth.onGoogleSignInSuccess((userInfo) => {
      onAuthSuccess({
        id: userInfo.id,
        name: userInfo.name,
        email: userInfo.email,
        accessLevel: 1,
        avatar: userInfo.picture,
      });
    });

    window.secureBrowser.auth.onOAuthError((error) => {
      console.error("❌ OAuth Error:", error);
      onAuthError("Google sign-in failed: " + error);
    });

    return () => {
      window.secureBrowser.auth.removeGoogleSignInListener();
      window.secureBrowser.auth.removeOAuthErrorListener();
    };
  }, [onAuthSuccess, onAuthError]);

  const handleSignIn = async () => {
    try {
      setIsSigningIn(true);
      // console.log('🔐 Opening Clerk sign-in modal...');
      await clerkAuth.signIn();
      // console.log('✅ Clerk sign-in modal opened successfully');
    } catch (error) {
      // console.error('❌ Sign in failed:', error);
      onAuthError(
        error instanceof Error
          ? error.message
          : "Unable to open sign-in. Please refresh and try again."
      );
    } finally {
      setIsSigningIn(false);
    }
  };

  const handleSignUp = async () => {
    try {
      setIsSigningUp(true);
      // console.log('🔐 Opening Clerk sign-up modal...');
      await clerkAuth.signUp();
      // console.log('✅ Clerk sign-up modal opened successfully');
    } catch (error) {
      // console.error('❌ Sign up failed:', error);
      onAuthError(
        error instanceof Error
          ? error.message
          : "Unable to open sign-up. Please refresh and try again."
      );
    } finally {
      setIsSigningUp(false);
    }
  };

  // Show loading screen while initializing
  if (isInitializing) {
    return (
      <LoadingScreen
        stage="auth"
        message="Initializing secure authentication..."
        progress={50}
      />
    );
  }

  // Show error if initialization failed
  if (initError) {
    return (
      <ErrorDisplay
        errors={[
          {
            type: "config",
            title: "Authentication Service Error",
            message: initError,
            details: [
              "Check your Clerk configuration",
              "Verify VITE_CLERK_PUBLISHABLE_KEY is set",
              "Ensure internet connectivity",
            ],
            critical: true,
          },
        ]}
        onRetry={() => window.location.reload()}
      />
    );
  }

  // Show loading if user is already authenticated
  if (authState.isSignedIn && authState.user) {
    return (
      <LoadingScreen
        stage="ready"
        message="Welcome back! Setting up your secure browser..."
        progress={90}
      />
    );
  }

  return (
    <>
      {/* Custom CSS for Clerk modal centering */}
      <style>{`
        .cl-modal {
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
        }
        .cl-modalContent {
          margin: auto !important;
          transform: none !important;
          position: relative !important;
          top: auto !important;
          left: auto !important;
        }
      `}</style>

      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-slate-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md space-y-6">
          {/* Header */}
          <div className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="relative">
                <div className="w-16 h-16 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg">
                  <Shield className="w-8 h-8 text-white" />
                </div>
                <div className="absolute -bottom-1 -right-1 w-6 h-6 bg-green-500 rounded-full flex items-center justify-center">
                  <Lock className="w-3 h-3 text-white" />
                </div>
              </div>
            </div>

            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Aussie Vault Browser
              </h1>
              <p className="text-gray-600 mt-1">
                Enterprise-grade browsing with VPN protection
              </p>
            </div>

            {/* Security Features */}
            <div className="flex justify-center gap-2 flex-wrap">
              <Badge variant="secondary" className="gap-1">
                <Globe className="w-3 h-3" />
                Australian VPN
              </Badge>
              <Badge variant="secondary" className="gap-1">
                <Shield className="w-3 h-3" />
                Encrypted
              </Badge>
              <Badge variant="secondary" className="gap-1">
                <Users className="w-3 h-3" />
                Enterprise SSO
              </Badge>
            </div>
          </div>

          {/* Authentication Card */}
          <Card className="border-0 shadow-xl bg-white/95 backdrop-blur-sm">
            <CardHeader className="text-center pb-4">
              <CardTitle className="text-lg font-semibold text-gray-900">
                Sign in to continue
              </CardTitle>
              <CardDescription className="text-gray-600">
                Access your secure SharePoint documents and browse safely
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              {/* Sign In Button */}
              <Button
                onClick={handleSignIn}
                disabled={isSigningIn || isSigningUp}
                className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-all duration-200 shadow-md hover:shadow-lg disabled:opacity-50"
              >
                {isSigningIn ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Signing in...
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Chrome className="w-4 h-4" />
                    Sign in with SSO
                  </div>
                )}
              </Button>

              <Separator className="my-4" />

              {/* Sign Up Button */}
              <Button
                onClick={handleSignUp}
                disabled={isSigningIn || isSigningUp}
                variant="outline"
                className="w-full h-12 border-gray-300 text-gray-700 font-medium rounded-lg transition-all duration-200 hover:bg-gray-50 hover:border-gray-400 disabled:opacity-50"
              >
                {isSigningUp ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
                    Creating account...
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Users className="w-4 h-4" />
                    Create new account
                  </div>
                )}
              </Button>

              <Separator className="my-4" />

              <Button
                onClick={() => window.secureBrowser.auth.startGoogleSignIn()}
                className="w-full h-12 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-all duration-200 shadow-md hover:shadow-lg"
              >
                <div className="flex items-center gap-2">
                  <Chrome className="w-4 h-4" />
                  Sign in with Google
                </div>
              </Button>

              {/* Features List */}
              <div className="mt-6 pt-4 border-t border-gray-200">
                <div className="space-y-3">
                  <div className="flex items-center gap-3 text-sm text-gray-600">
                    <div className="w-2 h-2 bg-green-500 rounded-full" />
                    <span>Automatic SharePoint login</span>
                  </div>
                  <div className="flex items-center gap-3 text-sm text-gray-600">
                    <div className="w-2 h-2 bg-green-500 rounded-full" />
                    <span>VPN-protected browsing</span>
                  </div>
                  <div className="flex items-center gap-3 text-sm text-gray-600">
                    <div className="w-2 h-2 bg-green-500 rounded-full" />
                    <span>Download protection</span>
                  </div>
                  <div className="flex items-center gap-3 text-sm text-gray-600">
                    <div className="w-2 h-2 bg-green-500 rounded-full" />
                    <span>Role-based access control</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Footer */}
          <div className="text-center text-xs text-gray-500 space-y-1">
            <p>Powered by Clerk Authentication</p>
            <p>Your data is encrypted and secure</p>
          </div>
        </div>
      </div>
    </>
  );
};
