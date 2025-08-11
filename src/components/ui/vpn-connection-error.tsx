import React, { useEffect } from "react";
import {
  AlertTriangle,
  Shield,
  RefreshCw,
  Globe,
  Wifi,
  CheckCircle,
} from "lucide-react";
import { Button } from "./button";
import { toast } from "sonner";

interface VPNConnectionErrorProps {
  onRetry: () => void;
  onCheckStatus: () => void;
  isRetrying?: boolean;
  isChecking?: boolean;
  errorDetails?: string;
  actualIP?: string;
  actualCountry?: string;
}

const VPNConnectionError: React.FC<VPNConnectionErrorProps> = ({
  onRetry,
  onCheckStatus,
  isRetrying = false,
  isChecking = false,
  errorDetails,
  actualIP,
  actualCountry,
}) => {
  // Only log the error, don't show toast notifications automatically
  useEffect(() => {
    // console.log("🔴 VPN Connection Error:", "🚫 VPN Connection Required - Secure browsing blocked until VPN is connected");
    // Removed automatic toast - only show when user manually triggered
  }, []);

  // Only log error details, don't show toast notifications automatically
  useEffect(() => {
    if (errorDetails) {
      // console.log("🔴 VPN Error Details:", `🔧 Connection Details: ${errorDetails}`);
      // Removed automatic toast - only show when user manually triggered
    }
  }, [errorDetails]);

  // Show completion toasts for retry and status check operations
  useEffect(() => {
    if (isRetrying) {
      // console.log("🔵 VPN Status:", "🔄 VPN connection attempt in progress...");
    }
  }, [isRetrying]);

  useEffect(() => {
    if (isChecking) {
      // console.log("🔵 VPN Status:", "🔍 VPN status check in progress...");
    }
  }, [isChecking]);

  const handleRetry = () => {
    // console.log("🔵 VPN Retry:", "🔄 Attempting to connect to Australian VPN...");
    toast.loading("Connecting to Australian VPN...", {
      description: "Establishing secure WireGuard connection",
      duration: 3000,
    });
    onRetry();
  };

  const handleCheckStatus = () => {
    // console.log("🔵 VPN Status Check:", "🔍 Checking VPN connection status...");
    toast.info("Checking VPN Status", {
      description: "Verifying connection without attempting to reconnect",
      duration: 2000,
    });
    onCheckStatus();
  };

  return (
    <div className="w-full h-full flex flex-col bg-white">
      {/* Scrollable Content Container */}
      <div className="flex-1">
        <div className="w-full px-4 py-6 overflow-x-hidden min-h-screen">
          {/* Critical Issues Header */}
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-600" />
              </div>
              <h1 className="text-2xl font-bold text-red-600">
                Critical Issues
              </h1>
            </div>
          </div>

          {/* Main Content Card */}
          <div className="bg-white border border-gray-200 rounded-lg shadow-sm">
            {/* Warning Header */}
            <div className="border-l-4 border-red-500 bg-red-50 p-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-full bg-red-100 flex items-center justify-center flex-shrink-0">
                  <AlertTriangle className="w-6 h-6 text-red-600" />
                </div>
                <div className="flex-1">
                  <h2 className="text-xl font-semibold text-red-800 mb-2">
                    VPN Connection Required
                  </h2>
                  <p className="text-red-700 text-base leading-relaxed">
                    Australian VPN connection required to access this browser
                  </p>
                  {actualCountry && actualIP && (
                    <div className="mt-3 p-3 bg-red-100 rounded-lg border border-red-200">
                      <p className="text-red-800 font-medium text-sm">
                        ⚠️ Current Location: {actualCountry} ({actualIP})
                      </p>
                      <p className="text-red-700 text-sm mt-1">
                        You must be connected to an Australian VPN to continue
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Requirements List */}
            <div className="p-6 border-b border-gray-100">
              <ul className="space-y-3">
                <li className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500 mt-2 flex-shrink-0" />
                  <span className="text-gray-700 font-medium">
                    VPN connection is required for security compliance
                  </span>
                </li>
                <li className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500 mt-2 flex-shrink-0" />
                  <span className="text-gray-700 font-medium">
                    All browsing must be routed through Australian servers
                  </span>
                </li>
                <li className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500 mt-2 flex-shrink-0" />
                  <span className="text-gray-700 font-medium">
                    Check your WireGuard configuration and server status
                  </span>
                </li>
                <li className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500 mt-2 flex-shrink-0" />
                  <span className="text-gray-700 font-medium">
                    Ensure WireGuard GUI is running and tunnel is active
                  </span>
                </li>
              </ul>
            </div>

            {/* Error Details (if any) */}
            {errorDetails && (
              <div className="p-6 border-b border-gray-100">
                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Wifi className="w-5 h-5 text-gray-600" />
                    <span className="font-medium text-gray-800">
                      Connection Details
                    </span>
                  </div>
                  <p className="text-gray-700 text-sm font-mono bg-white p-3 rounded border break-all">
                    {errorDetails}
                  </p>
                </div>
              </div>
            )}

            {/* Action Required Section */}
            <div className="p-6">
              <div className="bg-blue-50 rounded-lg p-4 mb-6">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="w-5 h-5 text-blue-600" />
                  <span className="font-semibold text-blue-800">
                    Action needed: Connect WireGuard and retry
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Button
                  onClick={handleRetry}
                  disabled={isRetrying}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-medium shadow-sm hover:shadow-md transition-all duration-200 flex items-center justify-center gap-3 text-base"
                >
                  {isRetrying ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      Retry Connection
                    </>
                  ) : (
                    <>
                      <RefreshCw className="w-5 h-5" />
                      Retry Connection
                    </>
                  )}
                </Button>

                <Button
                  onClick={handleCheckStatus}
                  disabled={isChecking}
                  variant="outline"
                  className="border-gray-300 text-gray-700 hover:bg-gray-50 px-8 py-3 rounded-lg font-medium shadow-sm hover:shadow-md transition-all duration-200 flex items-center justify-center gap-3 text-base"
                >
                  {isChecking ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      Checking Status...
                    </>
                  ) : (
                    <>
                      <CheckCircle className="w-5 h-5" />
                      Check Status
                    </>
                  )}
                </Button>
              </div>

              {/* Help Text */}
              <div className="mt-6 text-center">
                <p className="text-gray-500 text-sm leading-relaxed max-w-2xl mx-auto">
                  Make sure your WireGuard client is running and connected to
                  the Australian server before retrying. Check your network
                  connection and VPN configuration if the issue persists.
                </p>
              </div>
            </div>
          </div>

          {/* Additional Instructions */}
          <div className="mt-4 bg-gray-50 rounded-lg p-4 mb-4">
            <div className="flex items-start gap-3">
              <Globe className="w-5 h-5 text-gray-600 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="font-medium text-gray-800 mb-2">
                  Quick Setup Guide
                </h3>
                <ol className="text-gray-600 text-sm space-y-1 list-decimal list-inside">
                  <li>Open WireGuard application</li>
                  <li>
                    Import or activate your Australian server configuration
                  </li>
                  <li>
                    Verify the tunnel shows as "Active" with data transfer
                  </li>
                  <li>Click "Retry Connection" above to continue</li>
                </ol>
              </div>
            </div>
          </div>

          {/* Auto-Reconnect Status */}
          <div className="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
            <div className="flex items-start gap-3">
              <RefreshCw className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="font-medium text-yellow-800 mb-1">
                  Auto-Reconnect Active
                </h3>
                <p className="text-yellow-700 text-sm">
                  The system will automatically attempt to reconnect to the VPN
                  every 30 seconds. You can also manually retry the connection
                  using the button above.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VPNConnectionError;
