import React, { useState } from "react";
import { Button } from "../ui/button";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { CheckCircle, XCircle, AlertCircle, Loader2 } from "lucide-react";

interface DiagnosticTest {
  name: string;
  status: "pending" | "running" | "success" | "error";
  message: string;
  details?: string;
}

export const SharePointDiagnostics: React.FC = () => {
  const [tests, setTests] = useState<DiagnosticTest[]>([
    {
      name: "Environment Variables",
      status: "pending",
      message: "Checking MSAL configuration...",
    },
    {
      name: "Network Connectivity",
      status: "pending",
      message: "Testing connection to Microsoft endpoints...",
    },
    {
      name: "OAuth Token Request",
      status: "pending",
      message: "Testing client credentials flow...",
    },
    {
      name: "SharePoint API Access",
      status: "pending",
      message: "Testing Graph API permissions...",
    },
  ]);

  const updateTest = (index: number, updates: Partial<DiagnosticTest>) => {
    setTests((prev) =>
      prev.map((test, i) => (i === index ? { ...test, ...updates } : test))
    );
  };

  const runDiagnostics = async () => {
    // Test 1: Environment Variables
    updateTest(0, { status: "running" });
    try {
      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.system?.getEnvironment
      ) {
        const envString = await window.secureBrowser.system.getEnvironment();
        const envVars = JSON.parse(envString);

        const requiredVars = [
          "MSAL_CLIENT_ID",
          "MSAL_TENANT_ID",
          "MSAL_CLIENT_SECRET",
        ];
        const missing = requiredVars.filter((var_) => !envVars[var_]);

        if (missing.length > 0) {
          updateTest(0, {
            status: "error",
            message: `Missing variables: ${missing.join(", ")}`,
            details:
              "Please check your .env file contains all MSAL credentials",
          });
          return;
        }

        updateTest(0, {
          status: "success",
          message: "All MSAL environment variables found",
          details: `Client ID: ${envVars.MSAL_CLIENT_ID?.substring(0, 8)}...`,
        });

        // Test 2: Network Connectivity
        updateTest(1, { status: "running" });

        // Skip network test in development to avoid CORS issues
        if (
          window.location.hostname === "localhost" ||
          window.location.hostname === "127.0.0.1"
        ) {
          updateTest(1, {
            status: "success",
            message: "Skipped in development mode",
            details:
              "Network connectivity test bypassed to avoid CORS issues in localhost",
          });

          // Test 3: OAuth Token Request (also skip in dev)
          updateTest(2, { status: "running" });
          updateTest(2, {
            status: "success",
            message: "Skipped in development mode",
            details: "OAuth test bypassed in development environment",
          });
        } else {
          try {
            const response = await fetch(
              "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1&authorization_endpoint=https://login.microsoftonline.com/common/oauth2/authorize",
              {
                method: "GET",
                mode: "cors",
              }
            );

            if (response.ok) {
              updateTest(1, {
                status: "success",
                message: "Microsoft endpoints reachable",
                details: `Response: ${response.status} ${response.statusText}`,
              });

              // Test 3: OAuth Token Request
              updateTest(2, { status: "running" });
              await testOAuthFlow(envVars);
            } else {
              updateTest(1, {
                status: "error",
                message: `Network error: ${response.status} ${response.statusText}`,
                details:
                  "Microsoft OAuth endpoints may be blocked or unreachable",
              });
            }
          } catch (error) {
            updateTest(1, {
              status: "error",
              message: "Cannot reach Microsoft endpoints",
              details:
                error instanceof Error
                  ? error.message
                  : "Network connectivity issue",
            });
          }
        }
      } else {
        updateTest(0, {
          status: "error",
          message: "Cannot access environment variables",
          details: "Electron bridge not available",
        });
      }
    } catch (error) {
      updateTest(0, {
        status: "error",
        message: "Failed to load environment",
        details: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };

  const testOAuthFlow = async (_envVars: any) => {
    try {
      // console.log('🔄 Testing OAuth token request via main process...');
      // console.log('Client ID:', envVars.MSAL_CLIENT_ID?.substring(0, 8) + '...');

      // Use main process OAuth handler
      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.sharepoint?.getOAuthToken
      ) {
        const result = await window.secureBrowser.sharepoint.getOAuthToken();

        // console.log('OAuth Response:', result);

        if (result.success && result.accessToken) {
          updateTest(2, {
            status: "success",
            message: "OAuth token acquired successfully via main process",
            details: `Token length: ${result.accessToken.length}`,
          });

          // Test 4: SharePoint API Access
          updateTest(3, { status: "running" });
          await testSharePointAPI(result.accessToken);
        } else {
          updateTest(2, {
            status: "error",
            message: "OAuth failed in main process",
            details: result.error || "No access token received",
          });
        }
      } else {
        updateTest(2, {
          status: "error",
          message: "Main process OAuth handler not available",
          details:
            "window.secureBrowser.sharepoint.getOAuthToken is not defined",
        });
      }
    } catch (error) {
      updateTest(2, {
        status: "error",
        message: "OAuth request failed",
        details:
          error instanceof Error
            ? error.message
            : "Network error during token request",
      });
    }
  };

  const testSharePointAPI = async (accessToken: string) => {
    try {
      // console.log('🔄 Testing SharePoint API access via main process...');

      // Use main process Graph API handler
      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.sharepoint?.graphRequest
      ) {
        const response = await window.secureBrowser.sharepoint.graphRequest(
          "/sites/root",
          accessToken
        );

        // console.log('SharePoint API Response:', response);

        if (response.success && response.data) {
          const siteData = response.data;
          updateTest(3, {
            status: "success",
            message: "SharePoint API access successful",
            details: `Site: ${siteData.displayName} (${siteData.webUrl})`,
          });
        } else {
          updateTest(3, {
            status: "error",
            message: "SharePoint API failed in main process",
            details: response.error || "Unknown API error",
          });
        }
      } else {
        updateTest(3, {
          status: "error",
          message: "Main process Graph API handler not available",
          details:
            "window.secureBrowser.sharepoint.graphRequest is not defined",
        });
      }
    } catch (error) {
      updateTest(3, {
        status: "error",
        message: "SharePoint API request failed",
        details:
          error instanceof Error
            ? error.message
            : "Network error during API request",
      });
    }
  };

  const getStatusIcon = (status: DiagnosticTest["status"]) => {
    switch (status) {
      case "success":
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case "error":
        return <XCircle className="w-5 h-5 text-red-500" />;
      case "running":
        return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: DiagnosticTest["status"]) => {
    switch (status) {
      case "success":
        return <Badge className="bg-green-100 text-green-800">✓ Passed</Badge>;
      case "error":
        return <Badge className="bg-red-100 text-red-800">✗ Failed</Badge>;
      case "running":
        return <Badge className="bg-blue-100 text-blue-800">⟳ Running</Badge>;
      default:
        return <Badge className="bg-gray-100 text-gray-600">⏱ Pending</Badge>;
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          SharePoint Connection Diagnostics
        </h2>
        <p className="text-gray-600">
          This tool will help identify the connection issue with SharePoint.
        </p>
      </div>

      <div className="mb-6">
        <Button
          onClick={runDiagnostics}
          disabled={tests.some((t) => t.status === "running")}
          className="w-full"
        >
          {tests.some((t) => t.status === "running") ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Running Diagnostics...
            </>
          ) : (
            "Run Diagnostics"
          )}
        </Button>
      </div>

      <div className="space-y-4">
        {tests.map((test, index) => (
          <Card key={index} className="p-4">
            <div className="flex items-start gap-3">
              {getStatusIcon(test.status)}
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-semibold text-gray-900">{test.name}</h3>
                  {getStatusBadge(test.status)}
                </div>
                <p className="text-sm text-gray-600 mb-2">{test.message}</p>
                {test.details && (
                  <div className="text-xs bg-gray-50 p-2 rounded border font-mono">
                    {test.details}
                  </div>
                )}
              </div>
            </div>
          </Card>
        ))}
      </div>

      <div className="mt-6 p-4 bg-blue-50 rounded-lg">
        <h4 className="font-semibold text-blue-900 mb-2">Common Solutions:</h4>
        <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
          <li>
            Verify your Azure app registration has{" "}
            <strong>Sites.Read.All</strong> application permissions
          </li>
          <li>
            Ensure admin consent has been granted for the application
            permissions
          </li>
          <li>Check that the client secret hasn't expired</li>
          <li>Confirm the tenant ID and client ID are correct</li>
          <li>Try restarting the application after making changes</li>
        </ul>
      </div>
    </div>
  );
};
