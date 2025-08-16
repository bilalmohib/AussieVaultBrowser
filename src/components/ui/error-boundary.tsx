import React from "react";
import { confirmReload } from "@/utils/reload";
import { AlertTriangle, RefreshCw, Settings, Wifi, Shield } from "lucide-react";
import { Button } from "./button";
import { Card } from "./card";

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
}

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<ErrorBoundaryState>;
}

export class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({
      error,
      errorInfo,
    });

    // Log error to console for debugging
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  handleReload = async () => {
    const ok = await confirmReload({
      title: "Reload Application?",
      message:
        "A reload can resolve certain errors. Your current session will restart. Do you want to proceed?",
      confirmText: "Reload",
      cancelText: "Cancel",
    });
    if (ok) {
      window.location.reload();
    }
  };

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return <this.props.fallback {...this.state} />;
      }

      return (
        <DefaultErrorFallback
          {...this.state}
          onReload={this.handleReload}
          onReset={this.handleReset}
        />
      );
    }

    return this.props.children;
  }
}

interface DefaultErrorFallbackProps extends ErrorBoundaryState {
  onReload: () => void;
  onReset: () => void;
}

const DefaultErrorFallback: React.FC<DefaultErrorFallbackProps> = ({
  error,
  errorInfo,
  onReload,
  onReset,
}) => {
  const getErrorType = (error: Error | null) => {
    if (!error) return "unknown";
    const message = error.message.toLowerCase();

    if (message.includes("process is not defined")) return "environment";
    if (message.includes("vault")) return "vault";
    if (message.includes("vpn")) return "vpn";
    if (message.includes("network") || message.includes("fetch"))
      return "network";
    if (message.includes("preload")) return "electron";

    return "application";
  };

  const errorType = getErrorType(error);

  const getErrorIcon = (type: string) => {
    switch (type) {
      case "vault":
        return <Shield className="w-8 h-8 text-yellow-400" />;
      case "vpn":
        return <Wifi className="w-8 h-8 text-blue-400" />;
      case "network":
        return <Wifi className="w-8 h-8 text-red-400" />;
      case "environment":
        return <Settings className="w-8 h-8 text-purple-400" />;
      default:
        return <AlertTriangle className="w-8 h-8 text-red-400" />;
    }
  };

  const getErrorTitle = (type: string) => {
    switch (type) {
      case "vault":
        return "Vault Service Error";
      case "vpn":
        return "VPN Connection Error";
      case "network":
        return "Network Connection Error";
      case "environment":
        return "Configuration Error";
      case "electron":
        return "Application Loading Error";
      default:
        return "Application Error";
    }
  };

  const getErrorDescription = (type: string, error: Error | null) => {
    switch (type) {
      case "vault":
        return "Unable to connect to the vault service. SharePoint credentials may not be available.";
      case "vpn":
        return "VPN connection failed. Please check your Australian VPN server configuration.";
      case "network":
        return "Network connection failed. Please check your internet connection.";
      case "environment":
        return "Environment configuration is incomplete. The application may be missing required settings.";
      case "electron":
        return "Application failed to load properly. This may be due to missing dependencies or configuration issues.";
      default:
        return (
          error?.message || "An unexpected error occurred in the application."
        );
    }
  };

  const getSuggestions = (type: string) => {
    switch (type) {
      case "vault":
        return [
          "Check your vault credentials in the .env file",
          "Verify vault server is accessible",
          "Ensure vault service is properly configured",
        ];
      case "vpn":
        return [
          "Check your WireGuard configuration file",
          "Verify your Australian VPS is running",
          "Test VPN connection manually",
        ];
      case "network":
        return [
          "Check your internet connection",
          "Verify firewall settings",
          "Try refreshing the application",
        ];
      case "environment":
        return [
          "Check your .env file configuration",
          "Verify all required environment variables are set",
          "Restart the application after making changes",
        ];
      case "electron":
        return [
          "Try rebuilding the application: npm run build",
          "Clear cache and restart: npm run dev",
          "Check for missing dependencies: npm install",
        ];
      default:
        return [
          "Try refreshing the application",
          "Check the console for additional error details",
          "Contact support if the issue persists",
        ];
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
      <Card className="max-w-2xl w-full bg-slate-800 border-slate-700">
        <div className="p-8 text-center space-y-6">
          {/* Error Icon */}
          <div className="flex justify-center">{getErrorIcon(errorType)}</div>

          {/* Error Title */}
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">
              {getErrorTitle(errorType)}
            </h1>
            <p className="text-slate-300">
              {getErrorDescription(errorType, error)}
            </p>
          </div>

          {/* Error Details */}
          {error && (
            <div className="bg-slate-700/50 border border-slate-600 rounded-lg p-4 text-left">
              <h3 className="text-sm font-semibold text-slate-200 mb-2">
                Error Details:
              </h3>
              <code className="text-xs text-red-300 break-all">
                {error.name}: {error.message}
              </code>
            </div>
          )}

          {/* Suggestions */}
          <div className="bg-blue-900/30 border border-blue-700 rounded-lg p-4 text-left">
            <h3 className="text-sm font-semibold text-blue-200 mb-3">
              Suggested Solutions:
            </h3>
            <ul className="text-sm text-blue-100 space-y-1">
              {getSuggestions(errorType).map((suggestion, index) => (
                <li key={index} className="flex items-start">
                  <span className="text-blue-400 mr-2">•</span>
                  <span>{suggestion}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 justify-center">
            <Button
              onClick={onReload}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Reload Application
            </Button>
            <Button
              onClick={onReset}
              variant="outline"
              className="border-slate-600 text-slate-300 hover:bg-slate-700"
            >
              Try Again
            </Button>
          </div>

          {/* Development Info */}
          {process.env.NODE_ENV === "development" && errorInfo && (
            <details className="text-left">
              <summary className="text-sm text-slate-400 cursor-pointer hover:text-slate-300">
                Show Technical Details (Development)
              </summary>
              <pre className="mt-2 text-xs text-slate-500 bg-slate-800 p-3 rounded border overflow-auto">
                {errorInfo.componentStack}
              </pre>
            </details>
          )}
        </div>
      </Card>
    </div>
  );
};

export default ErrorBoundary;
