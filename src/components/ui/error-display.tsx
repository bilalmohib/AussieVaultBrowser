import React from 'react';
import { AlertTriangle, Wifi, WifiOff, Settings, CheckCircle, XCircle, Info } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from './alert';
import { Button } from './button';
import { Card, CardContent, CardHeader, CardTitle } from './card';

export interface ErrorInfo {
  type: 'environment' | 'vpn' | 'network' | 'config';
  title: string;
  message: string;
  details?: string[];
  action?: string;
  critical?: boolean;
}

export interface VPNStatus {
  connected: boolean;
  provider?: string;
  endpoint?: string;
  location?: string;
  lastCheck?: Date;
}

export interface EnvironmentStatus {
  loaded: boolean;
  valid: boolean;
  errors: string[];
  warnings: string[];
  config?: {
    nodeEnv?: string;
    vpnProvider?: string;
    wireguardEndpoint?: string;
    wireguardConfigPath?: string;
  };
}

interface ErrorDisplayProps {
  errors: ErrorInfo[];
  vpnStatus?: VPNStatus;
  environmentStatus?: EnvironmentStatus;
  onRetry?: () => void;
  onOpenSettings?: () => void;
}

export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({
  errors,
  vpnStatus,
  environmentStatus,
  onRetry,
  onOpenSettings
}) => {
  const criticalErrors = errors.filter(error => error.critical);
  const warnings = errors.filter(error => !error.critical);

  return (
    <div className="min-h-screen bg-gray-50 w-full overflow-auto">
      <div className="w-full p-4 space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center mb-4">
            <AlertTriangle className="h-16 w-16 text-red-500" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
                          Aussie Vault Browser
          </h1>
          <p className="text-gray-600">
            Configuration issues detected. Please review the details below.
          </p>
        </div>

        {/* Environment Status */}
        {environmentStatus && (
          <Card className="border-blue-200">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Environment Configuration
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="flex items-center gap-2">
                  {environmentStatus.loaded ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                  <span className="text-sm">
                    Environment: {environmentStatus.loaded ? 'Loaded' : 'Failed to Load'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {environmentStatus.valid ? (
                    <CheckCircle className="h-4 w-4 text-green-500" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-500" />
                  )}
                  <span className="text-sm">
                    Validation: {environmentStatus.valid ? 'Passed' : 'Failed'}
                  </span>
                </div>
              </div>

              {environmentStatus.config && (
                <div className="bg-gray-50 p-3 rounded-lg mb-4">
                  <h4 className="font-medium text-sm mb-2">Current Configuration:</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                    <div>NODE_ENV: {environmentStatus.config.nodeEnv || 'undefined'}</div>
                    <div>VPN_PROVIDER: {environmentStatus.config.vpnProvider || 'undefined'}</div>
                    <div>WIREGUARD_ENDPOINT: {environmentStatus.config.wireguardEndpoint || 'undefined'}</div>
                    <div>CONFIG_PATH: {environmentStatus.config.wireguardConfigPath || 'undefined'}</div>
                  </div>
                </div>
              )}

              {environmentStatus.errors.length > 0 && (
                <div className="mb-4">
                  <h4 className="font-medium text-sm text-red-700 mb-2">Errors:</h4>
                  <ul className="list-disc list-inside text-sm text-red-600 space-y-1">
                    {environmentStatus.errors.map((error, index) => (
                      <li key={index}>{error}</li>
                    ))}
                  </ul>
                </div>
              )}

              {environmentStatus.warnings.length > 0 && (
                <div>
                  <h4 className="font-medium text-sm text-yellow-700 mb-2">Warnings:</h4>
                  <ul className="list-disc list-inside text-sm text-yellow-600 space-y-1">
                    {environmentStatus.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* VPN Status */}
        {vpnStatus && (
          <Card className={vpnStatus.connected ? "border-green-200" : "border-red-200"}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {vpnStatus.connected ? (
                  <Wifi className="h-5 w-5 text-green-500" />
                ) : (
                  <WifiOff className="h-5 w-5 text-red-500" />
                )}
                VPN Connection Status
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-600">Status</div>
                  <div className={`font-medium ${vpnStatus.connected ? 'text-green-600' : 'text-red-600'}`}>
                    {vpnStatus.connected ? 'Connected' : 'Disconnected'}
                  </div>
                </div>
                {vpnStatus.provider && (
                  <div>
                    <div className="text-sm text-gray-600">Provider</div>
                    <div className="font-medium">{vpnStatus.provider}</div>
                  </div>
                )}
                {vpnStatus.endpoint && (
                  <div>
                    <div className="text-sm text-gray-600">Endpoint</div>
                    <div className="font-medium font-mono text-sm">{vpnStatus.endpoint}</div>
                  </div>
                )}
                {vpnStatus.location && (
                  <div>
                    <div className="text-sm text-gray-600">Location</div>
                    <div className="font-medium">{vpnStatus.location}</div>
                  </div>
                )}
              </div>
              {vpnStatus.lastCheck && (
                <div className="mt-4 text-xs text-gray-500">
                  Last checked: {vpnStatus.lastCheck.toLocaleString()}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Critical Errors */}
        {criticalErrors.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-red-700 flex items-center gap-2">
              <XCircle className="h-5 w-5" />
              Critical Issues
            </h2>
            {criticalErrors.map((error, index) => (
              <Alert key={index} variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>{error.title}</AlertTitle>
                <AlertDescription>
                  <div className="mt-2">
                    <p>{error.message}</p>
                    {error.details && error.details.length > 0 && (
                      <ul className="list-disc list-inside mt-2 space-y-1">
                        {error.details.map((detail, detailIndex) => (
                          <li key={detailIndex} className="text-sm">{detail}</li>
                        ))}
                      </ul>
                    )}
                    {error.action && (
                      <p className="mt-2 font-medium">Action needed: {error.action}</p>
                    )}
                  </div>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}

        {/* Warnings */}
        {warnings.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold text-yellow-700 flex items-center gap-2">
              <Info className="h-5 w-5" />
              Warnings
            </h2>
            {warnings.map((warning, index) => (
              <Alert key={index} variant="default" className="border-yellow-200">
                <Info className="h-4 w-4" />
                <AlertTitle>{warning.title}</AlertTitle>
                <AlertDescription>
                  <div className="mt-2">
                    <p>{warning.message}</p>
                    {warning.details && warning.details.length > 0 && (
                      <ul className="list-disc list-inside mt-2 space-y-1">
                        {warning.details.map((detail, detailIndex) => (
                          <li key={detailIndex} className="text-sm">{detail}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </AlertDescription>
              </Alert>
            ))}
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-4 justify-center">
          {onRetry && (
            <Button onClick={onRetry} className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              Retry Connection
            </Button>
          )}
          {onOpenSettings && (
            <Button variant="outline" onClick={onOpenSettings} className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              Open Settings
            </Button>
          )}
        </div>

        {/* Help Section */}
        <Card className="border-blue-200 bg-blue-50">
          <CardHeader>
            <CardTitle className="text-blue-900">Need Help?</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-blue-800 space-y-2">
              <p><strong>For WireGuard issues:</strong></p>
              <ul className="list-disc list-inside ml-4 space-y-1 text-sm">
                <li>Ensure WireGuard GUI is installed and running</li>
                <li>Import your config file and activate the tunnel</li>
                <li>Verify your server endpoint is correct: 134.199.169.102:59926</li>
                <li>Check your internet connection</li>
              </ul>
              <p className="mt-3"><strong>For environment issues:</strong></p>
              <ul className="list-disc list-inside ml-4 space-y-1 text-sm">
                <li>Ensure .env file exists in the project root</li>
                <li>Set NODE_ENV=development (not production)</li>
                <li>Verify all required variables are set</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ErrorDisplay; 