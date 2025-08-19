// Cross-platform utility functions
export type SupportedPlatform = "windows" | "macos" | "linux" | "unknown";

export interface PlatformInfo {
  platform: SupportedPlatform;
  displayName: string;
  emoji: string;
  canAutoConnect: boolean;
  requiresManualSetup: boolean;
  installInstructions: string[];
}

export const detectPlatform = (): SupportedPlatform => {
  if (typeof window !== "undefined") {
    // Browser/renderer process detection
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes("win")) return "windows";
    if (userAgent.includes("mac")) return "macos";
    if (userAgent.includes("linux")) return "linux";
  }

  if (typeof process !== "undefined") {
    // Node.js/main process detection
    switch (process.platform) {
      case "win32":
        return "windows";
      case "darwin":
        return "macos";
      case "linux":
        return "linux";
      default:
        return "unknown";
    }
  }

  return "unknown";
};

export const getPlatformInfo = (platform?: SupportedPlatform): PlatformInfo => {
  const currentPlatform = platform || detectPlatform();

  switch (currentPlatform) {
    case "windows":
      return {
        platform: "windows",
        displayName: "Windows",
        emoji: "🪟",
        canAutoConnect: false,
        requiresManualSetup: true,
        installInstructions: [
          "Download WireGuard from: https://www.wireguard.com/install/",
          "Install and open WireGuard GUI application",
          'Click "Add Tunnel" → "Add from file"',
          "Select your config file",
          'Click "Activate" to connect',
        ],
      };

    case "macos":
      return {
        platform: "macos",
        displayName: "macOS",
        emoji: "🍎",
        canAutoConnect: true,
        requiresManualSetup: false,
        installInstructions: [
          "Install WireGuard from App Store or: brew install wireguard-tools",
          "Use: sudo wg-quick up <config-file>",
          "Or import config into WireGuard app",
        ],
      };

    case "linux":
      return {
        platform: "linux",
        displayName: "Linux",
        emoji: "🐧",
        canAutoConnect: true,
        requiresManualSetup: false,
        installInstructions: [
          "Install WireGuard: sudo apt install wireguard (Ubuntu/Debian)",
          "Or: sudo yum install wireguard-tools (RHEL/CentOS)",
          "Use: sudo wg-quick up <config-file>",
          "Or use NetworkManager GUI if available",
        ],
      };

    default:
      return {
        platform: "unknown",
        displayName: "Unknown Platform",
        emoji: "❓",
        canAutoConnect: false,
        requiresManualSetup: true,
        installInstructions: [
          "Platform not supported",
          "Please use WireGuard manually",
        ],
      };
  }
};

export const logPlatformInfo = (): void => {
  getPlatformInfo();
  // console.log(`${info.emoji} Detected platform: ${info.displayName}`);
  // console.log(`   Auto-connect: ${info.canAutoConnect ? '✅' : '❌'}`);
  // console.log(`   Manual setup required: ${info.requiresManualSetup ? '✅' : '❌'}`);
};

export const printPlatformInstructions = (_configPath: string): void => {
  const info = getPlatformInfo();

  // console.log(`${info.emoji} ${info.displayName} Instructions:`);
  // console.log(`   Config file: ${configPath}`);
  // console.log('');

  info.installInstructions.forEach((_instruction, _index) => {
    // console.log(`   ${index + 1}. ${instruction}`);
  });

  if (info.requiresManualSetup) {
    // console.log('');
    // console.log('🔄 After connecting, restart this application to verify the connection.');
  }
};
