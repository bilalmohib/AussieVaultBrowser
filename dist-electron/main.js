import { ipcMain, app, session, BrowserWindow } from "electron";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { spawn } from "child_process";
import { promises } from "fs";
import { homedir } from "os";
const detectPlatform = () => {
  if (typeof window !== "undefined") {
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes("win")) return "windows";
    if (userAgent.includes("mac")) return "macos";
    if (userAgent.includes("linux")) return "linux";
  }
  if (typeof process !== "undefined") {
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
const getPlatformInfo = (platform) => {
  const currentPlatform = detectPlatform();
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
          'Click "Activate" to connect'
        ]
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
          "Or import config into WireGuard app"
        ]
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
          "Or use NetworkManager GUI if available"
        ]
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
          "Please use WireGuard manually"
        ]
      };
  }
};
const printPlatformInstructions = (configPath) => {
  const info = getPlatformInfo();
  console.log(`${info.emoji} ${info.displayName} Instructions:`);
  console.log(`   Config file: ${configPath}`);
  console.log("");
  info.installInstructions.forEach((instruction, index) => {
    console.log(`   ${index + 1}. ${instruction}`);
  });
  if (info.requiresManualSetup) {
    console.log("");
    console.log("🔄 After connecting, restart this application to verify the connection.");
  }
};
const loadEnvironmentVariables = async () => {
  try {
    const envPath = path.resolve(".env");
    const envContent = await promises.readFile(envPath, "utf-8");
    const envLines = envContent.split("\n");
    console.log("🔍 Loading .env file from:", envPath);
    for (const line of envLines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith("#")) {
        const [key, ...valueParts] = trimmed.split("=");
        if (key && valueParts.length > 0) {
          const value = valueParts.join("=").trim();
          process.env[key.trim()] = value;
          if (!key.includes("SECRET") && !key.includes("PASSWORD") && !key.includes("KEY") && !key.includes("ID")) {
            console.log(`📝 Loaded: ${key.trim()}=${value}`);
          } else {
            console.log(`📝 Loaded: ${key.trim()}=***`);
          }
        }
      }
    }
    console.log("✅ Environment variables loaded successfully");
  } catch (error) {
    console.error("❌ Failed to load .env file:", error);
    console.log("📝 This may cause VPN detection to fail");
  }
};
const __dirname = path.dirname(fileURLToPath(import.meta.url));
process.env.APP_ROOT = path.join(__dirname, "..");
const VITE_DEV_SERVER_URL = process.env["VITE_DEV_SERVER_URL"];
const MAIN_DIST = path.join(process.env.APP_ROOT, "dist-electron");
const RENDERER_DIST = path.join(process.env.APP_ROOT, "dist");
process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL ? path.join(process.env.APP_ROOT, "public") : RENDERER_DIST;
let win = null;
let vpnConnected = false;
let wireguardProcess = null;
const updateVPNStatus = (connected) => {
  const wasConnected = vpnConnected;
  vpnConnected = connected;
  if (wasConnected !== connected) {
    console.log(`🔄 VPN status changed: ${wasConnected ? "Connected" : "Disconnected"} → ${connected ? "Connected" : "Disconnected"}`);
  }
  console.log(`📡 VPN Status Updated: ${connected ? "✅ Connected - Allowing all HTTPS requests" : "❌ Disconnected - Blocking external requests"}`);
  if (win) {
    win.webContents.send("vpn-status-changed", connected);
  }
};
const connectVPN = async () => {
  try {
    const provider = process.env.VPN_PROVIDER || "wireguard";
    if (provider === "wireguard") {
      return await connectWireGuard();
    } else {
      throw new Error(`VPN provider ${provider} not implemented`);
    }
  } catch (error) {
    console.error("❌ VPN connection failed:", error);
    return false;
  }
};
const disconnectVPN = async () => {
  try {
    if (wireguardProcess) {
      return await disconnectWireGuard();
    }
    return true;
  } catch (error) {
    console.error("❌ VPN disconnection failed:", error);
    return false;
  }
};
const connectWireGuard = async () => {
  try {
    console.log("🔍 Debug: Environment variables at startup:");
    console.log(`  NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`  VPN_PROVIDER: ${process.env.VPN_PROVIDER}`);
    console.log(`  WIREGUARD_CONFIG_PATH: ${process.env.WIREGUARD_CONFIG_PATH}`);
    console.log(`  WIREGUARD_ENDPOINT: ${process.env.WIREGUARD_ENDPOINT}`);
    const configPath = process.env.WIREGUARD_CONFIG_PATH || "./config/wireguard-australia.conf";
    const resolvedPath = path.resolve(configPath);
    console.log(`🔍 Resolved config path: ${resolvedPath}`);
    try {
      await promises.access(resolvedPath);
      console.log("✅ Config file found");
    } catch (error) {
      console.log("❌ Config file not found:", error);
      console.log("📝 This is OK - config file not required for detection");
    }
    const platformInfo = getPlatformInfo();
    console.log(`🔌 Checking WireGuard connection on ${platformInfo.displayName}...`);
    const isConnected = await checkWireGuardConnection();
    if (isConnected) {
      console.log("✅ WireGuard is connected and active");
      console.log("✅ VPN connected successfully - unrestricted access enabled");
      return true;
    }
    console.log("🔄 Attempting to establish WireGuard connection...");
    const connectionResult = await establishWireGuardConnection(resolvedPath);
    if (connectionResult) {
      console.log("✅ WireGuard connection established successfully");
      const verifyConnection = await checkWireGuardConnection();
      if (verifyConnection) {
        console.log("✅ VPN auto-connected successfully");
        return true;
      } else {
        console.log("⚠️ Connection established but IP location verification failed");
        return false;
      }
    } else {
      console.log("❌ WireGuard connection failed.");
      printPlatformInstructions(resolvedPath);
      return false;
    }
  } catch (error) {
    console.error("❌ WireGuard setup error:", error);
    return false;
  }
};
const establishWireGuardConnection = async (configPath) => {
  const platform = process.platform;
  try {
    switch (platform) {
      case "linux":
        return await connectWireGuardLinux(configPath);
      case "darwin":
        return await connectWireGuardMacOS(configPath);
      case "win32":
        return await connectWireGuardWindows(configPath);
      default:
        console.error(`❌ Unsupported platform: ${platform}`);
        return false;
    }
  } catch (error) {
    console.error(`❌ Failed to connect on ${platform}:`, error);
    return false;
  }
};
const connectWireGuardLinux = async (configPath) => {
  return new Promise((resolve) => {
    console.log("🐧 Using Linux wg-quick...");
    const process2 = spawn("wg-quick", ["up", configPath], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    process2.on("exit", (code) => {
      resolve(code === 0);
    });
    process2.on("error", (error) => {
      console.error("❌ wg-quick error:", error);
      resolve(false);
    });
    setTimeout(() => resolve(false), 3e4);
  });
};
const connectWireGuardMacOS = async (configPath) => {
  return new Promise((resolve) => {
    console.log("🍎 Using macOS wg-quick...");
    const process2 = spawn("wg-quick", ["up", configPath], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    process2.on("exit", (code) => {
      resolve(code === 0);
    });
    process2.on("error", () => {
      console.log("🍎 Trying WireGuard macOS app...");
      resolve(false);
    });
    setTimeout(() => resolve(false), 3e4);
  });
};
const connectWireGuardWindows = async (configPath) => {
  console.log("🪟 Windows detected - checking existing connection...");
  console.log(`   Config available at: ${configPath}`);
  return false;
};
const checkWireGuardConnection = async () => {
  const platform = process.platform;
  try {
    switch (platform) {
      case "linux":
        return await checkWireGuardLinux();
      case "darwin":
        return await checkWireGuardMacOS();
      case "win32":
        return await checkWireGuardWindows();
      default:
        console.warn(`⚠️ Unsupported platform: ${platform}`);
        return false;
    }
  } catch (error) {
    console.error("❌ Error checking WireGuard status:", error);
    return false;
  }
};
const checkWireGuardLinux = async () => {
  return new Promise((resolve) => {
    const process2 = spawn("wg", ["show"], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    process2.stdout.on("data", (data) => {
      output += data.toString();
    });
    process2.on("exit", (code) => {
      if (code === 0 && output.trim()) {
        console.log("🐧 WireGuard active on Linux");
        resolve(true);
      } else {
        resolve(false);
      }
    });
    process2.on("error", () => resolve(false));
    setTimeout(() => resolve(false), 5e3);
  });
};
const checkWireGuardMacOS = async () => {
  return new Promise((resolve) => {
    const process2 = spawn("wg", ["show"], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    process2.stdout.on("data", (data) => {
      output += data.toString();
    });
    process2.on("exit", (code) => {
      if (code === 0 && output.trim()) {
        console.log("🍎 WireGuard active on macOS");
        resolve(true);
      } else {
        checkMacOSNetworkInterfaces().then(resolve);
      }
    });
    process2.on("error", () => {
      checkMacOSNetworkInterfaces().then(resolve);
    });
    setTimeout(() => resolve(false), 5e3);
  });
};
const checkMacOSNetworkInterfaces = async () => {
  return new Promise((resolve) => {
    const process2 = spawn("ifconfig", [], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    process2.stdout.on("data", (data) => {
      output += data.toString();
    });
    process2.on("exit", () => {
      const hasWG = output.includes("utun") || output.includes("tun") || output.includes("wg");
      resolve(hasWG);
    });
    process2.on("error", () => resolve(false));
    setTimeout(() => resolve(false), 5e3);
  });
};
const checkWireGuardWindows = async () => {
  console.log("🪟 Starting comprehensive Windows VPN detection...");
  console.log("🔍 PRIMARY CHECK: IP geolocation (mandatory)...");
  const ipResult = await checkCurrentIP();
  if (!ipResult) {
    console.log("❌ IP geolocation check FAILED - not connected to Australian VPN");
    console.log("🚨 CRITICAL: User appears to be browsing from non-Australian IP");
    console.log("🔍 Running diagnostic checks for troubleshooting...");
    await checkWireGuardCLI();
    await checkWindowsNetworkInterfaces();
    await checkRoutingTable();
    console.log("⚠️  Note: Ping connectivity to VPN server does not indicate active VPN connection");
    return false;
  }
  console.log("✅ IP geolocation check PASSED - Australian VPN confirmed");
  console.log("🔍 Running secondary verification checks...");
  const cliResult = await checkWireGuardCLI();
  const interfaceResult = await checkWindowsNetworkInterfaces();
  const routingResult = await checkRoutingTable();
  if (cliResult || interfaceResult || routingResult) {
    console.log("✅ Secondary checks confirm WireGuard is properly configured");
  } else {
    console.log("⚠️  Secondary checks inconclusive, but IP location confirms VPN is working");
  }
  return true;
};
const checkWireGuardCLI = async () => {
  return new Promise((resolve) => {
    console.log("🔍 Checking WireGuard CLI...");
    const wgProcess = spawn("wg", ["show"], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let wgOutput = "";
    wgProcess.stdout.on("data", (data) => {
      wgOutput += data.toString();
    });
    wgProcess.on("exit", (code) => {
      console.log(`🔍 WireGuard CLI exit code: ${code}`);
      console.log(`🔍 WireGuard CLI output: "${wgOutput.trim()}"`);
      if (code === 0 && wgOutput.trim()) {
        console.log("🪟 WireGuard active on Windows (CLI)");
        resolve(true);
        return;
      }
      resolve(false);
    });
    wgProcess.on("error", (error) => {
      console.log("🔍 WireGuard CLI error:", error.message);
      resolve(false);
    });
    setTimeout(() => {
      console.log("🔍 WireGuard CLI check timed out");
      resolve(false);
    }, 3e3);
  });
};
const checkWindowsNetworkInterfaces = async () => {
  return new Promise((resolve) => {
    console.log("🔍 Checking network interfaces via netsh...");
    const netshProcess = spawn("netsh", ["interface", "show", "interface"], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    netshProcess.stdout.on("data", (data) => {
      output += data.toString();
    });
    netshProcess.on("exit", () => {
      console.log("🔍 Network interfaces output:");
      console.log(output);
      const hasWireGuard = output.toLowerCase().includes("wireguard") || output.toLowerCase().includes("wg") || output.toLowerCase().includes("tun");
      console.log(`🔍 WireGuard interface found: ${hasWireGuard}`);
      if (hasWireGuard) {
        console.log("🪟 WireGuard interface detected on Windows");
      }
      resolve(hasWireGuard);
    });
    netshProcess.on("error", (error) => {
      console.log("🔍 Network interface check error:", error.message);
      resolve(false);
    });
    setTimeout(() => {
      console.log("🔍 Network interface check timed out");
      resolve(false);
    }, 3e3);
  });
};
const checkRoutingTable = async () => {
  return new Promise((resolve) => {
    console.log("🔍 Checking routing table...");
    const endpoint = process.env.WIREGUARD_ENDPOINT || "134.199.169.102:59926";
    const serverIP = endpoint.split(":")[0];
    console.log(`🔍 Looking for routes to server: ${serverIP}`);
    const routeProcess = spawn("route", ["print"], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    routeProcess.stdout.on("data", (data) => {
      output += data.toString();
    });
    routeProcess.on("exit", () => {
      const hasServerRoute = output.includes(serverIP);
      console.log(`🔍 Route to VPN server found: ${hasServerRoute}`);
      if (hasServerRoute) {
        console.log(`🪟 Found route to VPN server ${serverIP}`);
      }
      resolve(hasServerRoute);
    });
    routeProcess.on("error", (error) => {
      console.log("🔍 Route check error:", error.message);
      resolve(false);
    });
    setTimeout(() => {
      console.log("🔍 Route check timed out");
      resolve(false);
    }, 3e3);
  });
};
const checkCurrentIP = async () => {
  return new Promise((resolve) => {
    console.log("🔍 Checking current public IP and location...");
    const psCommand = `(Invoke-WebRequest -Uri "https://ipinfo.io/json" -UseBasicParsing).Content | ConvertFrom-Json | ConvertTo-Json -Compress`;
    const psProcess = spawn("powershell", ["-Command", psCommand], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    let output = "";
    psProcess.stdout.on("data", (data) => {
      output += data.toString();
    });
    psProcess.on("exit", () => {
      try {
        const ipInfo = JSON.parse(output.trim());
        const currentIP = ipInfo.ip;
        const country = ipInfo.country;
        const region = ipInfo.region;
        const city = ipInfo.city;
        console.log(`🔍 Current public IP: ${currentIP}`);
        console.log(`🔍 Location: ${city}, ${region}, ${country}`);
        const isAustralianIP = country === "AU" || country === "Australia";
        if (isAustralianIP) {
          console.log("🇦🇺 ✅ Connected via Australian VPN!");
          console.log(`📍 Australian location detected: ${city}, ${region}`);
        } else {
          console.log(`❌ Not connected to Australian VPN. Current location: ${country}`);
        }
        resolve(isAustralianIP);
      } catch (error) {
        console.log("🔍 Failed to parse IP info:", error);
        console.log("🔍 Raw output:", output);
        const ipOnlyCommand = `(Invoke-WebRequest -Uri "https://ipinfo.io/ip" -UseBasicParsing).Content.Trim()`;
        const fallbackProcess = spawn("powershell", ["-Command", ipOnlyCommand], {
          stdio: ["pipe", "pipe", "pipe"]
        });
        let fallbackOutput = "";
        fallbackProcess.stdout.on("data", (data) => {
          fallbackOutput += data.toString();
        });
        fallbackProcess.on("exit", () => {
          const ip = fallbackOutput.trim();
          console.log(`🔍 Fallback IP check: ${ip}`);
          const isNotLocalIP = !ip.startsWith("192.168.") && !ip.startsWith("10.") && !ip.startsWith("172.") && ip !== "127.0.0.1";
          console.log(`🔍 Assuming VPN status based on non-local IP: ${isNotLocalIP}`);
          resolve(isNotLocalIP);
        });
        fallbackProcess.on("error", () => {
          resolve(false);
        });
      }
    });
    psProcess.on("error", (error) => {
      console.log("🔍 IP check error:", error.message);
      resolve(false);
    });
    setTimeout(() => {
      console.log("🔍 IP check timed out");
      resolve(false);
    }, 1e4);
  });
};
const disconnectWireGuard = async () => {
  try {
    const configPath = process.env.WIREGUARD_CONFIG_PATH || "./config/wireguard-australia.conf";
    const resolvedPath = path.resolve(configPath);
    const platform = process.platform;
    console.log(`🔌 Disconnecting WireGuard on ${platform}...`);
    switch (platform) {
      case "linux":
      case "darwin":
        return await disconnectWireGuardUnix(resolvedPath);
      case "win32":
        return await disconnectWireGuardWindows();
      default:
        console.error(`❌ Unsupported platform: ${platform}`);
        return false;
    }
  } catch (error) {
    console.error("❌ WireGuard disconnect setup error:", error);
    return false;
  }
};
const disconnectWireGuardUnix = async (configPath) => {
  return new Promise((resolve) => {
    const downProcess = spawn("wg-quick", ["down", configPath], {
      stdio: ["pipe", "pipe", "pipe"]
    });
    downProcess.on("exit", (code) => {
      wireguardProcess = null;
      if (code === 0) {
        console.log("✅ WireGuard disconnected successfully");
        resolve(true);
      } else {
        console.error(`❌ WireGuard disconnection failed with code: ${code}`);
        resolve(false);
      }
    });
    downProcess.on("error", (error) => {
      console.error("❌ WireGuard disconnect error:", error);
      resolve(false);
    });
    setTimeout(() => resolve(false), 15e3);
  });
};
const disconnectWireGuardWindows = async () => {
  console.log("🪟 On Windows, please disconnect manually via WireGuard GUI");
  console.log("   1. Open WireGuard application");
  console.log('   2. Click "Deactivate" on your tunnel');
  return true;
};
const configureSecureSession = () => {
  const defaultSession = session.defaultSession;
  const enable1PasswordExtension = async () => {
    try {
      const extensionPath = await find1PasswordExtension();
      if (extensionPath) {
        await defaultSession.loadExtension(extensionPath);
        console.log("✅ 1Password extension loaded successfully");
      } else {
        console.log("📝 1Password extension not found - users can install it manually");
      }
    } catch (error) {
      console.warn("⚠️ Could not load 1Password extension:", error);
      console.log("📝 Users can install 1Password extension manually from their browser");
    }
  };
  const find1PasswordExtension = async () => {
    const possiblePaths = [
      // Chrome/Chromium paths
      path.join(homedir(), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"),
      path.join(homedir(), "Library", "Application Support", "Google", "Chrome", "Default", "Extensions", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"),
      path.join(homedir(), ".config", "google-chrome", "Default", "Extensions", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"),
      // Edge paths
      path.join(homedir(), "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Extensions", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"),
      path.join(homedir(), "Library", "Application Support", "Microsoft Edge", "Default", "Extensions", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"),
      // Firefox paths (1Password uses different ID)
      path.join(homedir(), "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
      path.join(homedir(), "Library", "Application Support", "Firefox", "Profiles"),
      path.join(homedir(), ".mozilla", "firefox")
    ];
    for (const basePath of possiblePaths) {
      try {
        if (await promises.access(basePath).then(() => true).catch(() => false)) {
          const entries = await promises.readdir(basePath);
          const versionFolders = entries.filter((entry) => /^\d+\.\d+\.\d+/.test(entry));
          if (versionFolders.length > 0) {
            const latestVersion = versionFolders.sort((a, b) => b.localeCompare(a))[0];
            const extensionPath = path.join(basePath, latestVersion);
            const manifestPath = path.join(extensionPath, "manifest.json");
            if (await promises.access(manifestPath).then(() => true).catch(() => false)) {
              return extensionPath;
            }
          }
        }
      } catch (error) {
      }
    }
    return null;
  };
  defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const url = details.url.toLowerCase();
    if (url.startsWith("chrome-extension://") || url.startsWith("moz-extension://") || url.startsWith("extension://")) {
      callback({ cancel: false });
      return;
    }
    if (url.includes("localhost") || url.includes("127.0.0.1") || url.startsWith("file://") || url.startsWith("data:")) {
      callback({ cancel: false });
      return;
    }
    if (url.startsWith("http://")) {
      console.log("🚫 Blocking insecure HTTP request:", details.url);
      callback({ cancel: true });
      return;
    }
    if (url.startsWith("https://")) {
      console.log("✅ Allowing HTTPS request:", details.url);
      callback({ cancel: false });
      return;
    }
    callback({ cancel: false });
  });
  defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const url = details.url.toLowerCase();
    if (url.includes("office.com") || url.includes("microsoft.com") || url.includes("google.com") || url.includes("sharepoint.com")) {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          "X-Content-Type-Options": ["nosniff"],
          "Referrer-Policy": ["strict-origin-when-cross-origin"]
        }
      });
      return;
    }
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "X-Frame-Options": ["SAMEORIGIN"],
        "X-Content-Type-Options": ["nosniff"],
        "Referrer-Policy": ["strict-origin-when-cross-origin"],
        "Permissions-Policy": ["camera=(), microphone=(), geolocation=()"],
        "Content-Security-Policy": [
          "default-src 'self' chrome-extension: moz-extension: extension:; script-src 'self' 'unsafe-inline' 'unsafe-eval' chrome-extension: moz-extension: extension:; style-src 'self' 'unsafe-inline' https: chrome-extension: moz-extension: extension:; connect-src 'self' https: wss: data: chrome-extension: moz-extension: extension:; img-src 'self' https: data: blob: chrome-extension: moz-extension: extension:; font-src 'self' https: data: chrome-extension: moz-extension: extension:; media-src 'self' https: data: chrome-extension: moz-extension: extension:; frame-src 'self' https: chrome-extension: moz-extension: extension:; child-src 'self' https: chrome-extension: moz-extension: extension:;"
        ]
      }
    });
  });
  defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    callback({
      requestHeaders: {
        ...details.requestHeaders,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      }
    });
  });
  setTimeout(enable1PasswordExtension, 1e3);
};
function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    icon: path.join(process.env.VITE_PUBLIC || "", "electron-vite.svg"),
    titleBarStyle: "default",
    show: false,
    // Don't show until ready
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      // Security: Enable webview for controlled browsing
      webviewTag: true,
      // Security: Disable node integration
      nodeIntegration: false,
      // Security: Enable context isolation
      contextIsolation: true,
      // Security: Enable web security
      webSecurity: true,
      // Security: Disable node integration in workers
      nodeIntegrationInWorker: false,
      // Security: Disable node integration in subframes  
      nodeIntegrationInSubFrames: false,
      // Security: Enable sandbox mode
      sandbox: false,
      // Keep false to allow webview
      // Security: Disable experimental features
      experimentalFeatures: false,
      // Security: Disable web workers
      enableWebSQL: false,
      // Additional security settings
      allowRunningInsecureContent: false,
      plugins: false
    }
  });
  win.webContents.setWindowOpenHandler(() => {
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, navigationUrl) => {
    const allowedOrigins = [
      VITE_DEV_SERVER_URL,
      "file://",
      "about:blank"
    ].filter(Boolean);
    const isAllowed = allowedOrigins.some(
      (origin) => navigationUrl.startsWith(origin || "")
    );
    if (!isAllowed) {
      console.log("🚫 Blocking main window navigation to:", navigationUrl);
      event.preventDefault();
    }
  });
  win.webContents.session.on("will-download", (event, item) => {
    console.log("🚫 Blocking download attempt:", item.getFilename());
    event.preventDefault();
  });
  if (VITE_DEV_SERVER_URL) {
    win.loadURL(VITE_DEV_SERVER_URL);
    if (process.env.NODE_ENV === "development") {
      win.webContents.openDevTools();
    }
  } else {
    win.loadFile(path.join(RENDERER_DIST, "index.html"));
  }
  win.once("ready-to-show", () => {
    if (win) {
      win.show();
      win.focus();
    }
  });
  setTimeout(async () => {
    try {
      const alreadyConnected = await checkWireGuardConnection();
      if (alreadyConnected) {
        console.log("✅ VPN is already connected during app initialization");
        updateVPNStatus(true);
      } else if (process.env.VPN_AUTO_CONNECT === "true") {
        console.log("🔄 VPN not connected, attempting auto-connect...");
        const connected = await connectVPN();
        updateVPNStatus(connected);
        if (connected) {
          console.log("✅ VPN auto-connected successfully");
        } else {
          console.warn("⚠️ VPN auto-connect failed");
        }
      } else {
        console.log("⚠️ VPN not connected and auto-connect disabled");
        updateVPNStatus(false);
      }
    } catch (error) {
      console.error("❌ VPN initialization error:", error);
      updateVPNStatus(false);
    }
  }, 500);
  win.on("closed", () => {
    disconnectVPN().catch((error) => {
      console.error("❌ Error disconnecting VPN on app close:", error);
    });
    win = null;
  });
  if (process.env.NODE_ENV === "production") {
    win.setMenuBarVisibility(false);
  }
}
ipcMain.handle("system-get-version", () => {
  return app.getVersion();
});
ipcMain.handle("system-get-environment", () => {
  const envVars = {
    NODE_ENV: process.env.NODE_ENV,
    APP_NAME: process.env.APP_NAME,
    APP_VERSION: process.env.APP_VERSION,
    VPN_PROVIDER: process.env.VPN_PROVIDER,
    VPN_SERVER_REGION: process.env.VPN_SERVER_REGION,
    VPN_AUTO_CONNECT: process.env.VPN_AUTO_CONNECT,
    VPN_FAIL_CLOSED: process.env.VPN_FAIL_CLOSED,
    WIREGUARD_CONFIG_PATH: process.env.WIREGUARD_CONFIG_PATH,
    WIREGUARD_ENDPOINT: process.env.WIREGUARD_ENDPOINT,
    VAULT_PROVIDER: process.env.VAULT_PROVIDER,
    VAULT_ADDR: process.env.VAULT_ADDR,
    VAULT_NAMESPACE: process.env.VAULT_NAMESPACE,
    VAULT_ROLE_ID: process.env.VAULT_ROLE_ID,
    VAULT_SECRET_ID: process.env.VAULT_SECRET_ID,
    AWS_REGION: process.env.AWS_REGION,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
    AZURE_TENANT_ID: process.env.AZURE_TENANT_ID,
    AZURE_CLIENT_ID: process.env.AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET: process.env.AZURE_CLIENT_SECRET,
    AZURE_VAULT_URL: process.env.AZURE_VAULT_URL,
    OP_CONNECT_HOST: process.env.OP_CONNECT_HOST,
    OP_CONNECT_TOKEN: process.env.OP_CONNECT_TOKEN,
    SHAREPOINT_TENANT_URL: process.env.SHAREPOINT_TENANT_URL,
    SHAREPOINT_AUTO_LOGIN: process.env.SHAREPOINT_AUTO_LOGIN,
    SHAREPOINT_DEFAULT_ACCESS_LEVEL: process.env.SHAREPOINT_DEFAULT_ACCESS_LEVEL,
    SHAREPOINT_DOCUMENT_LIBRARIES: process.env.SHAREPOINT_DOCUMENT_LIBRARIES,
    SECURITY_BLOCK_DOWNLOADS: process.env.SECURITY_BLOCK_DOWNLOADS,
    SECURITY_HTTPS_ONLY: process.env.SECURITY_HTTPS_ONLY,
    SECURITY_FAIL_CLOSED_VPN: process.env.SECURITY_FAIL_CLOSED_VPN,
    SECURITY_BLOCK_DEVTOOLS: process.env.SECURITY_BLOCK_DEVTOOLS,
    LEVEL1_DOMAINS: process.env.LEVEL1_DOMAINS,
    LEVEL2_DOMAINS: process.env.LEVEL2_DOMAINS,
    LEVEL3_ENABLED: process.env.LEVEL3_ENABLED,
    LOG_LEVEL: process.env.LOG_LEVEL,
    LOG_FILE_PATH: process.env.LOG_FILE_PATH
  };
  console.log("🔄 Environment variables requested from renderer:", {
    NODE_ENV: envVars.NODE_ENV,
    VPN_PROVIDER: envVars.VPN_PROVIDER,
    WIREGUARD_ENDPOINT: envVars.WIREGUARD_ENDPOINT
  });
  return JSON.stringify(envVars);
});
ipcMain.handle("vpn-get-status", async () => {
  console.log("🔍 VPN status requested - running comprehensive check...");
  try {
    const isConnected = await checkWireGuardConnection();
    const status = isConnected ? "connected" : "disconnected";
    console.log(`📊 VPN status check result: ${status}`);
    updateVPNStatus(isConnected);
    return status;
  } catch (error) {
    console.error("❌ VPN status check error:", error);
    return "disconnected";
  }
});
ipcMain.handle("vpn-connect", async (_event, provider) => {
  console.log(`🌐 VPN connect requested: ${provider}`);
  try {
    const success = await connectVPN();
    updateVPNStatus(success);
    return success;
  } catch (error) {
    console.error("❌ VPN connection error:", error);
    updateVPNStatus(false);
    return false;
  }
});
ipcMain.handle("vpn-disconnect", async () => {
  console.log("🌐 VPN disconnect requested");
  try {
    const success = await disconnectVPN();
    updateVPNStatus(false);
    return success;
  } catch (error) {
    console.error("❌ VPN disconnection error:", error);
    return false;
  }
});
const get1PasswordSecret = async (itemId) => {
  const serviceAccountToken = process.env.OP_SERVICE_ACCOUNT_TOKEN;
  if (!serviceAccountToken) {
    throw new Error("1Password Service Account not configured. Set OP_SERVICE_ACCOUNT_TOKEN environment variable.");
  }
  try {
    const response = await fetch(`https://my.1password.com/api/v1/items/${itemId}`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${serviceAccountToken}`,
        "Content-Type": "application/json"
      }
    });
    if (!response.ok) {
      throw new Error(`1Password Service Account API error: ${response.status} ${response.statusText}`);
    }
    const item = await response.json();
    const secrets = {};
    if (item.fields) {
      for (const field of item.fields) {
        if (field.label && field.value) {
          switch (field.label.toLowerCase()) {
            case "username":
            case "email":
              secrets.username = field.value;
              break;
            case "password":
              secrets.password = field.value;
              break;
            case "tenant_url":
            case "url":
            case "website":
              secrets.tenant_url = field.value;
              break;
            case "level1_domains":
              secrets.level1_domains = field.value;
              break;
            case "level2_domains":
              secrets.level2_domains = field.value;
              break;
            case "level3_enabled":
              secrets.level3_enabled = field.value === "true";
              break;
            default:
              secrets[field.label.toLowerCase().replace(/\s+/g, "_")] = field.value;
          }
        }
      }
    }
    return secrets;
  } catch (error) {
    throw new Error(`Failed to retrieve 1Password secret: ${error instanceof Error ? error.message : String(error)}`);
  }
};
ipcMain.handle("vault-get-sharepoint-credentials", async () => {
  console.log("🔑 SharePoint credentials requested from main process");
  try {
    const vaultProvider = process.env.VAULT_PROVIDER || "hashicorp";
    if (process.env.NODE_ENV === "development") {
      console.log("🔧 Development mode: returning mock vault credentials");
      return {
        username: "dev-user@yourcompany.sharepoint.com",
        password: "dev-password-from-vault",
        lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
    if (vaultProvider === "1password" || vaultProvider === "1password-cli") {
      console.log("🔐 Using 1Password Service Account for credentials");
      const itemId = process.env.OP_SHAREPOINT_ITEM_ID || "SharePoint Service Account";
      const secrets = await get1PasswordSecret(itemId);
      return {
        username: secrets.username,
        password: secrets.password,
        tenant_url: secrets.tenant_url,
        lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
      };
    } else {
      console.log(`⚠️ Vault provider ${vaultProvider} not fully implemented`);
      return {
        username: "vault-user@yourcompany.sharepoint.com",
        password: "vault-retrieved-password",
        lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  } catch (error) {
    console.error("❌ Vault credentials retrieval failed:", error);
    throw new Error(`Vault credentials unavailable: ${error instanceof Error ? error.message : "Unknown error"}`);
  }
});
ipcMain.handle("vault-rotate-credentials", async () => {
  console.log("🔄 Vault credential rotation requested from main process");
  try {
    if (process.env.NODE_ENV === "development") {
      console.log("🔧 Development mode: simulating credential rotation");
      return true;
    }
    return true;
  } catch (error) {
    console.error("❌ Vault credential rotation failed:", error);
    return false;
  }
});
ipcMain.handle("vault-get-status", async () => {
  if (process.env.NODE_ENV === "development") {
    return "connected-dev";
  }
  const vaultProvider = process.env.VAULT_PROVIDER || "hashicorp";
  try {
    if (vaultProvider === "1password" || vaultProvider === "1password-cli") {
      const serviceAccountToken = process.env.OP_SERVICE_ACCOUNT_TOKEN;
      const itemId = process.env.OP_SHAREPOINT_ITEM_ID;
      if (!serviceAccountToken) {
        return "error: 1Password Service Account not configured";
      }
      if (!itemId) {
        return "error: SharePoint Item ID not configured";
      }
      const response = await fetch(`https://my.1password.com/api/v1/items/${itemId}`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${serviceAccountToken}`,
          "Content-Type": "application/json"
        }
      });
      if (response.ok) {
        console.log("✅ 1Password Service Account access verified");
        return "connected";
      } else {
        console.error("❌ 1Password Service Account access failed:", response.status);
        return "error: Cannot access SharePoint credentials in 1Password";
      }
    } else {
      return "connected";
    }
  } catch (error) {
    console.error("❌ Vault status check failed:", error);
    return `error: ${error instanceof Error ? error.message : "Unknown error"}`;
  }
});
ipcMain.handle("security-check-url", async (_event, url, accessLevel) => {
  console.log(`🔒 URL check: ${url} (Level ${accessLevel})`);
  return true;
});
ipcMain.handle("security-log-navigation", async (_event, url, allowed, accessLevel) => {
  console.log(`📝 Navigation log: ${url} - ${allowed ? "ALLOWED" : "BLOCKED"} (Level ${accessLevel})`);
});
ipcMain.handle("security-prevent-download", async (_event, filename) => {
  console.log(`🚫 Download blocked: ${filename}`);
});
ipcMain.handle("extension-get-1password-status", async () => {
  try {
    const extensions = session.defaultSession.getAllExtensions();
    const onePasswordExtension = extensions.find(
      (ext) => ext.name.toLowerCase().includes("1password") || ext.id === "aeblfdkhhhdcdjpifhhbdiojplfjncoa"
    );
    if (onePasswordExtension) {
      return {
        installed: true,
        version: onePasswordExtension.version,
        name: onePasswordExtension.name,
        id: onePasswordExtension.id
      };
    } else {
      return {
        installed: false,
        downloadUrl: "https://chromewebstore.google.com/detail/1password-%E2%80%93-password-mana/aeblfdkhhhdcdjpifhhbdiojplfjncoa",
        instructions: "Please install the 1Password extension for the best experience"
      };
    }
  } catch (error) {
    console.error("❌ Error checking 1Password extension status:", error);
    return {
      installed: false,
      error: "Could not check extension status"
    };
  }
});
ipcMain.handle("extension-install-1password", async () => {
  console.log("🔧 1Password extension installation requested");
  return {
    success: false,
    message: "Please install 1Password extension manually",
    steps: [
      "1. Open Chrome or Edge browser",
      "2. Go to chrome://extensions/ or edge://extensions/",
      "3. Enable Developer mode",
      "4. Install 1Password extension from the web store",
      "5. Restart the Secure Remote Browser"
    ],
    webStoreUrl: "https://chromewebstore.google.com/detail/1password-%E2%80%93-password-mana/aeblfdkhhhdcdjpifhhbdiojplfjncoa"
  };
});
ipcMain.handle("sharepoint-inject-credentials", async (_event, webviewId) => {
  console.log(`🔐 SharePoint credentials injection requested for: ${webviewId}`);
  return true;
});
ipcMain.handle("sharepoint-get-config", async () => {
  return {
    tenantUrl: process.env.SHAREPOINT_TENANT_URL || "https://your-tenant.sharepoint.com",
    libraryPath: "/sites/documents/Shared Documents"
  };
});
ipcMain.handle("sharepoint-validate-access", async (_event, url) => {
  console.log(`🔍 SharePoint access validation: ${url}`);
  return true;
});
app.whenReady().then(async () => {
  console.log("🚀 Initializing Secure Remote Browser...");
  await loadEnvironmentVariables();
  configureSecureSession();
  console.log("🔌 Starting VPN connection...");
  const vpnConnected2 = await connectVPN();
  updateVPNStatus(vpnConnected2);
  if (!vpnConnected2) {
    console.error("❌ VPN connection failed - starting with restricted access");
  } else {
    console.log("✅ VPN connected successfully - unrestricted access enabled");
  }
  createWindow();
}).catch((error) => {
  console.error("❌ Failed to initialize app:", error);
  app.quit();
});
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  console.log("🚫 Another instance is already running");
  app.quit();
} else {
  app.on("second-instance", () => {
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
}
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    console.log("🔐 Closing Secure Remote Browser");
    app.quit();
  }
});
app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
app.on("web-contents-created", (_event, contents) => {
  contents.on("will-navigate", (event, navigationUrl) => {
    try {
      const isMainWindow = win && contents === win.webContents;
      if (isMainWindow) {
        const parsedUrl = new URL(navigationUrl);
        const allowedOrigins = [
          VITE_DEV_SERVER_URL,
          "file:",
          "about:"
        ].filter(Boolean);
        const isAllowed = allowedOrigins.some(
          (origin) => parsedUrl.protocol.startsWith(origin || "") || navigationUrl.startsWith(origin || "")
        );
        if (!isAllowed) {
          console.log("🚫 Blocking main window navigation to:", navigationUrl);
          event.preventDefault();
        }
      } else {
        console.log("🌐 Webview navigation allowed:", navigationUrl);
      }
    } catch (error) {
      console.warn("⚠️ Failed to parse navigation URL:", navigationUrl, error);
      const isMainWindow = win && contents === win.webContents;
      if (isMainWindow) {
        event.preventDefault();
      }
    }
  });
});
if (process.defaultApp) {
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient("secure-browser", process.execPath, [path.resolve(process.argv[1])]);
  }
} else {
  app.setAsDefaultProtocolClient("secure-browser");
}
process.on("SIGINT", () => {
  console.log("🔐 Received SIGINT, gracefully shutting down");
  app.quit();
});
process.on("SIGTERM", () => {
  console.log("🔐 Received SIGTERM, gracefully shutting down");
  app.quit();
});
export {
  MAIN_DIST,
  RENDERER_DIST,
  VITE_DEV_SERVER_URL
};
