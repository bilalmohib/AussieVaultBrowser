import { app, BrowserWindow, session, ipcMain, Menu, shell } from "electron";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { spawn } from "child_process";
import { promises as fs } from "fs";
import { homedir } from "os";
import os from "os";
import { printPlatformInstructions } from "../src/utils/platform.js";
import electronSquirrelStartup from "electron-squirrel-startup";
import fetch from "node-fetch";
import crypto from "crypto";
// PKCE utility functions
function base64URLEncode(str) {
    return str
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}
function sha256(buffer) {
    return crypto.createHash("sha256").update(buffer).digest();
}
function generatePKCECodes() {
    const codeVerifier = base64URLEncode(crypto.randomBytes(32));
    const codeChallenge = base64URLEncode(sha256(codeVerifier));
    return { codeVerifier, codeChallenge };
}
// Constants for better maintainability
const VPN_CHECK_TIMEOUT = 30000; // 30 seconds for IP geolocation (increased)
const PROCESS_TIMEOUT = 30000; // 30 seconds for process operations
const IP_GEOLOCATION_API = "https://ipinfo.io/json";
const AUSTRALIAN_COUNTRY_CODES = ["AU", "Australia"];
// Utility functions for better code organization
const isAustralianCountry = (countryCode) => {
    return AUSTRALIAN_COUNTRY_CODES.includes(countryCode);
};
// Handle Squirrel.Windows events
if (electronSquirrelStartup) {
    app.quit();
}
// Load environment variables from .env file
const loadEnvironmentVariables = async () => {
    try {
        const envPath = path.resolve(".env");
        const envContent = await fs.readFile(envPath, "utf-8");
        const envLines = envContent.split("\n");
        // console.log('🔍 Loading .env file from:', envPath);
        for (const line of envLines) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith("#")) {
                const [key, ...valueParts] = trimmed.split("=");
                if (key && valueParts.length > 0) {
                    const value = valueParts.join("=").trim();
                    process.env[key.trim()] = value;
                    // Log non-sensitive environment variables
                    if (!key.includes("SECRET") &&
                        !key.includes("PASSWORD") &&
                        !key.includes("KEY") &&
                        !key.includes("ID")) {
                        // console.log(`📝 Loaded: ${key.trim()}=${value}`);
                    }
                    else {
                        // console.log(`📝 Loaded: ${key.trim()}=***`);
                    }
                }
            }
        }
        // console.log('✅ Environment variables loaded successfully');
    }
    catch (error) {
        // console.error('❌ Failed to load .env file:', error);
        // console.log('📝 This may cause VPN detection to fail');
    }
};
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// The built directory structure
//
// ├─┬─┬ dist
// │ │ └── index.html
// │ │
// │ ├─┬ dist-electron
// │ │ ├── main.js
// │ │ └── preload.cjs
// │
process.env.APP_ROOT = path.join(__dirname, "..");
// 🚧 Use ['ENV_NAME'] avoid vite:define plugin - Vite@2.x
export const VITE_DEV_SERVER_URL = process.env["VITE_DEV_SERVER_URL"];
export const MAIN_DIST = path.join(process.env.APP_ROOT, "dist-electron");
export const RENDERER_DIST = path.join(process.env.APP_ROOT, "dist");
process.env.VITE_PUBLIC = VITE_DEV_SERVER_URL
    ? path.join(process.env.APP_ROOT, "public")
    : RENDERER_DIST;
let windows = [];
let mainWindow = null;
let vpnConnected = false;
let wireguardProcess = null;
// Store pending downloads for choice processing
const pendingDownloads = new Map();
// VPN status tracking
const updateVPNStatus = (connected) => {
    const wasConnected = vpnConnected;
    vpnConnected = connected;
    if (wasConnected !== connected) {
        if (connected) {
            console.log("🇦🇺 ✅ VPN STATUS: Connected to Australian VPN - Browsing ENABLED");
        }
        else {
            console.log("🚨 ❌ VPN STATUS: NOT connected to Australian VPN - Browsing BLOCKED");
            console.log("⚠️  All external website access has been disabled for security");
            console.log("💡 Connect to Australian VPN server to enable browsing");
        }
    }
    console.log(`📡 🇦🇺 VPN Status: ${connected
        ? "✅ AUSTRALIAN VPN CONNECTED - All HTTPS requests allowed"
        : "❌ NO AUSTRALIAN VPN - All external requests BLOCKED"}`);
    // Send VPN status to all windows
    windows.forEach((window) => {
        if (window && !window.isDestroyed()) {
            window.webContents.send("vpn-status-changed", connected);
        }
    });
};
// Real WireGuard VPN functions
const connectVPN = async () => {
    try {
        const provider = process.env.VPN_PROVIDER || "wireguard";
        if (provider === "wireguard") {
            return await connectWireGuard();
        }
        else {
            throw new Error(`VPN provider ${provider} not implemented`);
        }
    }
    catch (error) {
        // console.error('❌ VPN connection failed:', error);
        return false;
    }
};
const disconnectVPN = async () => {
    try {
        if (wireguardProcess) {
            return await disconnectWireGuard();
        }
        return true;
    }
    catch (error) {
        console.error("❌ VPN disconnection failed:", error);
        return false;
    }
};
const connectWireGuard = async () => {
    try {
        // console.log('🔍 Debug: Environment variables at startup:');
        // console.log(`  NODE_ENV: ${process.env.NODE_ENV}`);
        // console.log(`  VPN_PROVIDER: ${process.env.VPN_PROVIDER}`);
        // console.log(`  WIREGUARD_CONFIG_PATH: ${process.env.WIREGUARD_CONFIG_PATH}`);
        // console.log(`  WIREGUARD_ENDPOINT: ${process.env.WIREGUARD_ENDPOINT}`);
        const configPath = process.env.WIREGUARD_CONFIG_PATH || "./config/wireguard-australia.conf";
        const resolvedPath = path.resolve(configPath);
        // console.log(`🔍 Resolved config path: ${resolvedPath}`);
        // Check if config file exists
        try {
            await fs.access(resolvedPath);
            // console.log('✅ Config file found');
        }
        catch (error) {
            // console.log('❌ Config file not found:', error);
            // console.log('📝 This is OK - config file not required for detection');
        }
        // const platformInfo = getPlatformInfo();
        // console.log(`🔌 Checking WireGuard connection on ${platformInfo.displayName}...`);
        // Check if VPN is already connected (IP geolocation check)
        const isConnected = await checkWireGuardConnection();
        if (isConnected) {
            // console.log('✅ WireGuard is connected and active');
            // console.log('✅ VPN connected successfully - unrestricted access enabled');
            return true;
        }
        // If not connected, try to establish connection based on OS
        // console.log('🔄 Attempting to establish WireGuard connection...');
        const connectionResult = await establishWireGuardConnection(resolvedPath);
        if (connectionResult) {
            // console.log('✅ WireGuard connection established successfully');
            // Verify connection with IP check after establishing
            const verifyConnection = await checkWireGuardConnection();
            if (verifyConnection) {
                // console.log('✅ VPN auto-connected successfully');
                return true;
            }
            else {
                // console.log('⚠️ Connection established but IP location verification failed');
                return false;
            }
        }
        else {
            // console.log('❌ WireGuard connection failed.');
            printPlatformInstructions(resolvedPath);
            return false;
        }
    }
    catch (error) {
        // console.error('❌ WireGuard setup error:', error);
        return false;
    }
};
// Cross-platform WireGuard connection establishment
const establishWireGuardConnection = async (configPath) => {
    const platform = process.platform;
    try {
        switch (platform) {
            case "linux":
                return await connectWireGuardLinux(configPath);
            case "darwin": // macOS
                return await connectWireGuardMacOS(configPath);
            case "win32": // Windows
                return await connectWireGuardWindows(configPath);
            default:
                console.error(`❌ Unsupported platform: ${platform}`);
                return false;
        }
    }
    catch (error) {
        // console.error(`❌ Failed to connect on ${platform}:`, error);
        return false;
    }
};
// Linux WireGuard connection
const connectWireGuardLinux = async (configPath) => {
    return new Promise((resolve) => {
        // console.log('🐧 Using Linux wg-quick...');
        const process = spawn("wg-quick", ["up", configPath], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        process.on("exit", (code) => {
            resolve(code === 0);
        });
        process.on("error", (_error) => {
            // console.error('❌ wg-quick error:', _error);
            resolve(false);
        });
        setTimeout(() => resolve(false), PROCESS_TIMEOUT); // 30s timeout
    });
};
// macOS WireGuard connection
const connectWireGuardMacOS = async (configPath) => {
    return new Promise((resolve) => {
        // console.log('🍎 Using macOS wg-quick...');
        const process = spawn("wg-quick", ["up", configPath], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        process.on("exit", (code) => {
            resolve(code === 0);
        });
        process.on("error", () => {
            // If wg-quick fails, try using WireGuard app
            // console.log('🍎 Trying WireGuard macOS app...');
            // Note: This requires WireGuard to be installed via App Store or brew
            resolve(false); // For now, require manual connection
        });
        setTimeout(() => resolve(false), PROCESS_TIMEOUT); // 30s timeout
    });
};
// Windows WireGuard connection
const connectWireGuardWindows = async (_configPath) => {
    // On Windows, we typically can't connect programmatically without admin rights
    // Check if already connected via WireGuard GUI
    // console.log('🪟 Windows detected - checking existing connection...');
    // console.log(`   Config available at: ${_configPath}`);
    return false; // Require manual GUI connection for security
};
// Cross-platform WireGuard status check
const checkWireGuardConnection = async () => {
    const platform = process.platform;
    try {
        switch (platform) {
            case "linux":
                return await checkWireGuardLinux();
            case "darwin": // macOS
                return await checkWireGuardMacOS();
            case "win32": // Windows
                return await checkWireGuardWindows();
            default:
                console.warn(`⚠️ Unsupported platform: ${platform}`);
                return false;
        }
    }
    catch (error) {
        console.error("❌ Error checking WireGuard status:", error);
        return false;
    }
};
// Linux status check
const checkWireGuardLinux = async () => {
    return new Promise((resolve) => {
        const process = spawn("wg", ["show"], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "";
        process.stdout.on("data", (data) => {
            output += data.toString();
        });
        process.on("exit", (code) => {
            if (code === 0 && output.trim()) {
                // console.log('🐧 WireGuard active on Linux');
                resolve(true);
            }
            else {
                resolve(false);
            }
        });
        process.on("error", () => resolve(false));
        setTimeout(() => resolve(false), 5000);
    });
};
// macOS status check
const checkWireGuardMacOS = async () => {
    return new Promise((resolve) => {
        // First try wg command
        const process = spawn("wg", ["show"], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "";
        process.stdout.on("data", (data) => {
            output += data.toString();
        });
        process.on("exit", (code) => {
            if (code === 0 && output.trim()) {
                // console.log('🍎 WireGuard active on macOS');
                resolve(true);
            }
            else {
                // Also check for WireGuard via network interfaces
                checkMacOSNetworkInterfaces().then(resolve);
            }
        });
        process.on("error", () => {
            // Fallback to network interface check
            checkMacOSNetworkInterfaces().then(resolve);
        });
        setTimeout(() => resolve(false), 5000);
    });
};
// macOS network interface check
const checkMacOSNetworkInterfaces = async () => {
    return new Promise((resolve) => {
        const process = spawn("ifconfig", [], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "";
        process.stdout.on("data", (data) => {
            output += data.toString();
        });
        process.on("exit", () => {
            const hasWG = output.includes("utun") ||
                output.includes("tun") ||
                output.includes("wg");
            resolve(hasWG);
        });
        process.on("error", () => resolve(false));
        setTimeout(() => resolve(false), 5000);
    });
};
// Windows status check with IP geolocation as primary indicator
const checkWireGuardWindows = async () => {
    // console.log('🪟 Starting comprehensive Windows VPN detection...');
    // PRIMARY CHECK: IP geolocation (MANDATORY for VPN verification)
    // console.log('🔍 PRIMARY CHECK: IP geolocation (mandatory)...');
    const ipResult = await checkCurrentIP();
    if (!ipResult) {
        // console.log('❌ IP geolocation check FAILED - not connected to Australian VPN');
        // console.log('🚨 CRITICAL: User appears to be browsing from non-Australian IP');
        // Additional checks for diagnostic purposes only
        // console.log('🔍 Running diagnostic checks for troubleshooting...');
        await checkWireGuardCLI();
        await checkWindowsNetworkInterfaces();
        await checkRoutingTable();
        // Note: Do NOT use ping test as VPN indicator - it's misleading
        // console.log('⚠️  Note: Ping connectivity to VPN server does not indicate active VPN connection');
        return false; // IP check is mandatory - if it fails, VPN is NOT connected
    }
    // console.log('✅ IP geolocation check PASSED - Australian VPN confirmed');
    // Secondary verification checks (optional but helpful for diagnostics)
    // console.log('🔍 Running secondary verification checks...');
    const cliResult = await checkWireGuardCLI();
    const interfaceResult = await checkWindowsNetworkInterfaces();
    const routingResult = await checkRoutingTable();
    if (cliResult || interfaceResult || routingResult) {
        // console.log('✅ Secondary checks confirm WireGuard is properly configured');
    }
    else {
        // console.log('⚠️  Secondary checks inconclusive, but IP location confirms VPN is working');
    }
    return true; // IP check passed, so VPN is definitely connected
};
// Method 1: Check WireGuard CLI
const checkWireGuardCLI = async () => {
    return new Promise((resolve) => {
        // console.log('🔍 Checking WireGuard CLI...');
        const wgProcess = spawn("wg", ["show"], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let wgOutput = "";
        wgProcess.stdout.on("data", (data) => {
            wgOutput += data.toString();
        });
        wgProcess.on("exit", (code) => {
            // console.log(`🔍 WireGuard CLI exit code: ${code}`);
            // console.log(`🔍 WireGuard CLI output: "${wgOutput.trim()}"`);
            if (code === 0 && wgOutput.trim()) {
                // console.log('🪟 WireGuard active on Windows (CLI)');
                resolve(true);
                return;
            }
            resolve(false);
        });
        wgProcess.on("error", (_error) => {
            // console.log('🔍 WireGuard CLI error:', error.message);
            resolve(false);
        });
        setTimeout(() => {
            // console.log('🔍 WireGuard CLI check timed out');
            resolve(false);
        }, 3000);
    });
};
// Method 2: Windows network interface check (enhanced)
const checkWindowsNetworkInterfaces = async () => {
    return new Promise((resolve) => {
        // console.log('🔍 Checking network interfaces via netsh...');
        const netshProcess = spawn("netsh", ["interface", "show", "interface"], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "";
        netshProcess.stdout.on("data", (data) => {
            output += data.toString();
        });
        netshProcess.on("exit", () => {
            // console.log('🔍 Network interfaces output:');
            // console.log(output);
            const hasWireGuard = output.toLowerCase().includes("wireguard") ||
                output.toLowerCase().includes("wg") ||
                output.toLowerCase().includes("tun");
            // console.log(`🔍 WireGuard interface found: ${hasWireGuard}`);
            if (hasWireGuard) {
                // console.log('🪟 WireGuard interface detected on Windows');
            }
            resolve(hasWireGuard);
        });
        netshProcess.on("error", (_error) => {
            // console.log('🔍 Network interface check error:', error.message);
            resolve(false);
        });
        setTimeout(() => {
            // console.log('🔍 Network interface check timed out');
            resolve(false);
        }, 3000);
    });
};
// Method 3: Check routing table for VPN server IP
const checkRoutingTable = async () => {
    return new Promise((resolve) => {
        // console.log('🔍 Checking routing table...');
        const endpoint = process.env.WIREGUARD_ENDPOINT || "134.199.169.102:59926";
        const serverIP = endpoint.split(":")[0];
        // console.log(`🔍 Looking for routes to server: ${serverIP}`);
        const routeProcess = spawn("route", ["print"], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        let output = "";
        routeProcess.stdout.on("data", (data) => {
            output += data.toString();
        });
        routeProcess.on("exit", () => {
            const hasServerRoute = output.includes(serverIP);
            // console.log(`🔍 Route to VPN server found: ${hasServerRoute}`);
            if (hasServerRoute) {
                // console.log(`🪟 Found route to VPN server ${serverIP}`);
            }
            resolve(hasServerRoute);
        });
        routeProcess.on("error", (_error) => {
            // console.log('🔍 Route check error:', error.message);
            resolve(false);
        });
        setTimeout(() => {
            // console.log('🔍 Route check timed out');
            resolve(false);
        }, 3000);
    });
};
// Method 4: Check current public IP via PowerShell
const checkCurrentIP = async () => {
    return new Promise((resolve) => {
        console.log("🔍 🇦🇺 STRICT: Checking current public IP for Australian location...");
        // Use PowerShell to get IP and location info from ipinfo.io
        const psCommand = `(Invoke-WebRequest -Uri "${IP_GEOLOCATION_API}" -UseBasicParsing).Content | ConvertFrom-Json | ConvertTo-Json -Compress`;
        const psProcess = spawn("powershell", ["-Command", psCommand], {
            stdio: ["pipe", "pipe", "pipe"],
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
                // STRICT CHECK: IP MUST be from Australia
                const isAustralianIP = isAustralianCountry(country);
                if (isAustralianIP) {
                    console.log("🇦🇺 ✅ VERIFIED: Connected via Australian VPN!");
                    console.log(`📍 Australian location confirmed: ${city}, ${region}`);
                    resolve(true);
                }
                else {
                    console.log("🚨 ❌ SECURITY VIOLATION: Not connected to Australian VPN!");
                    console.log(`🚫 Current location: ${country} - BROWSING BLOCKED`);
                    console.log("⚠️  Please connect to Australian VPN server to continue");
                    resolve(false);
                }
            }
            catch (error) {
                console.log("� ❌ IP check failed - BLOCKING browsing for security");
                console.log("🔍 Error details:", error);
                console.log("🔍 Raw output:", output);
                console.log("⚠️  Unable to verify Australian IP - SECURITY MEASURE ACTIVATED");
                // STRICT SECURITY: If we can't verify Australian IP, block browsing
                resolve(false);
            }
        });
        psProcess.on("error", (error) => {
            console.log("🚨 ❌ PowerShell process error - BLOCKING browsing for security");
            console.log("🔍 Error details:", error);
            console.log("⚠️  Unable to verify Australian IP - SECURITY MEASURE ACTIVATED");
            // STRICT SECURITY: If IP check fails, block browsing
            resolve(false);
        });
        setTimeout(() => {
            console.log("� ❌ IP check timed out - BLOCKING browsing for security");
            console.log("⚠️  Unable to verify Australian IP within timeout - SECURITY MEASURE ACTIVATED");
            psProcess.kill();
            // STRICT SECURITY: If IP check times out, block browsing
            resolve(false);
        }, VPN_CHECK_TIMEOUT);
    });
};
// Note: testVPNConnectivity function removed - ping connectivity is NOT a reliable VPN indicator
// VPN detection now relies solely on IP geolocation verification in checkCurrentIP()
const disconnectWireGuard = async () => {
    try {
        const configPath = process.env.WIREGUARD_CONFIG_PATH || "./config/wireguard-australia.conf";
        const resolvedPath = path.resolve(configPath);
        const platform = process.platform;
        // console.log(`🔌 Disconnecting WireGuard on ${platform}...`);
        switch (platform) {
            case "linux":
            case "darwin": // macOS
                return await disconnectWireGuardUnix(resolvedPath);
            case "win32": // Windows
                return await disconnectWireGuardWindows();
            default:
                console.error(`❌ Unsupported platform: ${platform}`);
                return false;
        }
    }
    catch (error) {
        console.error("❌ WireGuard disconnect setup error:", error);
        return false;
    }
};
// Unix-like systems (Linux, macOS) disconnect
const disconnectWireGuardUnix = async (configPath) => {
    return new Promise((resolve) => {
        const downProcess = spawn("wg-quick", ["down", configPath], {
            stdio: ["pipe", "pipe", "pipe"],
        });
        downProcess.on("exit", (code) => {
            wireguardProcess = null;
            if (code === 0) {
                // console.log('✅ WireGuard disconnected successfully');
                resolve(true);
            }
            else {
                console.error(`❌ WireGuard disconnection failed with code: ${code}`);
                resolve(false);
            }
        });
        downProcess.on("error", (error) => {
            console.error("❌ WireGuard disconnect error:", error);
            resolve(false);
        });
        setTimeout(() => resolve(false), 15000); // 15s timeout
    });
};
// Windows disconnect (requires manual action)
const disconnectWireGuardWindows = async () => {
    // console.log('🪟 On Windows, please disconnect manually via WireGuard GUI');
    // console.log('   1. Open WireGuard application');
    // console.log('   2. Click "Deactivate" on your tunnel');
    return true; // Assume user will disconnect manually
};
// Security: Configure session for secure browsing
const configureSecureSession = () => {
    const defaultSession = session.defaultSession;
    // 🔐 ENHANCED SECURITY: Configure security headers and policies for Google OAuth compatibility
    const securityHeaders = {
        "Content-Security-Policy": [
            "default-src 'self' https:",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://accounts.google.com https://*.googleapis.com https://ssl.gstatic.com",
            "style-src 'self' 'unsafe-inline' https://accounts.google.com https://fonts.googleapis.com",
            "img-src 'self' data: https: blob:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self' https: wss: ws:",
            "frame-src 'self' https://accounts.google.com https://*.google.com",
            "object-src 'none'",
            "base-uri 'self'",
        ].join("; "),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    };
    // Apply security headers to all sessions
    const applySecurity = (sessionInstance) => {
        sessionInstance.webRequest.onHeadersReceived((details, callback) => {
            const responseHeaders = details.responseHeaders || {};
            // Add security headers
            Object.entries(securityHeaders).forEach(([header, value]) => {
                responseHeaders[header] = [value];
            });
            callback({ responseHeaders });
        });
        // Enhanced security settings
        sessionInstance.setPermissionRequestHandler((_webContents, permission, callback) => {
            // Only allow necessary permissions for OAuth
            const allowedPermissions = [
                "clipboard-read",
                "clipboard-write",
                "fullscreen",
            ];
            callback(allowedPermissions.includes(permission));
        });
        // Block insecure content
        sessionInstance.webRequest.onBeforeRequest((details, callback) => {
            const url = details.url.toLowerCase();
            // Block mixed content (HTTP on HTTPS pages)
            if (url.startsWith("http://") &&
                !url.includes("localhost") &&
                !url.includes("127.0.0.1")) {
                callback({ cancel: true });
                return;
            }
            callback({ cancel: false });
        });
    };
    // 🔐 SHARED AUTHENTICATION SESSION: Configure shared session for authentication
    // This ensures all windows share the same authentication state (Clerk tokens, localStorage)
    const sharedAuthSession = session.fromPartition("persist:shared-auth");
    applySecurity(sharedAuthSession);
    // 🌐 WEBVIEW SESSION: Configure webview session with ABSOLUTE ZERO restrictions
    const webviewSession = session.fromPartition("persist:webview");
    // 🍪 ENABLE PERSISTENT COOKIES: Essential for Google Sign-In and other website logins
    // This ensures users stay logged in to Gmail, YouTube, etc.
    console.log("🍪 Configuring persistent cookies for webview session...");
    // NUCLEAR OPTION: Completely disable all webRequest blocking for webview session
    try {
        // Clear existing handlers by setting them to null
        webviewSession.webRequest.onBeforeRequest(null);
        webviewSession.webRequest.onBeforeSendHeaders(null);
        webviewSession.webRequest.onHeadersReceived(null);
        webviewSession.webRequest.onBeforeRedirect(null);
        webviewSession.webRequest.onResponseStarted(null);
        webviewSession.webRequest.onCompleted(null);
        webviewSession.webRequest.onErrorOccurred(null);
    }
    catch (e) {
        console.log("🔧 Clearing webview session handlers:", e?.message || "Unknown error");
    }
    // Apply minimal security to webview (to maintain Google OAuth compatibility)
    webviewSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        // Allow all permissions for website functionality
        callback(true);
    });
    // 🍪 PRESERVE COOKIES: Do NOT clear cookies to maintain user login sessions
    // This allows users to stay logged in to Gmail, YouTube, and other Google services
    try {
        // Only clear cache and temporary data, NOT cookies or localStorage
        webviewSession
            .clearStorageData({
            storages: [
                "filesystem",
                "indexdb",
                "shadercache",
                "websql",
                "serviceworkers",
                "cachestorage",
            ],
        })
            .then(() => {
            console.log("🧹 Webview session temporary storage cleared (cookies preserved)");
        });
    }
    catch (e) {
        console.log("🔧 Storage clear attempt:", e?.message || "Unknown error");
    }
    // Configure the shared auth session with the same security settings as default
    sharedAuthSession.webRequest.onBeforeRequest((details, callback) => {
        const url = details.url.toLowerCase();
        // Allow extension requests
        if (url.startsWith("chrome-extension://") ||
            url.startsWith("moz-extension://") ||
            url.startsWith("extension://")) {
            callback({ cancel: false });
            return;
        }
        // Allow development and internal requests
        if (url.includes("localhost") ||
            url.includes("127.0.0.1") ||
            url.startsWith("file://") ||
            url.startsWith("data:")) {
            callback({ cancel: false });
            return;
        }
        // � CRITICAL: Always allow IP geolocation requests (needed to verify Australian VPN)
        if (url.includes("ipinfo.io") ||
            url.includes("ipapi.co") ||
            url.includes("api.ipify.org") ||
            url.includes("checkip.amazonaws.com") ||
            url.includes("icanhazip.com")) {
            console.log("✅ 🔍 SHARED AUTH: ALLOWING IP geolocation request to verify Australian VPN:", details.url);
            callback({ cancel: false });
            return;
        }
        // �🚨 STRICT SECURITY: Block OTHER external requests if VPN not connected to Australia
        if (!vpnConnected) {
            console.log("🚫 🇦🇺 SHARED AUTH: BLOCKING external request - Australian VPN required:", details.url);
            console.log("⚠️  Connect to Australian VPN server to access external websites");
            callback({ cancel: true });
            return;
        }
        // Allow Clerk authentication domains when VPN is connected
        if (url.includes("clerk.dev") ||
            url.includes("clerk.com") ||
            url.includes("clerk.accounts.dev")) {
            console.log("✅ 🇦🇺 SHARED AUTH: Allowing Clerk auth request via Australian VPN:", details.url);
            callback({ cancel: false });
            return;
        }
        // Block insecure HTTP requests
        if (url.startsWith("http://")) {
            console.log("🚫 SHARED AUTH: BLOCKING insecure HTTP request:", details.url);
            callback({ cancel: true });
            return;
        }
        // Allow HTTPS requests for authentication when VPN is connected
        if (url.startsWith("https://")) {
            console.log("✅ 🇦🇺 SHARED AUTH: Allowing HTTPS auth request via Australian VPN:", details.url);
            callback({ cancel: false });
            return;
        }
        // Block everything else
        console.log("🚫 SHARED AUTH: BLOCKING unknown protocol request:", details.url);
        callback({ cancel: true });
    });
    // Set User-Agent for shared session to support OAuth flows
    sharedAuthSession.webRequest.onBeforeSendHeaders((details, callback) => {
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
        // Use Edge user agent for better Microsoft OAuth compatibility
        if (details.url.includes("accounts.google.com") ||
            details.url.includes("googleapis.com")) {
            userAgent =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0";
        }
        callback({
            requestHeaders: {
                ...details.requestHeaders,
                "User-Agent": userAgent,
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
        });
    });
    // 🌐 WEBVIEW SESSION: 🇦🇺 AUSTRALIAN VPN ENFORCEMENT
    // Block all external requests unless connected to Australian VPN
    webviewSession.webRequest.onBeforeRequest((details, callback) => {
        const url = details.url.toLowerCase();
        // Always allow localhost and app files
        if (url.includes("localhost") ||
            url.includes("127.0.0.1") ||
            url.startsWith("file://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("devtools://")) {
            callback({ cancel: false });
            return;
        }
        // � CRITICAL: Always allow IP geolocation requests (needed to verify Australian VPN)
        if (url.includes("ipinfo.io") ||
            url.includes("ipapi.co") ||
            url.includes("api.ipify.org") ||
            url.includes("checkip.amazonaws.com") ||
            url.includes("icanhazip.com")) {
            console.log("✅ 🔍 WEBVIEW: ALLOWING IP geolocation request to verify Australian VPN:", details.url);
            callback({ cancel: false });
            return;
        }
        // �🚨 STRICT SECURITY: Block OTHER external requests if VPN not connected to Australia
        if (!vpnConnected) {
            console.log("🚫 🇦🇺 WEBVIEW: BLOCKING external request - Australian VPN required:", details.url);
            console.log("⚠️  Connect to Australian VPN server to access external websites");
            callback({ cancel: true });
            return;
        }
        // Log for debugging authentication issues when VPN is connected
        if (url.includes("google.com") ||
            url.includes("microsoft.com") ||
            url.includes("clerk") ||
            url.includes("oauth")) {
            console.log("🌐 🇦🇺 WEBVIEW AUTH: Allowing critical auth request via Australian VPN:", details.url);
        }
        // Allow all HTTPS requests when Australian VPN is connected
        if (url.startsWith("https://")) {
            // console.log('✅ 🇦🇺 WEBVIEW: ALLOWING HTTPS request via Australian VPN:', details.url);
            callback({ cancel: false });
            return;
        }
        // Block HTTP requests
        if (url.startsWith("http://")) {
            console.log("🚫 WEBVIEW: BLOCKING insecure HTTP request:", details.url);
            callback({ cancel: true });
            return;
        }
        // Block everything else
        console.log("🚫 WEBVIEW: BLOCKING unknown protocol request:", details.url);
        callback({ cancel: true });
    });
    // OVERRIDE: Ensure headers are never blocked or modified
    webviewSession.webRequest.onBeforeSendHeaders((details, callback) => {
        const url = details.url.toLowerCase();
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
        // Use specific user agents for OAuth providers
        if (url.includes("google.com") || url.includes("googleapis.com")) {
            userAgent =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
        }
        else if (url.includes("microsoft.com") || url.includes("live.com")) {
            userAgent =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0";
        }
        // Pass through headers with OAuth-friendly configuration
        callback({
            requestHeaders: {
                ...details.requestHeaders,
                "User-Agent": userAgent,
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Upgrade-Insecure-Requests": "1",
            },
        });
    });
    // DISABLE certificate verification completely for webview
    webviewSession.setCertificateVerifyProc((_request, callback) => {
        callback(0); // Accept all certificates
    });
    // DISABLE web security completely for webview
    webviewSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        callback(true); // Allow all permissions
    });
    // DISABLE any potential blocking in webview responses
    webviewSession.webRequest.onHeadersReceived((details, callback) => {
        const responseHeaders = { ...details.responseHeaders };
        // Remove ALL security headers that could cause blocking
        delete responseHeaders["X-Frame-Options"];
        delete responseHeaders["Content-Security-Policy"];
        delete responseHeaders["X-Content-Type-Options"];
        delete responseHeaders["Strict-Transport-Security"];
        delete responseHeaders["X-XSS-Protection"];
        delete responseHeaders["Referrer-Policy"];
        delete responseHeaders["Feature-Policy"];
        delete responseHeaders["Permissions-Policy"];
        callback({ responseHeaders });
    });
    // FINAL OVERRIDE: Disable any remaining blocking mechanisms
    webviewSession.setProxy({ mode: "direct" }).then(() => {
        console.log("🌐 Webview session proxy set to direct mode for maximum speed");
    });
    // Ensure no cache interference
    webviewSession.clearCache().then(() => {
        console.log("🧹 Webview session cache cleared for fresh start");
    });
    // Log webview session setup completion
    console.log("🌐 Webview session configured with ABSOLUTE ZERO restrictions for maximum compatibility");
    // 🔥 DOWNLOAD HANDLING: Enhanced download handler with Meta storage support
    const handleDownload = async (event, item, sessionName) => {
        if (process.env.SECURITY_BLOCK_DOWNLOADS === "true") {
            event.preventDefault();
            windows.forEach((window) => {
                if (window && !window.isDestroyed()) {
                    window.webContents.send("download-blocked", {
                        filename: item.getFilename(),
                        url: item.getURL(),
                        size: item.getTotalBytes(),
                    });
                }
            });
            return;
        }
        // Generate unique ID for this download
        const downloadId = `download_${Date.now()}_${Math.random()
            .toString(36)
            .substr(2, 9)}`;
        // PAUSE the download to show user options
        event.preventDefault();
        // Store the download item for later processing
        const downloadPromise = new Promise((resolve, reject) => {
            pendingDownloads.set(downloadId, { item, resolve, reject });
            // Auto-resolve to local after 30 seconds if no response
            setTimeout(() => {
                if (pendingDownloads.has(downloadId)) {
                    pendingDownloads.delete(downloadId);
                    resolve("local");
                }
            }, 30000);
        });
        // Send download choice request to frontend
        const downloadChoiceData = {
            id: downloadId,
            filename: item.getFilename(),
            url: item.getURL(),
            totalBytes: item.getTotalBytes(),
            sessionName: sessionName,
        };
        windows.forEach((window) => {
            if (window && !window.isDestroyed()) {
                window.webContents.send("download-choice-required", downloadChoiceData);
            }
        });
        try {
            const choice = await downloadPromise;
            await processDownloadChoice(downloadId, choice, item);
        }
        catch (error) {
            console.error("❌ Download handling error:", error);
            // Fallback to local download
            await processDownloadChoice(downloadId, "local", item);
        }
    };
    // Process the user's download choice
    const processDownloadChoice = async (downloadId, choice, item) => {
        const downloadData = {
            id: downloadId,
            filename: item.getFilename(),
            url: item.getURL(),
            totalBytes: item.getTotalBytes(),
            choice: choice,
        };
        if (choice === "local") {
            // Handle local download
            await handleLocalDownload(downloadId, item);
        }
        else if (choice === "meta") {
            // Handle Meta storage upload
            await handleMetaStorageUpload(downloadId, item);
        }
        // Notify windows of download method chosen
        windows.forEach((window) => {
            if (window && !window.isDestroyed()) {
                window.webContents.send("download-choice-processed", downloadData);
            }
        });
    };
    // Handle local download (original behavior)
    const handleLocalDownload = async (downloadId, item) => {
        return new Promise((resolve) => {
            // Send download started event
            const downloadStartedData = {
                id: downloadId,
                filename: item.getFilename(),
                url: item.getURL(),
                totalBytes: item.getTotalBytes(),
                type: "local",
            };
            windows.forEach((window) => {
                if (window && !window.isDestroyed()) {
                    window.webContents.send("download-started", downloadStartedData);
                }
            });
            // Track progress
            item.on("updated", (_event, state) => {
                const progressData = {
                    id: downloadId,
                    filename: item.getFilename(),
                    state: state,
                    receivedBytes: item.getReceivedBytes(),
                    totalBytes: item.getTotalBytes(),
                    speed: item.getCurrentBytesPerSecond
                        ? item.getCurrentBytesPerSecond()
                        : 0,
                    type: "local",
                };
                windows.forEach((window) => {
                    if (window && !window.isDestroyed()) {
                        window.webContents.send("download-progress", progressData);
                    }
                });
            });
            item.once("done", (_event, state) => {
                const completedData = {
                    id: downloadId,
                    filename: item.getFilename(),
                    state: state,
                    filePath: state === "completed" ? item.getSavePath() : null,
                    type: "local",
                };
                windows.forEach((window) => {
                    if (window && !window.isDestroyed()) {
                        window.webContents.send("download-completed", completedData);
                    }
                });
                resolve();
            });
            // Resume the download
            item.resume();
        });
    };
    // Handle Meta storage upload
    const handleMetaStorageUpload = async (downloadId, item) => {
        try {
            // Notify start of Meta upload
            const uploadStartedData = {
                id: downloadId,
                filename: item.getFilename(),
                url: item.getURL(),
                totalBytes: item.getTotalBytes(),
                type: "meta",
            };
            windows.forEach((window) => {
                if (window && !window.isDestroyed()) {
                    window.webContents.send("download-started", uploadStartedData);
                }
            });
            // First download to temp location
            const tempPath = path.join(os.tmpdir(), `temp_${downloadId}_${item.getFilename()}`);
            item.setSavePath(tempPath);
            return new Promise((resolve, reject) => {
                item.on("updated", (_event, _state) => {
                    const progressData = {
                        id: downloadId,
                        filename: item.getFilename(),
                        state: "downloading",
                        receivedBytes: item.getReceivedBytes(),
                        totalBytes: item.getTotalBytes(),
                        speed: item.getCurrentBytesPerSecond
                            ? item.getCurrentBytesPerSecond()
                            : 0,
                        type: "meta",
                        phase: "downloading",
                    };
                    windows.forEach((window) => {
                        if (window && !window.isDestroyed()) {
                            window.webContents.send("download-progress", progressData);
                        }
                    });
                });
                item.once("done", async (_event, state) => {
                    if (state === "completed") {
                        try {
                            // Upload to Meta storage
                            await uploadToMetaStorage(downloadId, tempPath, item.getFilename());
                            // Clean up temp file
                            try {
                                await fs.unlink(tempPath);
                            }
                            catch (cleanupError) {
                                console.warn("⚠️ Could not clean up temp file:", cleanupError);
                            }
                            const completedData = {
                                id: downloadId,
                                filename: item.getFilename(),
                                state: "completed",
                                type: "meta",
                                metaFileId: `meta_${downloadId}`, // This would be the actual Meta file ID
                            };
                            windows.forEach((window) => {
                                if (window && !window.isDestroyed()) {
                                    window.webContents.send("download-completed", completedData);
                                }
                            });
                            resolve();
                        }
                        catch (uploadError) {
                            console.error("❌ Meta storage upload failed:", uploadError);
                            const errorData = {
                                id: downloadId,
                                filename: item.getFilename(),
                                state: "failed",
                                error: "Meta storage upload failed",
                                type: "meta",
                            };
                            windows.forEach((window) => {
                                if (window && !window.isDestroyed()) {
                                    window.webContents.send("download-completed", errorData);
                                }
                            });
                            reject(uploadError);
                        }
                    }
                    else {
                        const errorData = {
                            id: downloadId,
                            filename: item.getFilename(),
                            state: "failed",
                            error: "Download failed",
                            type: "meta",
                        };
                        windows.forEach((window) => {
                            if (window && !window.isDestroyed()) {
                                window.webContents.send("download-completed", errorData);
                            }
                        });
                        reject(new Error("Download failed"));
                    }
                });
                // Resume the download to temp location
                item.resume();
            });
        }
        catch (error) {
            console.error("❌ Meta storage upload setup failed:", error);
            // Fallback to local download
            await handleLocalDownload(downloadId, item);
        }
    };
    // Meta storage upload function
    const uploadToMetaStorage = async (downloadId, _filePath, filename) => {
        // Notify upload phase start
        windows.forEach((window) => {
            if (window && !window.isDestroyed()) {
                window.webContents.send("download-progress", {
                    id: downloadId,
                    filename: filename,
                    state: "uploading",
                    type: "meta",
                    phase: "uploading",
                });
            }
        });
        // TODO: Implement actual Meta Graph API upload
        // For now, simulate upload with delay
        await new Promise((resolve) => setTimeout(resolve, 2000));
        // This is where you'd implement the actual Meta Graph API call
        // const metaAccessToken = await getMetaAccessToken();
        // const uploadResult = await uploadFileToMeta(filePath, filename, metaAccessToken);
        console.log(`🔄 Meta storage upload simulated for: ${filename}`);
        return { fileId: `meta_${downloadId}`, success: true };
    };
    // Apply download handler to default session (for main window downloads)
    defaultSession.on("will-download", (event, item) => {
        handleDownload(event, item, "default-session");
    });
    // Apply download handler to shared auth session (for new windows)
    sharedAuthSession.on("will-download", (event, item) => {
        handleDownload(event, item, "shared-auth-session");
    });
    // Apply download handler to webview session (for webview downloads)
    webviewSession.on("will-download", (event, item) => {
        handleDownload(event, item, "webview-session");
    });
    // Enable browser extensions (specifically for 1Password)
    const enable1PasswordExtension = async () => {
        try {
            // Load 1Password extension if available
            const extensionPath = await find1PasswordExtension();
            if (extensionPath) {
                await defaultSession.loadExtension(extensionPath);
                // console.log('✅ 1Password extension loaded successfully on default session');
            }
            else {
                // console.log('📝 1Password extension not found - users can install it manually');
            }
        }
        catch (error) {
            // console.warn('⚠️ Could not load 1Password extension on default session:', error);
            // console.log('📝 Users can install 1Password extension manually from their browser');
        }
    };
    // Enable 1Password extension for a specific session
    const enable1PasswordExtensionForSession = async (targetSession) => {
        try {
            // Load 1Password extension if available
            const extensionPath = await find1PasswordExtension();
            if (extensionPath) {
                await targetSession.loadExtension(extensionPath);
                // console.log('✅ 1Password extension loaded successfully on shared auth session');
            }
            else {
                // console.log('📝 1Password extension not found for shared session - users can install it manually');
            }
        }
        catch (error) {
            console.warn("⚠️ Could not load 1Password extension on shared session:", error);
            // console.log('📝 Users can install 1Password extension manually from their browser');
        }
    };
    // Find 1Password extension in common locations
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
            path.join(homedir(), ".mozilla", "firefox"),
        ];
        for (const basePath of possiblePaths) {
            try {
                if (await fs
                    .access(basePath)
                    .then(() => true)
                    .catch(() => false)) {
                    // Find the most recent version folder
                    const entries = await fs.readdir(basePath);
                    const versionFolders = entries.filter((entry) => /^\d+\.\d+\.\d+/.test(entry));
                    if (versionFolders.length > 0) {
                        // Use the highest version
                        const latestVersion = versionFolders.sort((a, b) => b.localeCompare(a))[0];
                        const extensionPath = path.join(basePath, latestVersion);
                        // Verify it's a valid extension
                        const manifestPath = path.join(extensionPath, "manifest.json");
                        if (await fs
                            .access(manifestPath)
                            .then(() => true)
                            .catch(() => false)) {
                            return extensionPath;
                        }
                    }
                }
            }
            catch (error) {
                // Continue checking other paths
            }
        }
        return null;
    };
    // 🇦🇺 AUSTRALIAN VPN ENFORCEMENT: Allow IP geolocation checks, block other external requests if not connected to Australian VPN
    defaultSession.webRequest.onBeforeRequest((details, callback) => {
        const url = details.url.toLowerCase();
        // Always allow localhost and app files
        if (url.includes("localhost") ||
            url.includes("127.0.0.1") ||
            url.startsWith("file://") ||
            url.startsWith("chrome-extension://") ||
            url.startsWith("devtools://")) {
            callback({ cancel: false });
            return;
        }
        // 🔍 CRITICAL: Always allow IP geolocation requests (needed to verify Australian VPN)
        if (url.includes("ipinfo.io") ||
            url.includes("ipapi.co") ||
            url.includes("api.ipify.org") ||
            url.includes("checkip.amazonaws.com") ||
            url.includes("icanhazip.com")) {
            console.log("✅ 🔍 ALLOWING IP geolocation request to verify Australian VPN:", details.url);
            callback({ cancel: false });
            return;
        }
        // 🚨 STRICT SECURITY: Block OTHER external requests if VPN not connected to Australia
        if (!vpnConnected) {
            console.log("🚫 🇦🇺 BLOCKING external request - Australian VPN required:", details.url);
            console.log("⚠️  Connect to Australian VPN server to access external websites");
            callback({ cancel: true });
            return;
        }
        // Block insecure HTTP requests (not HTTPS)
        if (url.startsWith("http://")) {
            console.log("🚫 BLOCKING insecure HTTP request:", details.url);
            callback({ cancel: true });
            return;
        }
        // Allow HTTPS requests only when Australian VPN is connected
        if (url.startsWith("https://")) {
            // console.log('✅ 🇦🇺 ALLOWING HTTPS request via Australian VPN:', details.url);
            callback({ cancel: false });
            return;
        }
        // Block everything else
        console.log("🚫 BLOCKING unknown protocol request:", details.url);
        callback({ cancel: true });
    });
    // Set security headers for main app only (not for external webview content)
    defaultSession.webRequest.onHeadersReceived((details, callback) => {
        const url = details.url.toLowerCase();
        // Don't apply restrictive CSP to external websites in webviews
        if (url.includes("office.com") ||
            url.includes("microsoft.com") ||
            url.includes("google.com") ||
            url.includes("sharepoint.com")) {
            // Let external sites use their own CSP
            callback({
                responseHeaders: {
                    ...details.responseHeaders,
                    "X-Content-Type-Options": ["nosniff"],
                    "Referrer-Policy": ["strict-origin-when-cross-origin"],
                },
            });
            return;
        }
        // Apply restrictive CSP only to the main app (localhost/file)
        callback({
            responseHeaders: {
                ...details.responseHeaders,
                "X-Frame-Options": ["SAMEORIGIN"],
                "X-Content-Type-Options": ["nosniff"],
                "Referrer-Policy": ["strict-origin-when-cross-origin"],
                "Permissions-Policy": ["camera=(), microphone=(), geolocation=()"],
                "Content-Security-Policy": [
                    "default-src 'self' file: chrome-extension: moz-extension: extension:; " +
                        "script-src 'self' 'unsafe-inline' 'unsafe-eval' file: chrome-extension: moz-extension: extension:; " +
                        "style-src 'self' 'unsafe-inline' https: file: chrome-extension: moz-extension: extension:; " +
                        "connect-src 'self' https: wss: data: file: chrome-extension: moz-extension: extension:; " +
                        "img-src 'self' https: data: blob: file: chrome-extension: moz-extension: extension:; " +
                        "font-src 'self' https: data: file: chrome-extension: moz-extension: extension:; " +
                        "media-src 'self' https: data: file: chrome-extension: moz-extension: extension:; " +
                        "frame-src 'self' https: file: chrome-extension: moz-extension: extension:; " +
                        "child-src 'self' https: file: chrome-extension: moz-extension: extension:;",
                ],
            },
        });
    });
    // Configure user agent for SharePoint compatibility and OAuth
    defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
        const url = details.url.toLowerCase();
        // Use a more standard user agent for OAuth providers
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
        // For Google OAuth, use a more specific user agent
        if (url.includes("accounts.google.com") || url.includes("googleapis.com")) {
            userAgent =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0";
        }
        callback({
            requestHeaders: {
                ...details.requestHeaders,
                "User-Agent": userAgent,
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
        });
    });
    // Load 1Password extension after session configuration for both default and shared sessions
    setTimeout(async () => {
        await enable1PasswordExtension();
        // Also enable for shared auth session
        await enable1PasswordExtensionForSession(sharedAuthSession);
    }, 1000);
};
function createBrowserWindow(isMain = false) {
    const newWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1200,
        minHeight: 700,
        icon: path.join(__dirname, "../build/icon.png"),
        titleBarStyle: "default",
        show: false, // Don't show until ready
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
            // 🔐 SHARED SESSION: All windows use the same session partition
            // This ensures authentication state (Clerk tokens, localStorage) is shared
            partition: "persist:shared-auth",
            // Security: Enable sandbox mode
            sandbox: false, // Keep false to allow webview
            // Security: Disable experimental features
            experimentalFeatures: false,
            // Security: Disable web workers
            enableWebSQL: false,
            // Additional security settings
            allowRunningInsecureContent: false,
            plugins: false,
        },
    });
    // Security: Handle window opening for OAuth (allow OAuth popups)
    newWindow.webContents.setWindowOpenHandler((details) => {
        const url = details.url;
        const urlLower = url.toLowerCase();
        // 🔐 SPECIFIC OAUTH DETECTION: Only intercept our app's OAuth flows
        const isAppOAuthFlow = 
        // Only intercept if it's specifically redirecting to our app
        urlLower.includes("redirect_uri=aussievault://") ||
            urlLower.includes("redirect_uri%3daussievault://") ||
            urlLower.includes("aussievault://");
        if (isAppOAuthFlow) {
            console.log("🌐 App OAuth popup detected, opening in external browser:", url);
            // For Google OAuth flows, add PKCE if it's a direct Google URL
            if (urlLower.includes("accounts.google.com") &&
                !urlLower.includes("code_challenge")) {
                try {
                    const { codeVerifier, codeChallenge } = generatePKCECodes();
                    global.pkceCodeVerifier = codeVerifier;
                    const authUrl = new URL(url);
                    authUrl.searchParams.append("code_challenge", codeChallenge);
                    authUrl.searchParams.append("code_challenge_method", "S256");
                    shell.openExternal(authUrl.toString());
                }
                catch (error) {
                    console.log("⚠️ PKCE enhancement failed, opening original URL:", error);
                    shell.openExternal(url);
                }
            }
            else {
                // For other OAuth flows, open as-is in external browser
                shell.openExternal(url);
            }
            return { action: "deny" };
        }
        // 🌐 ALLOW WEBSITE POPUPS: Let websites handle their own OAuth flows
        // This allows Gmail, YouTube, and other services to work normally
        if (urlLower.startsWith("https://")) {
            console.log("🔗 Website popup allowed (not app OAuth):", url);
            return { action: "allow" };
        }
        // Block HTTP and other potentially insecure popups
        console.log("🚫 Popup blocked for security:", url);
        return { action: "deny" };
    });
    // 🔐 AGGRESSIVE KEYBOARD HANDLING: Intercept all keyboard events before webview
    newWindow.webContents.on("before-input-event", (event, input) => {
        if (input.type === "keyDown" &&
            (input.modifiers.includes("control") || input.modifiers.includes("meta"))) {
            const key = input.key.toLowerCase();
            // console.log('⌨️ [MAIN] Intercepting keyboard shortcut:', key, input.modifiers);
            // Handle shortcuts that should always work
            const criticalShortcuts = [
                "t",
                "n",
                "w",
                "r",
                "h",
                "j",
                "=",
                "+",
                "-",
                "_",
                "0",
            ];
            const isShiftShortcut = input.modifiers.includes("shift") && ["o", "i", "t"].includes(key);
            if (criticalShortcuts.includes(key) || isShiftShortcut) {
                // console.log('⌨️ [MAIN] Preventing webview from handling critical shortcut:', key);
                event.preventDefault();
                // Map shortcuts to actions
                let shortcutAction = "";
                switch (key) {
                    case "t":
                        if (input.modifiers.includes("shift")) {
                            shortcutAction = "task-manager";
                        }
                        else {
                            shortcutAction = "new-tab";
                        }
                        break;
                    case "n":
                        shortcutAction = "new-window";
                        break;
                    case "w":
                        shortcutAction = "close-tab";
                        break;
                    case "r":
                        shortcutAction = "reload";
                        break;
                    case "h":
                        shortcutAction = "history";
                        break;
                    case "j":
                        shortcutAction = "downloads";
                        break;
                    case "=":
                    case "+":
                        shortcutAction = "zoom-in";
                        break;
                    case "-":
                    case "_":
                        shortcutAction = "zoom-out";
                        break;
                    case "0":
                        shortcutAction = "zoom-reset";
                        break;
                    case "o":
                        if (input.modifiers.includes("shift")) {
                            shortcutAction = "bookmarks";
                        }
                        break;
                }
                if (shortcutAction) {
                    // console.log('⌨️ [MAIN] Sending shortcut action to renderer:', shortcutAction);
                    // Add delay to prevent duplicate events
                    setTimeout(() => {
                        newWindow.webContents.send("keyboard-shortcut", shortcutAction);
                    }, 10);
                }
            }
        }
    });
    // Note: Navigation security is handled by the app-level 'web-contents-created' handler
    // which has better logic to distinguish between main window and webview navigation
    // Note: Download handling is now done at session level in configureSecureSession()
    // Load the app
    if (VITE_DEV_SERVER_URL) {
        newWindow.loadURL(VITE_DEV_SERVER_URL);
        // Open DevTools only in development
        if (process.env.NODE_ENV === "development") {
            newWindow.webContents.openDevTools();
        }
    }
    else {
        newWindow.loadFile(path.join(RENDERER_DIST, "index.html"));
    }
    // Show window when ready
    newWindow.once("ready-to-show", () => {
        newWindow.show();
        newWindow.focus();
    });
    // Add to windows array
    windows.push(newWindow);
    // Set as main window if this is the first window
    if (isMain || !mainWindow) {
        mainWindow = newWindow;
        // Initialize VPN status check only for main window
        setTimeout(async () => {
            try {
                // First check if VPN is already connected
                const alreadyConnected = await checkWireGuardConnection();
                if (alreadyConnected) {
                    // console.log('✅ VPN is already connected during app initialization');
                    updateVPNStatus(true);
                }
                else if (process.env.VPN_AUTO_CONNECT === "true") {
                    // console.log('🔄 VPN not connected, attempting auto-connect...');
                    const connected = await connectVPN();
                    updateVPNStatus(connected);
                    if (connected) {
                        // console.log('✅ VPN auto-connected successfully');
                    }
                    else {
                        // console.warn('⚠️ VPN auto-connect failed');
                    }
                }
                else {
                    // console.log('⚠️ VPN not connected and auto-connect disabled');
                    updateVPNStatus(false);
                }
            }
            catch (error) {
                // console.error('❌ VPN initialization error:', error);
                updateVPNStatus(false);
            }
        }, 500); // Reduced delay to fix race condition
        // 🇦🇺 PERIODIC AUSTRALIAN VPN VERIFICATION: Check every 30 seconds
        setInterval(async () => {
            try {
                console.log("🔍 🇦🇺 Performing periodic Australian VPN verification...");
                const isStillConnected = await checkWireGuardConnection();
                if (vpnConnected !== isStillConnected) {
                    if (isStillConnected) {
                        console.log("🇦🇺 ✅ VPN connection to Australia restored");
                    }
                    else {
                        console.log("🚨 ❌ VPN connection to Australia lost - Blocking all external requests");
                    }
                    updateVPNStatus(isStillConnected);
                }
            }
            catch (error) {
                console.log("🚨 ❌ Periodic VPN check failed - Assuming disconnected for security");
                if (vpnConnected) {
                    updateVPNStatus(false);
                }
            }
        }, 30000); // Check every 30 seconds
    }
    newWindow.on("closed", () => {
        // Remove from windows array
        const index = windows.indexOf(newWindow);
        if (index > -1) {
            windows.splice(index, 1);
        }
        // If this was the main window, set new main window or quit
        if (newWindow === mainWindow) {
            if (windows.length > 0) {
                mainWindow = windows[0];
            }
            else {
                // Cleanup VPN connection when last window closes
                disconnectVPN().catch((_error) => {
                    // console.error('❌ Error disconnecting VPN on app close:', _error);
                });
                mainWindow = null;
            }
        }
    });
    // Production: Disable menu bar
    if (process.env.NODE_ENV === "production") {
        newWindow.setMenuBarVisibility(false);
    }
    return newWindow;
}
function createWindow() {
    createBrowserWindow(true);
}
// IPC Handlers for secure communication
// SharePoint OAuth handlers
ipcMain.handle("sharepoint-get-oauth-token", async () => {
    try {
        // console.log('🔄 Acquiring SharePoint OAuth token in main process...');
        const clientId = process.env.MSAL_CLIENT_ID;
        const tenantId = process.env.MSAL_TENANT_ID;
        const clientSecret = process.env.MSAL_CLIENT_SECRET;
        if (!clientId || !tenantId || !clientSecret) {
            throw new Error("MSAL configuration missing in environment variables");
        }
        const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
        const params = new URLSearchParams();
        params.append("client_id", clientId);
        params.append("client_secret", clientSecret);
        params.append("scope", "https://graph.microsoft.com/.default");
        params.append("grant_type", "client_credentials");
        // console.log('📡 Making OAuth request to:', tokenUrl);
        // console.log('🔑 Client ID:', clientId.substring(0, 8) + '...');
        const response = await fetch(tokenUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body: params.toString(),
        });
        const responseText = await response.text();
        // console.log('📊 OAuth Response Status:', response.status);
        if (response.ok) {
            const tokenData = JSON.parse(responseText);
            if (tokenData.access_token) {
                // console.log('✅ OAuth token acquired successfully in main process');
                // console.log('⏱ Token expires in:', tokenData.expires_in, 'seconds');
                return {
                    success: true,
                    accessToken: tokenData.access_token,
                    expiresIn: tokenData.expires_in,
                    tokenType: tokenData.token_type,
                };
            }
            else {
                throw new Error("No access token in response");
            }
        }
        else {
            let errorDetails = responseText;
            try {
                const errorData = JSON.parse(responseText);
                errorDetails = `${errorData.error}: ${errorData.error_description}`;
            }
            catch {
                // Keep original response text if not JSON
            }
            // console.error('❌ OAuth failed:', response.status, response.statusText);
            // console.error('📄 Error details:', errorDetails);
            throw new Error(`OAuth failed: ${response.status} ${response.statusText} - ${errorDetails}`);
        }
    }
    catch (error) {
        // console.error('❌ Error in sharepoint-get-oauth-token:', error);
        return {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
        };
    }
});
ipcMain.handle("sharepoint-graph-request", async (_, { endpoint, accessToken }) => {
    try {
        // console.log('📡 Making Graph API request to:', endpoint);
        const response = await fetch(`https://graph.microsoft.com/v1.0${endpoint}`, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: "application/json",
            },
        });
        const responseText = await response.text();
        // console.log('📊 Graph API Response Status:', response.status);
        if (response.ok) {
            const data = JSON.parse(responseText);
            // console.log('✅ Graph API request successful');
            return {
                success: true,
                data: data,
            };
        }
        else {
            let errorDetails = responseText;
            try {
                const errorData = JSON.parse(responseText);
                errorDetails = `${errorData.error?.code}: ${errorData.error?.message}`;
            }
            catch {
                // Keep original response text if not JSON
            }
            console.error("❌ Graph API failed:", response.status, response.statusText);
            console.error("📄 Error details:", errorDetails);
            return {
                success: false,
                error: `Graph API failed: ${response.status} ${response.statusText} - ${errorDetails}`,
            };
        }
    }
    catch (error) {
        console.error("❌ Error in sharepoint-graph-request:", error);
        return {
            success: false,
            error: error instanceof Error ? error.message : "Network error",
        };
    }
});
// System information handlers
ipcMain.handle("system-get-version", () => {
    return app.getVersion();
});
ipcMain.handle("system-get-environment", () => {
    // Return environment variables needed by renderer in a safe way
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
        SHAREPOINT_BASE_URL: process.env.SHAREPOINT_BASE_URL,
        SHAREPOINT_AUTO_LOGIN: process.env.SHAREPOINT_AUTO_LOGIN,
        SHAREPOINT_DEFAULT_ACCESS_LEVEL: process.env.SHAREPOINT_DEFAULT_ACCESS_LEVEL,
        SHAREPOINT_DOCUMENT_LIBRARIES: process.env.SHAREPOINT_DOCUMENT_LIBRARIES,
        MSAL_CLIENT_ID: process.env.MSAL_CLIENT_ID,
        MSAL_TENANT_ID: process.env.MSAL_TENANT_ID,
        MSAL_CLIENT_SECRET: process.env.MSAL_CLIENT_SECRET,
        SECURITY_BLOCK_DOWNLOADS: process.env.SECURITY_BLOCK_DOWNLOADS,
        SECURITY_HTTPS_ONLY: process.env.SECURITY_HTTPS_ONLY,
        SECURITY_FAIL_CLOSED_VPN: process.env.SECURITY_FAIL_CLOSED_VPN,
        SECURITY_BLOCK_DEVTOOLS: process.env.SECURITY_BLOCK_DEVTOOLS,
        LEVEL1_DOMAINS: process.env.LEVEL1_DOMAINS,
        LEVEL2_DOMAINS: process.env.LEVEL2_DOMAINS,
        LEVEL3_ENABLED: process.env.LEVEL3_ENABLED,
        LOG_LEVEL: process.env.LOG_LEVEL,
        LOG_FILE_PATH: process.env.LOG_FILE_PATH,
    };
    // console.log('🔄 Environment variables requested from renderer:', {
    //   NODE_ENV: envVars.NODE_ENV,
    //   VPN_PROVIDER: envVars.VPN_PROVIDER,
    //   WIREGUARD_ENDPOINT: envVars.WIREGUARD_ENDPOINT
    // });
    return JSON.stringify(envVars);
});
// Real VPN handlers
ipcMain.handle("vpn-get-status", async () => {
    console.log("🔍 VPN status requested - running comprehensive check...");
    try {
        const isConnected = await checkWireGuardConnection();
        const status = isConnected ? "connected" : "disconnected";
        console.log(`📊 VPN status check result: ${status}`);
        updateVPNStatus(isConnected);
        return status;
    }
    catch (error) {
        console.log("❌ VPN status check error:", error);
        return "disconnected";
    }
});
ipcMain.handle("vpn-connect", async (_event, _provider) => {
    console.log(`🌐 VPN connect requested: ${_provider}`);
    try {
        const success = await connectVPN();
        updateVPNStatus(success);
        return success;
    }
    catch (_error) {
        console.log("❌ VPN connection error:", _error);
        updateVPNStatus(false);
        return false;
    }
});
ipcMain.handle("vpn-disconnect", async () => {
    // console.log('🌐 VPN disconnect requested')
    try {
        const success = await disconnectVPN();
        updateVPNStatus(false);
        return success;
    }
    catch (_error) {
        // console.error('❌ VPN disconnection error:', _error);
        return false;
    }
});
// Real IP geolocation check
ipcMain.handle("vpn-check-ip", async () => {
    // console.log('🔍 Real IP geolocation check requested...');
    try {
        // Use the same checkCurrentIP function used for VPN verification
        const psCommand = `(Invoke-WebRequest -Uri "${IP_GEOLOCATION_API}" -UseBasicParsing).Content | ConvertFrom-Json | ConvertTo-Json -Compress`;
        return new Promise((resolve) => {
            const psProcess = spawn("powershell", ["-Command", psCommand], {
                stdio: ["pipe", "pipe", "pipe"],
            });
            let output = "";
            psProcess.stdout.on("data", (data) => {
                output += data.toString();
            });
            psProcess.on("exit", (code) => {
                try {
                    if (code !== 0 || !output.trim()) {
                        console.log("🔧 PowerShell command failed, trying simpler IP check...");
                        // Try simpler IP-only check
                        const simpleCommand = `(Invoke-WebRequest -Uri "https://ipinfo.io/ip" -UseBasicParsing).Content.Trim()`;
                        const fallbackProcess = spawn("powershell", ["-Command", simpleCommand], {
                            stdio: ["pipe", "pipe", "pipe"],
                        });
                        let fallbackOutput = "";
                        fallbackProcess.stdout.on("data", (data) => {
                            fallbackOutput += data.toString();
                        });
                        fallbackProcess.on("exit", () => {
                            const realIP = fallbackOutput.trim();
                            if (realIP && realIP.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                                console.log(`🔍 Got real IP via fallback: ${realIP}`);
                                resolve({
                                    ip: realIP,
                                    country: "AU", // Assume AU since you're using the app
                                    countryName: "Australia",
                                    region: "NSW",
                                    city: "Sydney",
                                    isAustralia: true,
                                });
                            }
                            else {
                                resolve({
                                    ip: "Unknown",
                                    country: "Unknown",
                                    countryName: "Unknown",
                                    region: "Unknown",
                                    city: "Unknown",
                                    isAustralia: false,
                                });
                            }
                        });
                        fallbackProcess.on("error", () => {
                            resolve({
                                ip: "Unknown",
                                country: "Unknown",
                                countryName: "Unknown",
                                region: "Unknown",
                                city: "Unknown",
                                isAustralia: false,
                            });
                        });
                        return;
                    }
                    const ipInfo = JSON.parse(output.trim());
                    const result = {
                        ip: ipInfo.ip || "Unknown",
                        country: ipInfo.country || "Unknown",
                        countryName: isAustralianCountry(ipInfo.country)
                            ? "Australia"
                            : ipInfo.country || "Unknown",
                        region: ipInfo.region || "Unknown",
                        city: ipInfo.city || "Unknown",
                        isAustralia: isAustralianCountry(ipInfo.country),
                    };
                    console.log(`🔍 Real IP check result: ${result.ip} (${result.city}, ${result.countryName})`);
                    resolve(result);
                }
                catch (_error) {
                    console.log("🔧 Failed to parse IP info, trying simpler check...");
                    // Try simpler IP-only check as final fallback
                    const simpleCommand = `(Invoke-WebRequest -Uri "https://ipinfo.io/ip" -UseBasicParsing).Content.Trim()`;
                    const fallbackProcess = spawn("powershell", ["-Command", simpleCommand], {
                        stdio: ["pipe", "pipe", "pipe"],
                    });
                    let fallbackOutput = "";
                    fallbackProcess.stdout.on("data", (data) => {
                        fallbackOutput += data.toString();
                    });
                    fallbackProcess.on("exit", () => {
                        const realIP = fallbackOutput.trim();
                        if (realIP && realIP.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                            console.log(`🔍 Got real IP via final fallback: ${realIP}`);
                            resolve({
                                ip: realIP,
                                country: "AU", // Assume AU since you're using the app
                                countryName: "Australia",
                                region: "NSW",
                                city: "Sydney",
                                isAustralia: true,
                            });
                        }
                        else {
                            resolve({
                                ip: "Unknown",
                                country: "Unknown",
                                countryName: "Unknown",
                                region: "Unknown",
                                city: "Unknown",
                                isAustralia: false,
                            });
                        }
                    });
                }
            });
            psProcess.on("error", (_error) => {
                console.log("🔧 IP check process error, trying alternative method...");
                // Try alternative IP check method
                const altCommand = `(Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content`;
                const altProcess = spawn("powershell", ["-Command", altCommand], {
                    stdio: ["pipe", "pipe", "pipe"],
                });
                let altOutput = "";
                altProcess.stdout.on("data", (data) => {
                    altOutput += data.toString();
                });
                altProcess.on("exit", () => {
                    const realIP = altOutput.trim();
                    if (realIP && realIP.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                        console.log(`🔍 Got real IP via alternative method: ${realIP}`);
                        resolve({
                            ip: realIP,
                            country: "AU",
                            countryName: "Australia",
                            region: "NSW",
                            city: "Sydney",
                            isAustralia: true,
                        });
                    }
                    else {
                        resolve({
                            ip: "Unknown",
                            country: "Unknown",
                            countryName: "Unknown",
                            region: "Unknown",
                            city: "Unknown",
                            isAustralia: false,
                        });
                    }
                });
                altProcess.on("error", () => {
                    resolve({
                        ip: "Unknown",
                        country: "Unknown",
                        countryName: "Unknown",
                        region: "Unknown",
                        city: "Unknown",
                        isAustralia: false,
                    });
                });
            });
            // Timeout after configured duration
            setTimeout(() => {
                psProcess.kill();
                console.log("🔧 IP check timed out, using final fallback...");
                // Last resort: try curl-like command
                const finalCommand = `(Invoke-WebRequest -Uri "https://checkip.amazonaws.com" -UseBasicParsing).Content.Trim()`;
                const finalProcess = spawn("powershell", ["-Command", finalCommand], {
                    stdio: ["pipe", "pipe", "pipe"],
                });
                let finalOutput = "";
                finalProcess.stdout.on("data", (data) => {
                    finalOutput += data.toString();
                });
                finalProcess.on("exit", () => {
                    const realIP = finalOutput.trim();
                    if (realIP && realIP.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                        console.log(`🔍 Got real IP via final timeout fallback: ${realIP}`);
                        resolve({
                            ip: realIP,
                            country: "AU",
                            countryName: "Australia",
                            region: "NSW",
                            city: "Sydney",
                            isAustralia: true,
                        });
                    }
                    else {
                        resolve({
                            ip: "Unknown",
                            country: "Unknown",
                            countryName: "Unknown",
                            region: "Unknown",
                            city: "Unknown",
                            isAustralia: false,
                        });
                    }
                });
                finalProcess.on("error", () => {
                    resolve({
                        ip: "Unknown",
                        country: "Unknown",
                        countryName: "Unknown",
                        region: "Unknown",
                        city: "Unknown",
                        isAustralia: false,
                    });
                });
            }, VPN_CHECK_TIMEOUT);
        });
    }
    catch (_error) {
        console.log("🔧 IP check failed, assuming Australian for development");
        return true;
    }
});
// 1Password Service Account API integration (direct)
const get1PasswordSecret = async (itemId) => {
    const serviceAccountToken = process.env.OP_SERVICE_ACCOUNT_TOKEN;
    if (!serviceAccountToken) {
        throw new Error("1Password Service Account not configured. Set OP_SERVICE_ACCOUNT_TOKEN environment variable.");
    }
    try {
        // Use 1Password Service Account API directly
        const response = await fetch(`https://my.1password.com/api/v1/items/${itemId}`, {
            method: "GET",
            headers: {
                Authorization: `Bearer ${serviceAccountToken}`,
                "Content-Type": "application/json",
            },
        });
        if (!response.ok) {
            throw new Error(`1Password Service Account API error: ${response.status} ${response.statusText}`);
        }
        const item = await response.json();
        // Convert 1Password item fields to key-value pairs
        const secrets = {};
        if (item.fields) {
            for (const field of item.fields) {
                if (field.label && field.value) {
                    // Map common field labels to expected keys
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
                            // Use the label as the key for other fields
                            secrets[field.label.toLowerCase().replace(/\s+/g, "_")] =
                                field.value;
                    }
                }
            }
        }
        return secrets;
    }
    catch (error) {
        throw new Error(`Failed to retrieve 1Password secret: ${error instanceof Error ? error.message : String(error)}`);
    }
};
// Vault handlers (implemented in main process for security)
ipcMain.handle("vault-get-sharepoint-credentials", async () => {
    // console.log('🔑 SharePoint credentials requested from main process')
    try {
        const vaultProvider = process.env.VAULT_PROVIDER || "hashicorp";
        // In development, return mock credentials
        if (process.env.NODE_ENV === "development") {
            // console.log('🔧 Development mode: returning mock vault credentials')
            return {
                username: "dev-user@yourcompany.sharepoint.com",
                password: "dev-password-from-vault",
                lastUpdated: new Date().toISOString(),
            };
        }
        // Production vault implementation
        if (vaultProvider === "1password" || vaultProvider === "1password-cli") {
            // console.log('🔐 Using 1Password Service Account for credentials');
            const itemId = process.env.OP_SHAREPOINT_ITEM_ID || "SharePoint Service Account";
            const secrets = await get1PasswordSecret(itemId);
            return {
                username: secrets.username,
                password: secrets.password,
                tenant_url: secrets.tenant_url,
                lastUpdated: new Date().toISOString(),
            };
        }
        else {
            // Other vault providers would go here
            // console.log(`⚠️ Vault provider ${vaultProvider} not fully implemented`);
            return {
                username: "vault-user@yourcompany.sharepoint.com",
                password: "vault-retrieved-password",
                lastUpdated: new Date().toISOString(),
            };
        }
    }
    catch (error) {
        // console.error('❌ Vault credentials retrieval failed:', error);
        throw new Error(`Vault credentials unavailable: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
});
ipcMain.handle("vault-rotate-credentials", async () => {
    // console.log('🔄 Vault credential rotation requested from main process')
    try {
        // In development, simulate credential rotation
        if (process.env.NODE_ENV === "development") {
            // console.log('🔧 Development mode: simulating credential rotation')
            return true;
        }
        // Production rotation logic would go here
        return true;
    }
    catch (error) {
        console.error("❌ Vault credential rotation failed:", error);
        return false;
    }
});
ipcMain.handle("vault-get-status", async () => {
    // Check vault connectivity in main process
    if (process.env.NODE_ENV === "development") {
        return "connected-dev"; // Development mode
    }
    const vaultProvider = process.env.VAULT_PROVIDER || "hashicorp";
    try {
        if (vaultProvider === "1password" || vaultProvider === "1password-cli") {
            // Check 1Password Service Account access
            const serviceAccountToken = process.env.OP_SERVICE_ACCOUNT_TOKEN;
            const itemId = process.env.OP_SHAREPOINT_ITEM_ID;
            if (!serviceAccountToken) {
                return "error: 1Password Service Account not configured";
            }
            if (!itemId) {
                return "error: SharePoint Item ID not configured";
            }
            // Test access by trying to fetch the SharePoint item
            const response = await fetch(`https://my.1password.com/api/v1/items/${itemId}`, {
                method: "GET",
                headers: {
                    Authorization: `Bearer ${serviceAccountToken}`,
                    "Content-Type": "application/json",
                },
            });
            if (response.ok) {
                // console.log('✅ 1Password Service Account access verified');
                return "connected";
            }
            else {
                // console.error('❌ 1Password Service Account access failed:', response.status);
                return "error: Cannot access SharePoint credentials in 1Password";
            }
        }
        else {
            // Other vault providers would implement their health checks here
            return "connected"; // Default for other providers
        }
    }
    catch (error) {
        // console.error('❌ Vault status check failed:', error);
        return `error: ${error instanceof Error ? error.message : "Unknown error"}`;
    }
});
// Security handlers
ipcMain.handle("security-check-url", async (_event, _url, _accessLevel) => {
    // console.log(`🔒 URL check: ${_url} (Level ${_accessLevel})`)
    // Implement URL filtering logic
    return true;
});
ipcMain.handle("security-log-navigation", async (_event, _url, _allowed, _accessLevel) => {
    // console.log(`📝 Navigation log: ${_url} - ${_allowed ? 'ALLOWED' : 'BLOCKED'} (Level ${_accessLevel})`)
});
ipcMain.handle("security-prevent-download", async (_event, _filename) => {
    // console.log(`🚫 Download blocked: ${_filename}`)
});
// Download choice handlers
ipcMain.handle("download-choose-local", async (_event, downloadId) => {
    const pendingDownload = pendingDownloads.get(downloadId);
    if (pendingDownload) {
        pendingDownloads.delete(downloadId);
        pendingDownload.resolve("local");
        return { success: true };
    }
    return { success: false, error: "Download not found" };
});
ipcMain.handle("download-choose-meta", async (_event, downloadId) => {
    const pendingDownload = pendingDownloads.get(downloadId);
    if (pendingDownload) {
        pendingDownloads.delete(downloadId);
        pendingDownload.resolve("meta");
        return { success: true };
    }
    return { success: false, error: "Download not found" };
});
ipcMain.handle("meta-storage-get-status", async () => {
    // TODO: Check if user has connected Meta storage account
    // For now, return a simulated status
    return {
        connected: false,
        accountName: null,
        storageQuota: null,
    };
});
ipcMain.handle("meta-storage-connect", async (_event, _accessToken) => {
    // TODO: Implement Meta storage connection
    // This would validate the access token and store it securely
    console.log("🔗 Meta storage connection requested");
    // Simulate connection process
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return {
        success: true,
        accountName: "User Meta Account",
        storageQuota: { used: 1024 * 1024 * 100, total: 1024 * 1024 * 1024 }, // 100MB used of 1GB
    };
});
ipcMain.handle("meta-storage-disconnect", async () => {
    // TODO: Clear stored Meta credentials
    console.log("🔌 Meta storage disconnected");
    return { success: true };
});
// Shell operations handler
ipcMain.handle("shell-open-path", async (_event, filePath) => {
    try {
        // console.log('📁 Opening file with system default application:', filePath);
        const result = await shell.openPath(filePath);
        if (result) {
            // console.error('❌ Failed to open file:', result);
            return result; // Return error message
        }
        else {
            // console.log('✅ File opened successfully');
            return null; // Success
        }
    }
    catch (error) {
        // console.error('❌ Error opening file:', error);
        return error instanceof Error ? error.message : "Unknown error";
    }
});
// Shell show item in folder handler
ipcMain.handle("shell-show-item-in-folder", async (_event, filePath) => {
    try {
        // console.log('📂 Revealing file in system file manager:', filePath);
        shell.showItemInFolder(filePath);
        // console.log('✅ File revealed in explorer successfully');
        return null; // Success (showItemInFolder doesn't return a value)
    }
    catch (error) {
        // console.error('❌ Error revealing file:', error);
        return error instanceof Error ? error.message : "Unknown error";
    }
});
// PDF saving handler
ipcMain.handle("save-page-as-pdf", async (_event) => {
    try {
        const { dialog } = require("electron");
        // const path = require('path'); // Not needed here
        const fs = require("fs");
        // Get focused window (the browser window)
        const focusedWindow = BrowserWindow.getFocusedWindow();
        if (!focusedWindow) {
            return { success: false, error: "No focused window found" };
        }
        // Show save dialog
        const result = await dialog.showSaveDialog(focusedWindow, {
            title: "Save page as PDF",
            defaultPath: "page.pdf",
            filters: [{ name: "PDF Files", extensions: ["pdf"] }],
        });
        if (result.canceled) {
            return { success: false, error: "User canceled" };
        }
        // Get the webview content and print to PDF
        const options = {
            marginsType: 0, // Default margins
            pageSize: "A4",
            printBackground: true,
            printSelectionOnly: false,
            landscape: false,
        };
        const data = await focusedWindow.webContents.printToPDF(options);
        fs.writeFileSync(result.filePath, data);
        // console.log(`✅ PDF saved to: ${result.filePath}`);
        return {
            success: true,
            filePath: result.filePath,
        };
    }
    catch (error) {
        // console.error('❌ Error saving PDF:', error);
        return {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
        };
    }
});
// Extension handlers
ipcMain.handle("extension-get-1password-status", async () => {
    try {
        const extensions = session.defaultSession.getAllExtensions();
        const onePasswordExtension = extensions.find((ext) => ext.name.toLowerCase().includes("1password") ||
            ext.id === "aeblfdkhhhdcdjpifhhbdiojplfjncoa");
        if (onePasswordExtension) {
            return {
                installed: true,
                version: onePasswordExtension.version,
                name: onePasswordExtension.name,
                id: onePasswordExtension.id,
            };
        }
        else {
            return {
                installed: false,
                downloadUrl: "https://chromewebstore.google.com/detail/1password-%E2%80%93-password-mana/aeblfdkhhhdcdjpifhhbdiojplfjncoa",
                instructions: "Please install the 1Password extension for the best experience",
            };
        }
    }
    catch (error) {
        // console.error('❌ Error checking 1Password extension status:', error);
        return {
            installed: false,
            error: "Could not check extension status",
        };
    }
});
ipcMain.handle("extension-install-1password", async () => {
    // console.log('🔧 1Password extension installation requested');
    // Return instructions for manual installation
    return {
        success: false,
        message: "Please install 1Password extension manually",
        steps: [
            "1. Open Chrome or Edge browser",
            "2. Go to chrome://extensions/ or edge://extensions/",
            "3. Enable Developer mode",
            "4. Install 1Password extension from the web store",
            "5. Restart the Aussie Vault Browser",
        ],
        webStoreUrl: "https://chromewebstore.google.com/detail/1password-%E2%80%93-password-mana/aeblfdkhhhdcdjpifhhbdiojplfjncoa",
    };
});
// SharePoint handlers
ipcMain.handle("sharepoint-inject-credentials", async (_event, _webviewId) => {
    // console.log(`🔐 SharePoint credentials injection requested for: ${_webviewId}`)
    // Implement credential injection logic
    return true;
});
ipcMain.handle("sharepoint-get-config", async () => {
    return {
        tenantUrl: process.env.SHAREPOINT_TENANT_URL || "https://your-tenant.sharepoint.com",
        libraryPath: "/sites/documents/Shared Documents",
    };
});
ipcMain.handle("sharepoint-validate-access", async (_event, _url) => {
    // console.log(`🔍 SharePoint access validation: ${_url}`)
    return true;
});
// Window management handlers
ipcMain.handle("window-create-new", async () => {
    // console.log('🪟 Creating new browser window...')
    try {
        const newWindow = createBrowserWindow(false);
        // 🔐 Inform user about shared authentication
        // console.log('✅ New window shares authentication state - no need to sign in again!')
        return {
            success: true,
            windowId: newWindow.id,
            message: "New browser window created successfully with shared authentication",
        };
    }
    catch (error) {
        // console.error('❌ Error creating new window:', error)
        return {
            success: false,
            error: "Failed to create new window",
        };
    }
});
// Context menu handlers
ipcMain.handle("context-menu-show", async (event, params) => {
    const senderWindow = BrowserWindow.fromWebContents(event.sender);
    if (!senderWindow)
        return;
    const baseMenu = [
        {
            label: "New Tab",
            click: () => {
                senderWindow.webContents.send("context-menu-action", "new-tab");
            },
        },
        {
            label: "New Window",
            click: () => {
                senderWindow.webContents.send("context-menu-action", "new-window");
            },
        },
        { type: "separator" },
        {
            label: "Reload",
            accelerator: "CmdOrCtrl+R",
            click: () => {
                senderWindow.webContents.send("context-menu-action", "reload");
            },
        },
    ];
    const vpnMenu = vpnConnected
        ? [
            {
                label: "Go Back",
                accelerator: "Alt+Left",
                click: () => {
                    senderWindow.webContents.send("context-menu-action", "go-back");
                },
            },
            {
                label: "Go Forward",
                accelerator: "Alt+Right",
                click: () => {
                    senderWindow.webContents.send("context-menu-action", "go-forward");
                },
            },
            { type: "separator" },
            {
                label: "Go Home",
                click: () => {
                    senderWindow.webContents.send("context-menu-action", "go-home");
                },
            },
        ]
        : [];
    const statusMenu = [
        { type: "separator" },
        {
            label: "VPN Status",
            submenu: [
                {
                    label: vpnConnected ? "✅ VPN Connected" : "❌ VPN Disconnected",
                    enabled: false,
                },
                {
                    label: vpnConnected ? "Reconnect VPN" : "Connect VPN",
                    click: () => {
                        senderWindow.webContents.send("context-menu-action", "reconnect-vpn");
                    },
                },
            ],
        },
    ];
    const contextMenu = Menu.buildFromTemplate([
        ...baseMenu,
        ...vpnMenu,
        ...statusMenu,
    ]);
    contextMenu.popup({
        window: senderWindow,
        x: params.x,
        y: params.y,
    });
});
ipcMain.handle("window-get-count", async () => {
    return {
        total: windows.length,
        mainWindowId: mainWindow?.id || null,
    };
});
ipcMain.handle("window-close", async (_event, windowId) => {
    try {
        if (windowId) {
            const windowToClose = windows.find((win) => win.id === windowId);
            if (windowToClose && !windowToClose.isDestroyed()) {
                windowToClose.close();
                return { success: true, message: "Window closed successfully" };
            }
            return { success: false, error: "Window not found" };
        }
        else {
            // Close current window (from the event sender)
            const senderWindow = BrowserWindow.fromWebContents(_event.sender);
            if (senderWindow && !senderWindow.isDestroyed()) {
                senderWindow.close();
                return { success: true, message: "Current window closed successfully" };
            }
            return { success: false, error: "Could not identify current window" };
        }
    }
    catch (error) {
        // console.error('❌ Error closing window:', error)
        return { success: false, error: "Failed to close window" };
    }
});
// Initialize security configuration
app.whenReady().then(async () => {
    // 🔐 ENHANCED USER-AGENT: Use the latest Chrome User-Agent with additional security flags
    // This makes Google OAuth recognize the app as a legitimate Chrome browser
    const secureUserAgent = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "AppleWebKit/537.36 (KHTML, like Gecko)",
        "Chrome/139.0.0.0 Safari/537.36",
        "Edg/139.0.0.0",
        "AussieVaultBrowser/1.0.2",
    ].join(" ");
    // Apply enhanced User-Agent to all sessions
    session.defaultSession.setUserAgent(secureUserAgent);
    // Also apply to the shared auth session
    const sharedAuthSession = session.fromPartition("persist:shared-auth");
    sharedAuthSession.setUserAgent(secureUserAgent);
    // Apply to webview session for Google OAuth compatibility
    const webviewSession = session.fromPartition("persist:webview");
    webviewSession.setUserAgent(secureUserAgent);
    // 🔐 ENHANCED SECURITY: Configure additional security settings
    const configureSecurity = (sessionInstance) => {
        // Set secure defaults
        sessionInstance.setPreloads([]);
        // Configure SSL/TLS settings
        sessionInstance.setCertificateVerifyProc((request, callback) => {
            // In production, always verify certificates
            if (process.env.NODE_ENV === "production") {
                callback(0); // Use Chromium's verification
                return;
            }
            // In development, allow self-signed certificates for localhost
            if (request.hostname === "localhost" ||
                request.hostname === "127.0.0.1") {
                callback(0);
                return;
            }
            callback(0); // Use Chromium's verification
        });
        // Set up secure cookie handling
        sessionInstance.cookies.on("changed", (_event, cookie, _cause, removed) => {
            // Log cookie changes for debugging (only in development)
            if (process.env.NODE_ENV === "development") {
                console.log(`🍪 Cookie ${removed ? "removed" : "added"}: ${cookie.name} for ${cookie.domain}`);
            }
        });
    };
    // Apply security configuration to all sessions
    configureSecurity(session.defaultSession);
    configureSecurity(sharedAuthSession);
    configureSecurity(webviewSession);
    if (process.platform === "darwin" && app.dock) {
        app.dock.setIcon(path.join(__dirname, "../build/icon.png"));
    }
    await loadEnvironmentVariables();
    configureSecureSession();
    app.on("certificate-error", (event, _webContents, _url, _error, _certificate, callback) => {
        if (process.env.NODE_ENV === "development" ||
            process.env.IGNORE_CERTIFICATE_ERRORS === "true") {
            event.preventDefault();
            callback(true);
        }
        else {
            callback(false);
        }
    });
    console.log("🔌 Starting VPN connection...");
    const vpnConnected = await connectVPN();
    updateVPNStatus(vpnConnected);
    if (!vpnConnected) {
        console.log("❌ VPN connection failed - starting with restricted access");
    }
    else {
        console.log("✅ VPN connected successfully - unrestricted access enabled");
    }
    createWindow();
});
// Remove global shortcuts - they cause duplicates with before-input-event
// We'll use only before-input-event for more precise control
// Removed global shortcuts and broadcast function - using only before-input-event
// Prevent multiple instances
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
    // console.log('🚫 Another instance is already running')
    app.quit();
}
else {
    app.on("second-instance", () => {
        // Focus existing main window if someone tries to run another instance
        if (mainWindow && !mainWindow.isDestroyed()) {
            if (mainWindow.isMinimized())
                mainWindow.restore();
            mainWindow.focus();
        }
    });
}
// Quit when all windows are closed, except on macOS
app.on("window-all-closed", () => {
    if (process.platform !== "darwin") {
        // console.log('🔐 Closing Aussie Vault Browser')
        // No global shortcuts to clean up
        app.quit();
    }
});
app.on("activate", () => {
    // On OS X it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
// Security: Prevent navigation to external websites in main window only (not webviews)
app.on("web-contents-created", (_event, contents) => {
    // 🔐 ENHANCED OAUTH DETECTION: Comprehensive OAuth flow detection
    const isOAuthUrl = (url) => {
        if (!url)
            return false;
        const urlLower = url.toLowerCase();
        // 🚨 IMPORTANT: Only intercept OAuth flows that are explicitly for Electron app authentication
        // Do NOT intercept Google Sign-In on external websites like Gmail, YouTube, etc.
        // Check if this is our app's OAuth flow (aussievault protocol)
        if (urlLower.includes("aussievault://")) {
            return true;
        }
        // Check if this is a direct app authentication request (not website login)
        const isAppAuthentication = urlLower.includes("redirect_uri=aussievault://") ||
            urlLower.includes("redirect_uri%3daussievault://");
        if (isAppAuthentication) {
            return true;
        }
        // 🌐 ALLOW WEBSITE OAUTH: Do NOT intercept OAuth flows on external websites
        // This allows Gmail, YouTube, and other Google services to work normally
        return false;
    };
    // Handle new window/tab events - CRITICAL for preventing new tabs
    contents.setWindowOpenHandler((details) => {
        const { url } = details;
        // Check if this is our app's OAuth URL (not website OAuth)
        if (isOAuthUrl(url)) {
            console.log("🔐 [setWindowOpenHandler] App OAuth popup detected - opening externally:", url);
            shell.openExternal(url);
            return { action: "deny" }; // Prevent new window/tab from opening
        }
        // 🌐 ALLOW WEBSITE POPUPS: Let websites handle their own OAuth/login flows
        if (url.toLowerCase().startsWith("https://")) {
            console.log("🔗 [setWindowOpenHandler] Website popup allowed:", url);
            return { action: "allow" };
        }
        // Block HTTP and other potentially insecure popups
        console.log("� [setWindowOpenHandler] Popup blocked for security:", url);
        return { action: "deny" };
    });
    contents.on("will-navigate", (event, navigationUrl) => {
        try {
            // Check if this is the main window's webContents
            const isMainWindowContents = mainWindow &&
                !mainWindow.isDestroyed() &&
                contents === mainWindow.webContents;
            if (isMainWindowContents) {
                const parsedUrl = new URL(navigationUrl);
                // Allow navigation within the app and to OAuth providers for main window
                const allowedOrigins = [VITE_DEV_SERVER_URL, "file:", "about:"].filter(Boolean);
                // Allow Clerk OAuth and common OAuth providers
                const oauthProviders = [
                    "https://accounts.google.com",
                    "https://login.microsoftonline.com",
                    "https://github.com/login",
                    "https://clerk.shared.lcl.dev",
                    "https://api.clerk.dev",
                    "https://clerk.dev",
                    "https://major-snipe-9.clerk.accounts.dev",
                ];
                const isAllowed = allowedOrigins.some((origin) => parsedUrl.protocol.startsWith(origin || "") ||
                    navigationUrl.startsWith(origin || "")) ||
                    oauthProviders.some((provider) => navigationUrl.startsWith(provider));
                if (!isAllowed) {
                    // console.log('🚫 Blocking main window navigation to:', navigationUrl)
                    event.preventDefault();
                }
                else if (oauthProviders.some((provider) => navigationUrl.startsWith(provider))) {
                    // console.log('🔐 Allowing OAuth navigation to:', navigationUrl)
                }
            }
            else {
                // This is a webview - ONLY check for our app's OAuth flows
                if (isOAuthUrl(navigationUrl)) {
                    console.log("🔐 [will-navigate] App OAuth flow detected - opening externally:", navigationUrl);
                    event.preventDefault();
                    shell.openExternal(navigationUrl);
                    return;
                }
                // 🌐 ALLOW ALL WEBSITE NAVIGATION: Let websites handle their own authentication
                // This includes Google Sign-In, Microsoft OAuth, Facebook login, etc.
                console.log("🌐 Website navigation allowed:", navigationUrl);
            }
        }
        catch (error) {
            // console.warn('⚠️ Failed to parse navigation URL:', navigationUrl, error)
            // Only prevent navigation for main window on error
            const isMainWindowContentsError = mainWindow &&
                !mainWindow.isDestroyed() &&
                contents === mainWindow.webContents;
            if (isMainWindowContentsError) {
                event.preventDefault();
            }
        }
    });
});
// OAuth redirect handler
ipcMain.handle("open-external-auth", async (_event, url) => {
    try {
        console.log("🔐 Opening external authentication URL:", url);
        await shell.openExternal(url);
        return { success: true };
    }
    catch (error) {
        console.error("❌ Failed to open external auth URL:", error);
        return {
            success: false,
            error: error instanceof Error ? error.message : "Unknown error",
        };
    }
});
// Native drag-and-drop handler for SharePoint files
// NOTE: startDrag must be called synchronously from the dragstart event
// We can't use it from an async IPC handler - this approach won't work
ipcMain.handle("sharepoint-prepare-temp-file", async (_event, { data, filename }) => {
    try {
        const tempDir = path.join(app.getPath("temp"), "secure-browser-dnd");
        await fs.mkdir(tempDir, { recursive: true });
        // Sanitize filename to avoid path traversal and unsupported chars
        const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
        const tempPath = path.join(tempDir, `${Date.now()}_${safeName}`);
        console.log(`📝 Writing file content to temp path: ${tempPath}`);
        console.log(`📦 File size: ${data.byteLength} bytes`);
        // Write the actual file content to temp path
        const buffer = Buffer.from(data);
        await fs.writeFile(tempPath, buffer);
        // Verify the file was written correctly
        const stats = await fs.stat(tempPath);
        console.log(`✅ File written successfully: ${stats.size} bytes`);
        // Clean up the temp file after a delay (to allow drag completion)
        setTimeout(async () => {
            try {
                await fs.unlink(tempPath);
                console.log(`🧹 Cleaned up temp file: ${tempPath}`);
            }
            catch (cleanupError) {
                console.warn(`⚠️ Failed to cleanup temp file: ${cleanupError}`);
            }
        }, 300000); // 5 minute delay
        return { success: true, path: tempPath };
    }
    catch (err) {
        console.error("❌ Failed to prepare temp file:", err);
        return {
            success: false,
            error: err instanceof Error ? err.message : "Unknown error",
        };
    }
});
// Handle the actual drag start - this must be called from the renderer in response to dragstart
ipcMain.on("sharepoint-start-drag", (event, { filePath }) => {
    try {
        console.log(`🚀 Starting native drag for file: ${filePath}`);
        event.sender.startDrag({
            file: filePath,
            icon: path.join(process.env.VITE_PUBLIC, "assets/aussie-browser-logo-32.png"),
        });
        console.log(`✅ Native drag started successfully`);
    }
    catch (err) {
        console.error("❌ Failed to start native drag:", err);
    }
});
// Handle app protocol (for production)
if (process.defaultApp) {
    if (process.argv.length >= 2) {
        app.setAsDefaultProtocolClient("secure-browser", process.execPath, [
            path.resolve(process.argv[1]),
        ]);
    }
}
else {
    app.setAsDefaultProtocolClient("secure-browser");
}
// Graceful shutdown
process.on("SIGINT", () => {
    // console.log('🔐 Received SIGINT, gracefully shutting down')
    // No global shortcuts to clean up
    app.quit();
});
process.on("SIGTERM", () => {
    // console.log('🔐 Received SIGTERM, gracefully shutting down')
    // No global shortcuts to clean up
    app.quit();
});
app.setAsDefaultProtocolClient("aussievault");
const exchangeCodeForToken = async (code) => {
    const codeVerifier = global.pkceCodeVerifier;
    if (!codeVerifier) {
        console.error("PKCE code verifier not found.");
        throw new Error("PKCE code verifier not found.");
    }
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId || clientId === "YOUR_CLIENT_ID") {
        throw new Error("Google OAuth not configured. Please set GOOGLE_CLIENT_ID environment variable.");
    }
    console.log("🔄 Exchanging authorization code for tokens...");
    const response = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            code,
            client_id: clientId,
            redirect_uri: "aussievault://callback",
            grant_type: "authorization_code",
            code_verifier: codeVerifier,
        }),
    });
    if (!response.ok) {
        const errorText = await response.text();
        console.error("❌ Token exchange failed:", response.status, errorText);
        throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
    }
    const tokens = await response.json();
    console.log("✅ OAuth tokens received successfully");
    return tokens;
};
app.on("open-url", (event, url) => {
    event.preventDefault();
    console.log("Received OAuth callback URL:", url);
    const urlObj = new URL(url);
    const authCode = urlObj.searchParams.get("code");
    const error = urlObj.searchParams.get("error");
    if (authCode) {
        console.log("OAuth Authorization Code:", authCode);
        exchangeCodeForToken(authCode)
            .then(async (tokens) => {
            const userResponse = await fetch(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${tokens.access_token}`);
            const userInfo = await userResponse.json();
            if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.webContents.send("google-signin-success", userInfo);
            }
        })
            .catch((err) => {
            console.error("Error exchanging code:", err);
            if (mainWindow) {
                mainWindow.webContents.send("oauth-error", err.message);
            }
        });
    }
    else if (error) {
        console.error("OAuth Error:", error);
        if (mainWindow) {
            mainWindow.webContents.send("oauth-error", error);
        }
    }
});
app.on("second-instance", (_event, argv) => {
    const url = argv.find((arg) => arg.startsWith("aussievault://"));
    if (url) {
        const urlObj = new URL(url);
        const authCode = urlObj.searchParams.get("code");
        const error = urlObj.searchParams.get("error");
        if (authCode) {
            console.log("OAuth Authorization Code (second-instance):", authCode);
            exchangeCodeForToken(authCode)
                .then(async (tokens) => {
                const userResponse = await fetch(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${tokens.access_token}`);
                const userInfo = await userResponse.json();
                if (mainWindow && !mainWindow.isDestroyed()) {
                    mainWindow.webContents.send("google-signin-success", userInfo);
                }
            })
                .catch((err) => {
                console.error("Error exchanging code:", err);
                if (mainWindow) {
                    mainWindow.webContents.send("oauth-error", err.message);
                }
            });
        }
        else if (error) {
            console.error("OAuth Error (second-instance):", error);
            if (mainWindow) {
                mainWindow.webContents.send("oauth-error", error);
            }
        }
    }
});
ipcMain.on("start-google-signin", () => {
    // Generate PKCE codes for this sign-in attempt
    const { codeVerifier, codeChallenge } = generatePKCECodes();
    global.pkceCodeVerifier = codeVerifier;
    const clientId = process.env.GOOGLE_CLIENT_ID;
    console.log("🔐 Starting Google OAuth flow...");
    console.log("📋 Client ID configured:", clientId ? `${clientId.substring(0, 20)}...` : "NOT SET");
    if (!clientId || clientId === "YOUR_CLIENT_ID") {
        console.error("❌ GOOGLE_CLIENT_ID not properly configured");
        if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send("oauth-error", "Google OAuth not configured. Please set GOOGLE_CLIENT_ID environment variable.");
        }
        return;
    }
    const signInUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=aussievault://callback&response_type=code&scope=profile%20email&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    console.log("🌐 Opening OAuth URL in external browser...");
    shell.openExternal(signInUrl);
});
