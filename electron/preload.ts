import { contextBridge, ipcRenderer } from "electron";

// --------- Expose some API to the Renderer process ---------
contextBridge.exposeInMainWorld("ipcRenderer", {
  on(...args: Parameters<typeof ipcRenderer.on>) {
    const [channel, listener] = args;
    return ipcRenderer.on(channel, (event, ...args) =>
      listener(event, ...args)
    );
  },
  off(...args: Parameters<typeof ipcRenderer.off>) {
    const [channel, ...omit] = args;
    return ipcRenderer.off(channel, ...omit);
  },
  send(...args: Parameters<typeof ipcRenderer.send>) {
    const [channel, ...omit] = args;
    return ipcRenderer.send(channel, ...omit);
  },
  invoke(...args: Parameters<typeof ipcRenderer.invoke>) {
    const [channel, ...omit] = args;
    return ipcRenderer.invoke(channel, ...omit);
  },
});

// Modern electronAPI (for useVPN hook compatibility)
contextBridge.exposeInMainWorld("electronAPI", {
  vpn: {
    getStatus: () => ipcRenderer.invoke("vpn-get-status"),
    connect: (provider: string) => ipcRenderer.invoke("vpn-connect", provider),
    disconnect: () => ipcRenderer.invoke("vpn-disconnect"),
    checkIP: () => ipcRenderer.invoke("vpn-check-ip"),
    onStatusChange: (callback: (status: string) => void) => {
      ipcRenderer.on("vpn-status-changed", (_, status) => callback(status));
    },
    removeStatusListener: () => {
      ipcRenderer.removeAllListeners("vpn-status-changed");
    },
  },
  shell: {
    openPath: (path: string) => ipcRenderer.invoke("shell-open-path", path),
    showItemInFolder: (path: string) =>
      ipcRenderer.invoke("shell-show-item-in-folder", path),
  },

  // Download Management
  downloads: {
    chooseLocal: (downloadId: string) =>
      ipcRenderer.invoke("download-choose-local", downloadId),
    chooseMeta: (downloadId: string) =>
      ipcRenderer.invoke("download-choose-meta", downloadId),
  },

  // Event listeners for download events
  on: (channel: string, func: (...args: any[]) => void) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed",
    ];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, func);
    }
  },

  removeListener: (channel: string, func: (...args: any[]) => void) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed",
    ];
    if (validChannels.includes(channel)) {
      ipcRenderer.removeListener(channel, func);
    }
  },

  // External auth handling
  openExternalAuth: (url: string) =>
    ipcRenderer.invoke("open-external-auth", url),
});

// Secure API for VPN and Vault operations
contextBridge.exposeInMainWorld("secureBrowser", {
  // VPN Operations
  vpn: {
    getStatus: () => ipcRenderer.invoke("vpn-get-status"),
    connect: (provider: string) => ipcRenderer.invoke("vpn-connect", provider),
    disconnect: () => ipcRenderer.invoke("vpn-disconnect"),
    checkIP: () => ipcRenderer.invoke("vpn-check-ip"),
    onStatusChange: (callback: (status: string) => void) => {
      ipcRenderer.on("vpn-status-changed", (_, status) => callback(status));
    },
    removeStatusListener: () => {
      ipcRenderer.removeAllListeners("vpn-status-changed");
    },
  },

  // Vault Operations
  vault: {
    getSharePointCredentials: () =>
      ipcRenderer.invoke("vault-get-sharepoint-credentials"),
    rotateCredentials: () => ipcRenderer.invoke("vault-rotate-credentials"),
    getVaultStatus: () => ipcRenderer.invoke("vault-get-status"),
  },

  // Security Operations
  security: {
    checkUrlAllowed: (url: string, accessLevel: number) =>
      ipcRenderer.invoke("security-check-url", url, accessLevel),
    logNavigation: (url: string, allowed: boolean, accessLevel: number) =>
      ipcRenderer.invoke("security-log-navigation", url, allowed, accessLevel),
    preventDownload: (filename: string) =>
      ipcRenderer.invoke("security-prevent-download", filename),
  },

  // SharePoint Operations
  sharepoint: {
    injectCredentials: (webviewId: string) =>
      ipcRenderer.invoke("sharepoint-inject-credentials", webviewId),
    getLibraryConfig: () => ipcRenderer.invoke("sharepoint-get-config"),
    validateAccess: (url: string) =>
      ipcRenderer.invoke("sharepoint-validate-access", url),
    getOAuthToken: () => ipcRenderer.invoke("sharepoint-get-oauth-token"),
    graphRequest: (endpoint: string, accessToken: string) =>
      ipcRenderer.invoke("sharepoint-graph-request", { endpoint, accessToken }),
    // Prepare temporary file for native drag
    prepareTempFile: (options: { data: ArrayBuffer; filename: string }) =>
      ipcRenderer.invoke("sharepoint-prepare-temp-file", options),
    // Start native drag (must be called synchronously from dragstart)
    startDrag: (filePath: string) =>
      ipcRenderer.send("sharepoint-start-drag", { filePath }),
  },

  // System Information
  system: {
    getVersion: () => ipcRenderer.invoke("system-get-version"),
    getEnvironment: () => ipcRenderer.invoke("system-get-environment"),
    isProduction: () => false, // Will be determined by main process
  },

  // Extension Management
  extensions: {
    get1PasswordStatus: () =>
      ipcRenderer.invoke("extension-get-1password-status"),
    install1Password: () => ipcRenderer.invoke("extension-install-1password"),
  },

  // Browser Actions
  savePageAsPDF: () => ipcRenderer.invoke("save-page-as-pdf"),

  // File System Operations
  shell: {
    openPath: (path: string) => ipcRenderer.invoke("shell-open-path", path),
    showItemInFolder: (path: string) =>
      ipcRenderer.invoke("shell-show-item-in-folder", path),
  },

  // Download Management
  downloads: {
    chooseLocal: (downloadId: string) =>
      ipcRenderer.invoke("download-choose-local", downloadId),
    chooseMeta: (downloadId: string) =>
      ipcRenderer.invoke("download-choose-meta", downloadId),
  },

  // Meta Storage Integration
  metaStorage: {
    getStatus: () => ipcRenderer.invoke("meta-storage-get-status"),
    connect: (accessToken: string) =>
      ipcRenderer.invoke("meta-storage-connect", accessToken),
    disconnect: () => ipcRenderer.invoke("meta-storage-disconnect"),
  },

  // Event listeners for download events
  on: (channel: string, func: (...args: any[]) => void) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed",
    ];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, func);
    }
  },

  removeListener: (channel: string, func: (...args: any[]) => void) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed",
    ];
    if (validChannels.includes(channel)) {
      ipcRenderer.removeListener(channel, func);
    }
  },

  // Window Management
  window: {
    createNew: () => ipcRenderer.invoke("window-create-new"),
    getCount: () => ipcRenderer.invoke("window-get-count"),
    close: (windowId?: number) => ipcRenderer.invoke("window-close", windowId),
  },

  // Context Menu
  contextMenu: {
    show: (params: { x: number; y: number }) =>
      ipcRenderer.invoke("context-menu-show", params),
    onAction: (callback: (action: string) => void) => {
      ipcRenderer.on("context-menu-action", (_, action) => callback(action));
    },
    removeActionListener: () => {
      ipcRenderer.removeAllListeners("context-menu-action");
    },
  },

  // Auth Operations
  auth: {
    startGoogleSignIn: () => ipcRenderer.send("start-google-signin"),
    onGoogleSignInSuccess: (callback: (userInfo: any) => void) =>
      ipcRenderer.on("google-signin-success", (_, userInfo) =>
        callback(userInfo)
      ),
    onOAuthError: (callback: (error: string) => void) =>
      ipcRenderer.on("oauth-error", (_, error) => callback(error)),
    removeGoogleSignInListener: () =>
      ipcRenderer.removeAllListeners("google-signin-success"),
    removeOAuthErrorListener: () =>
      ipcRenderer.removeAllListeners("oauth-error"),
  },
});

// Debug: Log electronAPI creation
console.log("🔧 Preload: electronAPI exposed to window with methods:", {
  downloads: "object",
  metaStorage: "object",
  on: "function",
  removeListener: "function",
});

// Remove node integration from window object for security
delete (window as unknown as { module?: unknown }).module;
delete (window as unknown as { exports?: unknown }).exports;
delete (window as unknown as { require?: unknown }).require;

// Enhanced security - prevent access to node internals
try {
  // Note: process object is not available in renderer with context isolation
  Object.freeze(console);
} catch (error) {
  // Ignore freezing errors in some environments
}

// Log security initialization
// console.log('🔒 Secure Browser Preload: Context isolation enabled')
// console.log('🌐 VPN-routed traffic: Ready for Australian endpoint')
// console.log('🔑 Vault integration: SharePoint credentials secure')

// Type definitions for renderer process
// Type definitions for renderer process
export interface SecureBrowserAPI {
  vpn: {
    getStatus: () => Promise<string>;
    connect: (provider: string) => Promise<boolean>;
    disconnect: () => Promise<boolean>;
    onStatusChange: (callback: (status: string) => void) => void;
    removeStatusListener: () => void;
  };
  vault: {
    getSharePointCredentials: () => Promise<{
      username: string;
      password: string;
    }>;
    rotateCredentials: () => Promise<boolean>;
    getVaultStatus: () => Promise<string>;
  };
  security: {
    checkUrlAllowed: (url: string, accessLevel: number) => Promise<boolean>;
    logNavigation: (
      url: string,
      allowed: boolean,
      accessLevel: number
    ) => Promise<void>;
    preventDownload: (filename: string) => Promise<void>;
  };
  sharepoint: {
    injectCredentials: (webviewId: string) => Promise<boolean>;
    getLibraryConfig: () => Promise<{ tenantUrl: string; libraryPath: string }>;
    validateAccess: (url: string) => Promise<boolean>;
    getOAuthToken: () => Promise<{
      success: boolean;
      accessToken?: string;
      error?: string;
    }>;
    graphRequest: (
      endpoint: string,
      accessToken: string
    ) => Promise<{ success: boolean; data?: any; error?: string }>;
    prepareTempFile: (options: {
      data: ArrayBuffer;
      filename: string;
    }) => Promise<{ success: boolean; path?: string; error?: string }>;
    startDrag: (filePath: string) => void;
  };
  system: {
    getVersion: () => Promise<string>;
    getEnvironment: () => Promise<string>;
    isProduction: () => boolean;
  };
  extensions: {
    get1PasswordStatus: () => Promise<{
      installed: boolean;
      version?: string;
      name?: string;
      id?: string;
      downloadUrl?: string;
      instructions?: string;
      error?: string;
    }>;
    install1Password: () => Promise<{
      success: boolean;
      message: string;
      steps: string[];
      webStoreUrl: string;
    }>;
  };
  window: {
    createNew: () => Promise<{
      success: boolean;
      windowId?: number;
      message?: string;
      error?: string;
    }>;
    getCount: () => Promise<{
      total: number;
      mainWindowId: number | null;
    }>;
    close: (windowId?: number) => Promise<{
      success: boolean;
      message?: string;
      error?: string;
    }>;
  };
  contextMenu: {
    show: (params: { x: number; y: number }) => Promise<void>;
    onAction: (callback: (action: string) => void) => void;
    removeActionListener: () => void;
  };
  shell: {
    openPath: (path: string) => Promise<string | null>;
    showItemInFolder: (path: string) => Promise<string | null>;
  };
  on: (channel: string, func: (...args: any[]) => void) => void;
  removeListener: (channel: string, func: (...args: any[]) => void) => void;
  auth: {
    startGoogleSignIn: () => void;
    onGoogleSignInSuccess: (callback: (userInfo: any) => void) => void;
    onOAuthError: (callback: (error: string) => void) => void;
    removeGoogleSignInListener: () => void;
    removeOAuthErrorListener: () => void;
  };
}

declare global {
  interface Window {
    secureBrowser: SecureBrowserAPI;
  }
}
