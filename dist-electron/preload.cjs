"use strict";
const electron = require("electron");
electron.contextBridge.exposeInMainWorld("ipcRenderer", {
  on(...args) {
    const [channel, listener] = args;
    return electron.ipcRenderer.on(
      channel,
      (event, ...args2) => listener(event, ...args2)
    );
  },
  off(...args) {
    const [channel, ...omit] = args;
    return electron.ipcRenderer.off(channel, ...omit);
  },
  send(...args) {
    const [channel, ...omit] = args;
    return electron.ipcRenderer.send(channel, ...omit);
  },
  invoke(...args) {
    const [channel, ...omit] = args;
    return electron.ipcRenderer.invoke(channel, ...omit);
  }
});
electron.contextBridge.exposeInMainWorld("electronAPI", {
  vpn: {
    getStatus: () => electron.ipcRenderer.invoke("vpn-get-status"),
    connect: (provider) => electron.ipcRenderer.invoke("vpn-connect", provider),
    disconnect: () => electron.ipcRenderer.invoke("vpn-disconnect"),
    checkIP: () => electron.ipcRenderer.invoke("vpn-check-ip"),
    onStatusChange: (callback) => {
      electron.ipcRenderer.on("vpn-status-changed", (_, status) => callback(status));
    },
    removeStatusListener: () => {
      electron.ipcRenderer.removeAllListeners("vpn-status-changed");
    }
  },
  shell: {
    openPath: (path) => electron.ipcRenderer.invoke("shell-open-path", path),
    showItemInFolder: (path) => electron.ipcRenderer.invoke("shell-show-item-in-folder", path)
  },
  // Download Management
  downloads: {
    chooseLocal: (downloadId) => electron.ipcRenderer.invoke("download-choose-local", downloadId),
    chooseMeta: (downloadId) => electron.ipcRenderer.invoke("download-choose-meta", downloadId)
  },
  // Event listeners for download events
  on: (channel, func) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed"
    ];
    if (validChannels.includes(channel)) {
      electron.ipcRenderer.on(channel, func);
    }
  },
  removeListener: (channel, func) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed"
    ];
    if (validChannels.includes(channel)) {
      electron.ipcRenderer.removeListener(channel, func);
    }
  },
  // External auth handling
  openExternalAuth: (url) => electron.ipcRenderer.invoke("open-external-auth", url)
});
electron.contextBridge.exposeInMainWorld("secureBrowser", {
  // VPN Operations
  vpn: {
    getStatus: () => electron.ipcRenderer.invoke("vpn-get-status"),
    connect: (provider) => electron.ipcRenderer.invoke("vpn-connect", provider),
    disconnect: () => electron.ipcRenderer.invoke("vpn-disconnect"),
    checkIP: () => electron.ipcRenderer.invoke("vpn-check-ip"),
    onStatusChange: (callback) => {
      electron.ipcRenderer.on("vpn-status-changed", (_, status) => callback(status));
    },
    removeStatusListener: () => {
      electron.ipcRenderer.removeAllListeners("vpn-status-changed");
    }
  },
  // Vault Operations
  vault: {
    getSharePointCredentials: () => electron.ipcRenderer.invoke("vault-get-sharepoint-credentials"),
    rotateCredentials: () => electron.ipcRenderer.invoke("vault-rotate-credentials"),
    getVaultStatus: () => electron.ipcRenderer.invoke("vault-get-status")
  },
  // Security Operations
  security: {
    checkUrlAllowed: (url, accessLevel) => electron.ipcRenderer.invoke("security-check-url", url, accessLevel),
    logNavigation: (url, allowed, accessLevel) => electron.ipcRenderer.invoke("security-log-navigation", url, allowed, accessLevel),
    preventDownload: (filename) => electron.ipcRenderer.invoke("security-prevent-download", filename)
  },
  // SharePoint Operations
  sharepoint: {
    injectCredentials: (webviewId) => electron.ipcRenderer.invoke("sharepoint-inject-credentials", webviewId),
    getLibraryConfig: () => electron.ipcRenderer.invoke("sharepoint-get-config"),
    validateAccess: (url) => electron.ipcRenderer.invoke("sharepoint-validate-access", url),
    getOAuthToken: () => electron.ipcRenderer.invoke("sharepoint-get-oauth-token"),
    graphRequest: (endpoint, accessToken) => electron.ipcRenderer.invoke("sharepoint-graph-request", { endpoint, accessToken }),
    // Prepare temporary file for native drag
    prepareTempFile: (options) => electron.ipcRenderer.invoke("sharepoint-prepare-temp-file", options),
    // Start native drag (must be called synchronously from dragstart)
    startDrag: (filePath) => electron.ipcRenderer.send("sharepoint-start-drag", { filePath })
  },
  // System Information
  system: {
    getVersion: () => electron.ipcRenderer.invoke("system-get-version"),
    getEnvironment: () => electron.ipcRenderer.invoke("system-get-environment"),
    isProduction: () => false
    // Will be determined by main process
  },
  // Extension Management
  extensions: {
    get1PasswordStatus: () => electron.ipcRenderer.invoke("extension-get-1password-status"),
    install1Password: () => electron.ipcRenderer.invoke("extension-install-1password")
  },
  // Browser Actions
  savePageAsPDF: () => electron.ipcRenderer.invoke("save-page-as-pdf"),
  // File System Operations
  shell: {
    openPath: (path) => electron.ipcRenderer.invoke("shell-open-path", path),
    showItemInFolder: (path) => electron.ipcRenderer.invoke("shell-show-item-in-folder", path)
  },
  // Download Management
  downloads: {
    chooseLocal: (downloadId) => electron.ipcRenderer.invoke("download-choose-local", downloadId),
    chooseMeta: (downloadId) => electron.ipcRenderer.invoke("download-choose-meta", downloadId)
  },
  // Meta Storage Integration
  metaStorage: {
    getStatus: () => electron.ipcRenderer.invoke("meta-storage-get-status"),
    connect: (accessToken) => electron.ipcRenderer.invoke("meta-storage-connect", accessToken),
    disconnect: () => electron.ipcRenderer.invoke("meta-storage-disconnect")
  },
  // Event listeners for download events
  on: (channel, func) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed"
    ];
    if (validChannels.includes(channel)) {
      electron.ipcRenderer.on(channel, func);
    }
  },
  removeListener: (channel, func) => {
    const validChannels = [
      "download-started",
      "download-progress",
      "download-completed",
      "download-blocked",
      "download-choice-required",
      "download-choice-processed"
    ];
    if (validChannels.includes(channel)) {
      electron.ipcRenderer.removeListener(channel, func);
    }
  },
  // Window Management
  window: {
    createNew: () => electron.ipcRenderer.invoke("window-create-new"),
    getCount: () => electron.ipcRenderer.invoke("window-get-count"),
    close: (windowId) => electron.ipcRenderer.invoke("window-close", windowId)
  },
  // Context Menu
  contextMenu: {
    show: (params) => electron.ipcRenderer.invoke("context-menu-show", params),
    onAction: (callback) => {
      electron.ipcRenderer.on("context-menu-action", (_, action) => callback(action));
    },
    removeActionListener: () => {
      electron.ipcRenderer.removeAllListeners("context-menu-action");
    }
  },
  // Auth Operations
  auth: {
    startGoogleSignIn: () => electron.ipcRenderer.send("start-google-signin"),
    onGoogleSignInSuccess: (callback) => electron.ipcRenderer.on(
      "google-signin-success",
      (_, userInfo) => callback(userInfo)
    ),
    onOAuthError: (callback) => electron.ipcRenderer.on("oauth-error", (_, error) => callback(error)),
    removeGoogleSignInListener: () => electron.ipcRenderer.removeAllListeners("google-signin-success"),
    removeOAuthErrorListener: () => electron.ipcRenderer.removeAllListeners("oauth-error")
  }
});
console.log("🔧 Preload: electronAPI exposed to window with methods:", {
  downloads: "object",
  metaStorage: "object",
  on: "function",
  removeListener: "function"
});
delete window.module;
delete window.exports;
delete window.require;
try {
  Object.freeze(console);
} catch (error) {
}
