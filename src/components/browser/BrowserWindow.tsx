import React, {
  useState,
  useRef,
  useEffect,
  useCallback,
  useMemo,
} from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  ArrowLeft,
  ArrowRight,
  RotateCcw,
  Home,
  Plus,
  X,
  Shield,
  AlertTriangle,
  Lock,
  FileDown,
  Printer,
  Copy,
  ExternalLink,
  Globe,
} from "lucide-react";

import { useVPN } from "@/hooks/useVPN";
import { injectSharePointCredentials } from "@/services/vaultService";
import { SecureBrowserDatabaseService } from "@/services/databaseService";
import { HistoryService } from "@/services/historyService";
import SearchBar from "./SearchBar";
import BrowserMenu from "./BrowserMenu";
import HistoryModal from "./HistoryModal";
import DownloadsModal from "./DownloadsModal";
import BookmarksModal from "./BookmarksModal";
import TaskManagerModal from "./TaskManagerModal";
import DebugAuthModal from "./DebugAuthModal";
import SettingsModal from "./SettingsModal";
import BookmarkButton from "./BookmarkButton";
import VPNConnectionError from "@/components/ui/vpn-connection-error";
import { SharePointSidebar } from "./SharePointSidebar";

interface Tab {
  id: string;
  title: string;
  url: string;
  isLoading: boolean;
}

interface BrowserWindowProps {
  user?: any;
  onLogout?: () => void;
}

const BrowserWindow: React.FC<BrowserWindowProps> = ({ user, onLogout }) => {

  const {
    vpnStatus,
    allowBrowsing,
    connection,
    connectVPN,
    checkVPNStatus,
    isConnecting,
    isCheckingStatus,
    lastError,
    actualIP,
    actualCountry,
  } = useVPN(user?.accessLevel);
  
  // Wait for user to be loaded before setting default URL
  const defaultUrl = user?.accessLevel ? getDefaultUrl(user.accessLevel) : "https://www.google.com";
  
  const [tabs, setTabs] = useState<Tab[]>([
    {
      id: "1",
      title: "New Tab",
      url: defaultUrl,
      isLoading: false,
    },
  ]);
  const [activeTab, setActiveTab] = useState("1");
  
  // Enhanced setActiveTab that also syncs URL bar
  const setActiveTabWithSync = useCallback((tabId: string) => {
    setActiveTab(tabId);
    // Immediately sync URL bar with the new active tab
    const tab = tabs.find(t => t.id === tabId);
    if (tab && tab.url) {
      setUrlInput(tab.url);
    }
  }, [tabs]);
  const [urlInput, setUrlInput] = useState(defaultUrl);
  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState(false);
  const [isDownloadsModalOpen, setIsDownloadsModalOpen] = useState(false);
  const [isBookmarksModalOpen, setIsBookmarksModalOpen] = useState(false);
  const [isTaskManagerModalOpen, setIsTaskManagerModalOpen] = useState(false);
  const [isDebugAuthModalOpen, setIsDebugAuthModalOpen] = useState(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState(false);
  const [isSharePointSidebarOpen, setIsSharePointSidebarOpen] = useState(false);
  const [zoomLevel, setZoomLevel] = useState(100);
  const [contextMenu, setContextMenu] = useState<{
    visible: boolean;
    x: number;
    y: number;
  }>({ visible: false, x: 0, y: 0 });
  // Download interface to match DownloadsModal
  interface DownloadItem {
    id: string;
    filename: string;
    url: string;
    size: number;
    totalBytes: number;
    downloadedBytes: number;
    status: "downloading" | "completed" | "cancelled" | "blocked";
    startTime: Date;
    endTime?: Date;
    speed?: number;
    progress: number;
    filePath?: string;
  }

  // Downloads state with localStorage persistence
  const [downloads, setDownloads] = useState<DownloadItem[]>(() => {
    try {
      const savedDownloads = localStorage.getItem("app-downloads");
      if (savedDownloads) {
        const parsed = JSON.parse(savedDownloads);
        // Convert date strings back to Date objects and handle interrupted downloads
        const restoredDownloads = parsed.map((download: any) => {
          const restored = {
            ...download,
            startTime: new Date(download.startTime),
            endTime: download.endTime ? new Date(download.endTime) : undefined,
          };

          // Mark any downloads that were in progress as cancelled since they can't continue
          if (restored.status === "downloading") {
            restored.status = "cancelled";
            restored.endTime = new Date();
            // console.log(
            //   "📋 Restored interrupted download as cancelled:",
            //   restored.filename
            // );
          }

          return restored;
        });

        // console.log(
        //   "📥 Restored",
        //   restoredDownloads.length,
        //   "downloads from localStorage"
        // );
        return restoredDownloads;
      }
    } catch (error) {
      // Error loading downloads from localStorage
    }
    return [];
  });
  const webviewRefs = useRef<{ [key: string]: HTMLElement | null }>({});
  const webviewInitialized = useRef<{ [key: string]: boolean }>({});

  // Debug downloads state changes
  useEffect(() => {
    // console.log("📊 Downloads state changed:", {
    //   total: downloads.length,
    //   downloading: downloads.filter((d) => d.status === "downloading").length,
    //   completed: downloads.filter((d) => d.status === "completed").length,
    //   cancelled: downloads.filter((d) => d.status === "cancelled").length,
    //   blocked: downloads.filter((d) => d.status === "blocked").length,
    //   downloads: downloads.map((d) => ({
    //     id: d.id,
    //     filename: d.filename,
    //     status: d.status,
    //   })),
    // });
  }, [downloads]);

  // Debug zoom level changes
  useEffect(() => {
    // console.log("🔍 [ZOOM STATE] Zoom level state changed:", zoomLevel + "%");
    // console.log("🔍 [ZOOM STATE] This should trigger UI updates in BrowserMenu");

    // Force a re-render of the menu to ensure it shows the updated zoom level
    const menuContainer = document.querySelector(
      "[data-radix-dropdown-menu-content]"
    );
    if (menuContainer) {
      // console.log("🔄 [ZOOM] Menu is open, should update zoom display automatically");
    }
  }, [zoomLevel]);

  // Save downloads to localStorage whenever downloads change
  useEffect(() => {
    try {
      localStorage.setItem("app-downloads", JSON.stringify(downloads));
      // console.log(
      //   "💾 Downloads saved to localStorage:",
      //   downloads.length,
      //   "items"
      // );
    } catch (error) {
      // Failed to save downloads to localStorage

      // Handle quota exceeded error by clearing old downloads
      if (error instanceof Error && error.name === "QuotaExceededError") {
        try {
          // Keep only the last 50 downloads
          const recentDownloads = downloads.slice(-50);
          localStorage.setItem(
            "app-downloads",
            JSON.stringify(recentDownloads)
          );
          setDownloads(recentDownloads);
          // console.log(
          //   "✅ Cleared old downloads, keeping",
          //   recentDownloads.length,
          //   "recent ones"
          // );
        } catch (retryError) {
          // console.error("❌ Failed to save even after cleanup:", retryError);
          localStorage.removeItem("app-downloads");
        }
      }
    }
  }, [downloads]);

  // Initialize HistoryService with current user
  useEffect(() => {
    if (user) {
      HistoryService.setCurrentUser(user);
      // console.log("✅ HistoryService initialized with user:", user.email);
    }
  }, [user]);

  // Update default URL when user access level changes
  useEffect(() => {
    if (user?.accessLevel) {
      const newDefaultUrl = getDefaultUrl(user.accessLevel);
      
      // Update the first tab if it's still on the old default URL
      setTabs(prevTabs => 
        prevTabs.map((tab, index) => 
          index === 0 && (tab.url === "https://www.google.com" || tab.url.includes("office.com"))
            ? { ...tab, url: newDefaultUrl }
            : tab
        )
      );
      
      // Update URL input if it matches the old default (using functional update)
      setUrlInput(prevUrlInput => {
        if (prevUrlInput === "https://www.google.com" || prevUrlInput.includes("office.com")) {
          return newDefaultUrl;
        }
        return prevUrlInput;
      });
    }
  }, [user?.accessLevel]);

  // Sync URL bar with active tab's current URL
  useEffect(() => {
    const activeTabData = tabs.find(tab => tab.id === activeTab);
    if (activeTabData && activeTabData.url && activeTabData.url !== urlInput) {
      setUrlInput(activeTabData.url);
    }
  }, [activeTab, tabs]);

  // Get default URL based on access level
  function getDefaultUrl(accessLevel: number): string {
    switch (accessLevel) {
      case 3:
        return "https://www.google.com"; // Full access starts at Google for unrestricted browsing
      case 2:
        return "https://www.office.com"; // Manager level starts with Office
      default:
        return "https://www.office.com"; // Restricted level starts with SharePoint/Office
    }
  }

  // Access level configurations
  const getAccessLevelConfig = useCallback(() => {
    const level = user?.accessLevel || 1;
    switch (level) {
      case 3:
        return {
          name: "Full Access",
          allowedDomains: ["*"], // All domains
          variant: "default" as const,
        };
      case 2:
        return {
          name: "Manager",
          allowedDomains: [
            "sharepoint.com",
            "office.com",
            "microsoft.com",
            "wikipedia.org",
            "github.com",
            "stackoverflow.com",
          ],
          variant: "secondary" as const,
        };
      default:
        return {
          name: "Restricted",
          allowedDomains: ["sharepoint.com", "office.com"],
          variant: "outline" as const,
        };
    }
  }, [user?.accessLevel]);

  // Add history tracking function
  const addToHistory = useCallback(async (url: string, title?: string) => {
    try {
      if (url && url.startsWith("http")) {
        await HistoryService.addHistoryEntry(url, title || "Untitled");
        // console.log("✅ Added to history:", { url, title });
      }
    } catch (error) {
      // console.error("❌ Failed to add to history:", error);
    }
  }, []);

  // Navigate to URL from history
  const navigateToUrl = useCallback(
    (url: string) => {
      setUrlInput(url);
      const webview = webviewRefs.current[activeTab] as HTMLElement & {
        src: string;
      };

      if (webview) {
        // Update tab state
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === activeTab
              ? { ...tab, url, isLoading: true, title: "Loading..." }
              : tab
          )
        );

        // Navigate webview
        webview.src = url;
      }
    },
    [activeTab]
  );

  // Menu handlers
  const handleHistoryClick = useCallback(() => {
    setIsHistoryModalOpen(true);
  }, []);

  const handleDownloadsClick = useCallback(() => {
    setIsDownloadsModalOpen(true);
  }, []);

  const handleBookmarksClick = useCallback(() => {
    setIsBookmarksModalOpen(true);
  }, []);

  const handleTaskManagerClick = useCallback(() => {
    setIsTaskManagerModalOpen(true);
  }, []);

  const handleDebugAuthClick = useCallback(() => {
    setIsDebugAuthModalOpen(true);
  }, []);

  const handleSettingsClick = useCallback(() => {
    // console.log("Settings clicked");
    setIsSettingsModalOpen(true);
  }, []);

  const handleSharePointClick = useCallback(() => {
    setIsSharePointSidebarOpen(true);
  }, []);

  const applyZoomToActiveWebview = useCallback(
    (zoomPercent: number) => {
      const webview = webviewRefs.current[activeTab] as any;
      if (webview) {
        const zoomFactor = zoomPercent / 100;
        // console.log(
        //   `🔍 [ZOOM] Applying zoom: ${zoomPercent}% (factor: ${zoomFactor}) to tab ${activeTab}`
        // );

        try {
          let applied = false;

          // Method 1: Standard Electron webview setZoomFactor
          if (
            webview.setZoomFactor &&
            typeof webview.setZoomFactor === "function"
          ) {
            webview.setZoomFactor(zoomFactor);
            // console.log(`✅ [ZOOM] Applied via setZoomFactor: ${zoomPercent}%`);
            applied = true;
          }

          // Method 2: Execute JavaScript to set CSS zoom
          if (
            webview.executeJavaScript &&
            typeof webview.executeJavaScript === "function"
          ) {
            const jsCode = `
             (function() {
               try {
                 // Remove any existing zoom CSS
                 var existingZoom = document.getElementById('aussie-browser-zoom');
                 if (existingZoom) existingZoom.remove();
                 
                 // Create zoom CSS
                 var zoomCSS = document.createElement('style');
                 zoomCSS.id = 'aussie-browser-zoom';
                 zoomCSS.innerHTML = 
                   'html { zoom: ${zoomPercent}% !important; transform-origin: top left !important; }' +
                   'body { zoom: ${zoomPercent}% !important; transform-origin: top left !important; }';
                 document.head.appendChild(zoomCSS);
                 
                 // Also try setting style directly
                 document.documentElement.style.zoom = '${zoomPercent}%';
                 document.body.style.zoom = '${zoomPercent}%';
                 
                 // console.log('Zoom applied via JavaScript: ${zoomPercent}%');
                 return true;
               } catch (e) {
                 // console.error('Error applying zoom via JS:', e);
                 return false;
               }
             })();
           `;

            webview
              .executeJavaScript(jsCode)
              .then((result: any) => {
                // console.log(`✅ [ZOOM] executeJavaScript result:`, result);
              })
              .catch((error: any) => {
                // console.error(`❌ [ZOOM] executeJavaScript failed:`, error);
              });
            applied = true;
          }

          // Method 3: Insert CSS directly
          if (webview.insertCSS && typeof webview.insertCSS === "function") {
            const zoomCSS = `
             html, body { 
               zoom: ${zoomPercent}% !important; 
               transform-origin: top left !important;
             }
             * {
               zoom: inherit !important;
             }
           `;
            webview.insertCSS(zoomCSS);
            // console.log(`✅ [ZOOM] Applied via insertCSS: ${zoomPercent}%`);
            applied = true;
          }

          if (!applied) {
            // No zoom method available for webview
          }
        } catch (error) {
          // Failed to apply zoom
        }
      } else {
        // No webview found for active tab
        // console.log(
        //   "⚠️ [ZOOM] Available webviews:",
        //   Object.keys(webviewRefs.current)
        // );
      }
    },
    [activeTab]
  );

  const handleZoomIn = useCallback(() => {
    // console.log(`🔍 [ZOOM] === ZOOM IN FUNCTION CALLED ===`);
    // console.log(`🔍 [ZOOM] Current zoom level before change: ${zoomLevel}%`);

    setZoomLevel((prev) => {
      const newLevel = Math.min(prev + 5, 300);
      // console.log(`📈 [ZOOM] State update: ${prev}% -> ${newLevel}%`);

      // Apply zoom immediately, not with setTimeout
      // console.log(`⏰ [ZOOM] Applying zoom level ${newLevel}% to active webview immediately`);
      setTimeout(() => applyZoomToActiveWebview(newLevel), 10);

      return newLevel;
    });

    // console.log(`🔍 [ZOOM] === ZOOM IN FUNCTION COMPLETED ===`);
  }, [applyZoomToActiveWebview]); // Remove zoomLevel from dependencies to avoid stale closures

  const handleZoomOut = useCallback(() => {
    // console.log(`🔍 [ZOOM] === ZOOM OUT FUNCTION CALLED ===`);
    // console.log(`🔍 [ZOOM] Current zoom level before change: ${zoomLevel}%`);

    setZoomLevel((prev) => {
      const newLevel = Math.max(prev - 5, 25);
      // console.log(`📉 [ZOOM] State update: ${prev}% -> ${newLevel}%`);

      // Apply zoom immediately, not with setTimeout
      // console.log(`⏰ [ZOOM] Applying zoom level ${newLevel}% to active webview immediately`);
      setTimeout(() => applyZoomToActiveWebview(newLevel), 10);

      return newLevel;
    });

    // console.log(`🔍 [ZOOM] === ZOOM OUT FUNCTION COMPLETED ===`);
  }, [applyZoomToActiveWebview]); // Remove zoomLevel from dependencies to avoid stale closures

  const handleZoomReset = useCallback(() => {
    // console.log(`🔄 [ZOOM] Reset triggered - forcing 100% zoom (current: ${zoomLevel}%)`);

    // Set zoom level to 100% first
    setZoomLevel(100);

    // Force reset with multiple attempts for reliability
    const forceReset = () => {
      const webview = webviewRefs.current[activeTab] as any;
      if (webview) {
        // console.log(`🔧 [ZOOM] Force resetting webview zoom to 100%`);

        // Method 1: Electron setZoomFactor (most reliable)
        if (webview.setZoomFactor) {
          webview.setZoomFactor(1.0);
          // console.log('✅ [ZOOM] setZoomFactor(1.0) applied');
        }

        // Method 2: Remove all zoom CSS and reset via JavaScript
        if (webview.executeJavaScript) {
          webview
            .executeJavaScript(
              `
            (function() {
              try {
                // console.log('🔧 [ZOOM] JavaScript zoom reset starting...');
                
                // Remove any existing zoom CSS
                var existingZoom = document.getElementById('aussie-browser-zoom');
                if (existingZoom) {
                  existingZoom.remove();
                  // console.log('🗑️ Removed existing zoom CSS');
                }
                
                // Remove all zoom styles from all elements
                const allElements = document.querySelectorAll('*');
                allElements.forEach(el => {
                  if (el.style) {
                    el.style.zoom = '';
                    el.style.transform = '';
                  }
                });
                
                // Reset root elements specifically
                document.documentElement.style.zoom = '100%';
                document.body.style.zoom = '100%';
                document.documentElement.style.transform = 'none';
                document.body.style.transform = 'none';
                
                // console.log('✅ [ZOOM] JavaScript zoom reset completed - 100%');
                return true;
              } catch (e) {
                return false;
              }
            })();
          `
            )
            .then((result: any) => {
              // console.log('✅ [ZOOM] JavaScript execution result:', result);
            })
            .catch((error: any) => {
              // console.error('❌ [ZOOM] JavaScript execution failed:', error);
            });
        }

        // Method 3: Insert CSS to force 100%
        if (webview.insertCSS) {
          webview.insertCSS(`
            html, body { 
              zoom: 100% !important; 
              transform: none !important;
              transform-origin: top left !important;
            }
            * {
              zoom: inherit !important;
            }
          `);
          // console.log('✅ [ZOOM] CSS reset applied');
        }
      } else {
        // console.warn('⚠️ [ZOOM] No webview found for zoom reset');
      }
    };

    // Apply reset immediately and with multiple attempts
    // console.log('🔄 [ZOOM] Starting zoom reset sequence...');
    forceReset();
    setTimeout(() => {
      // console.log('🔄 [ZOOM] Retry zoom reset (50ms)');
      forceReset();
    }, 50);
    setTimeout(() => {
      // console.log('🔄 [ZOOM] Final zoom reset (200ms)');
      forceReset();
    }, 200);

    // console.log('✅ [ZOOM] Zoom reset sequence initiated');
  }, [activeTab]);

  // Reapply zoom when pages finish loading (stable version - no auto-refresh triggers)
  useEffect(() => {
    const currentTab = tabs.find((tab) => tab.id === activeTab);
    if (currentTab && !currentTab.isLoading && zoomLevel !== 100) {
      // Use longer delay to prevent interference with navigation
      const timeoutId = setTimeout(() => {
        applyZoomToActiveWebview(zoomLevel);
      }, 1000);
      
      return () => clearTimeout(timeoutId);
    }
  }, [
    // Only watch loading state changes to prevent excessive triggering
    tabs.find((tab) => tab.id === activeTab)?.isLoading,
    activeTab,
    zoomLevel,
    applyZoomToActiveWebview,
  ]);

  const handleLogout = useCallback(() => {
    if (onLogout) {
      onLogout();
    }
  }, [onLogout]);

  const getHomeUrl = useCallback((): string => {
    const level = user?.accessLevel || 1;
    switch (level) {
      case 3:
        return "https://www.google.com"; // Consistent with getDefaultUrl - full access starts at Google
      case 2:
        return "https://www.office.com"; // Consistent with getDefaultUrl - manager starts at Office
      default:
        return "https://www.office.com"; // Consistent with getDefaultUrl - restricted starts at Office
    }
  }, [user?.accessLevel]);

  // Smart URL/Search detection helper function
  const isValidUrl = useCallback((input: string): boolean => {
    // Check if it looks like a URL
    if (input.startsWith("http://") || input.startsWith("https://")) {
      return true;
    }

    // Check if it has a domain-like structure (contains a dot and no spaces)
    if (input.includes(".") && !input.includes(" ")) {
      // Simple domain pattern check
      const domainPattern =
        /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      const parts = input.split("/");
      const domain = parts[0];

      // Check if the domain part looks valid
      if (domainPattern.test(domain)) {
        return true;
      }
    }

    // Check for localhost or IP addresses
    if (
      input.startsWith("localhost") ||
      input.match(/^\d+\.\d+\.\d+\.\d+(:\d+)?/)
    ) {
      return true;
    }

    return false;
  }, []);

  // Construct search URL for Google search
  const constructSearchUrl = useCallback((query: string): string => {
    const encodedQuery = encodeURIComponent(query);
    return `https://www.google.com/search?q=${encodedQuery}`;
  }, []);

  // Process input to determine if it's a URL or search query
  const processInput = useCallback(
    (input: string): string => {
      const trimmedInput = input.trim();

      if (!trimmedInput) {
        return getHomeUrl();
      }

      // If it looks like a URL, treat it as one
      if (isValidUrl(trimmedInput)) {
        // Add https:// if no protocol is specified
        if (
          !trimmedInput.startsWith("http://") &&
          !trimmedInput.startsWith("https://")
        ) {
          return `https://${trimmedInput}`;
        }
        return trimmedInput;
      }

      // For levels 2 and 3, treat non-URLs as search queries
      const userLevel = user?.accessLevel || 1;
      if (userLevel >= 2) {
        // console.log(
        //   `🔍 Treating "${trimmedInput}" as search query for access level ${userLevel}`
        // );
        return constructSearchUrl(trimmedInput);
      }

      // For level 1 (restricted), only allow URLs, no search
      // console.log(
      //   `⚠️ Search not allowed for access level ${userLevel}, treating as URL attempt`
      // );
      // Try to make it a URL anyway (will likely be blocked)
      if (
        !trimmedInput.startsWith("http://") &&
        !trimmedInput.startsWith("https://")
      ) {
        return `https://${trimmedInput}`;
      }
      return trimmedInput;
    },
    [isValidUrl, constructSearchUrl, getHomeUrl, user?.accessLevel]
  );

  const isUrlAllowed = useCallback(
    (url: string): boolean => {
      // ALWAYS ALLOW ALL URLs for Level 3 users - NO RESTRICTIONS
      if (user?.accessLevel === 3) {
        return true;
      }

      const config = getAccessLevelConfig();

      // For Level 3, always allow all URLs
      if (config.allowedDomains.includes("*")) {
        return true;
      }

      try {
        // Ensure URL has protocol
        let fullUrl = url;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
          fullUrl = "https://" + url;
        }

        const urlObj = new URL(fullUrl);
        const domain = urlObj.hostname.replace("www.", "");

        const isAllowed = config.allowedDomains.some((allowed) => {
          const match = domain === allowed || domain.endsWith("." + allowed);
          return match;
        });
        return isAllowed;
      } catch (error) {
        return false;
      }
    },
    [getAccessLevelConfig, user?.accessLevel]
  );

  const handleUrlSubmit = useCallback(() => {
    // Process the input to determine final URL
    const finalUrl = processInput(urlInput);
    const isSearchQuery =
      !isValidUrl(urlInput.trim()) && (user?.accessLevel || 1) >= 2;

    // LEVEL 3 USERS: SKIP ALL VALIDATION INCLUDING VPN - Navigate immediately like Chrome
    if (user?.accessLevel === 3) {
      
      // Update tab state immediately
      setTabs((tabs) =>
        tabs.map((tab) =>
          tab.id === activeTab
            ? {
                ...tab,
                url: finalUrl,
                isLoading: true,
                title: isSearchQuery ? `Search: ${urlInput}` : "Loading...",
              }
            : tab
        )
      );

      // Update URL input immediately  
      setUrlInput(finalUrl);

      // Let React handle the webview src update automatically via the src={tab.url} prop
      return; // Exit early for Level 3 users
    }

    // For Level 1 and 2 users, do the normal validation including VPN check
    
    // Block navigation if VPN is not connected (fail-closed behavior for Level 1 & 2)
    if (!allowBrowsing) {
      // Log blocked navigation due to VPN
      SecureBrowserDatabaseService.logNavigation(
        urlInput,
        false,
        "VPN connection required"
      );

      SecureBrowserDatabaseService.logSecurityEvent(
        "domain_blocked",
        `Navigation blocked due to VPN disconnection: ${urlInput}`,
        "high",
        urlInput
      );

      alert(
        `VPN connection required. Browser access is blocked until Australian VPN connection is established. Status: ${vpnStatus}`
      );
      return;
    }

    // Log the type of navigation
    if (isSearchQuery) {
      SecureBrowserDatabaseService.logSecurityEvent(
        "unauthorized_access",
        `User performed search query: "${urlInput}" (Level ${user?.accessLevel})`,
        "low",
        finalUrl
      );
    }

    // Check if the final URL is allowed
    const urlAllowed = isUrlAllowed(finalUrl);

    // Log navigation attempt
    SecureBrowserDatabaseService.logNavigation(
      finalUrl,
      urlAllowed,
      urlAllowed
        ? undefined
        : `Access level ${
            getAccessLevelConfig().name
          } does not permit this domain`
    );

    if (!urlAllowed) {
      // This should NEVER happen for Level 3 users
      // console.error(
      //   `❌ CRITICAL: Level ${user?.accessLevel} user blocked from accessing: ${finalUrl}`
      // );

      // Log security event for blocked domain
      SecureBrowserDatabaseService.logSecurityEvent(
        "domain_blocked",
        `Domain access blocked for user with ${
          getAccessLevelConfig().name
        } access level: ${finalUrl}${
          isSearchQuery ? ` (search: "${urlInput}")` : ""
        }`,
        "medium",
        finalUrl
      );

      if (isSearchQuery) {
        alert(
          `Search blocked. Your access level (${
            getAccessLevelConfig().name
          }) does not permit Google searches. Original query: "${urlInput}"`
        );
      } else {
        alert(
          `Access denied. Your access level (${
            getAccessLevelConfig().name
          }) does not permit accessing this URL: ${finalUrl}`
        );
      }
      return;
    }

    // console.log(`✅ URL allowed - proceeding with navigation to: ${finalUrl}`);

    // Log successful navigation
    SecureBrowserDatabaseService.logSecurityEvent(
      "unauthorized_access", // Using this type for positive security events
      `User navigated to ${
        isSearchQuery ? "search results" : "URL"
      }: ${finalUrl}${isSearchQuery ? ` (query: "${urlInput}")` : ""}`,
      "low",
      finalUrl
    );

    const webview = webviewRefs.current[activeTab] as HTMLElement & {
      src: string;
    };

    if (webview) {
      // For search queries, set a more descriptive title immediately
      const newTitle = isSearchQuery ? `Search: ${urlInput}` : "Loading...";
      
      // Update tab state with the final URL
      setTabs((tabs) =>
        tabs.map((tab) =>
          tab.id === activeTab
            ? {
                ...tab,
                url: finalUrl,
                isLoading: true,
                title: newTitle,
              }
            : tab
        )
      );

      // Update the URL input to show the final URL
      setUrlInput(finalUrl);

      // Navigate webview
      // console.log(`🚀 Setting webview src to: ${finalUrl}`);
      webview.src = finalUrl;
    }
  }, [
    urlInput,
    allowBrowsing,
    vpnStatus,
    isUrlAllowed,
    activeTab,
    getAccessLevelConfig,
    processInput,
    isValidUrl,
    user?.accessLevel,
  ]);

  const handleUrlChange = useCallback((value: string) => {
    setUrlInput(value);
  }, []);

  const goBack = useCallback(() => {
    const webview = webviewRefs.current[activeTab] as HTMLElement & {
      canGoBack(): boolean;
      goBack(): void;
    };
    if (webview && webview.canGoBack()) {
      webview.goBack();
    }
  }, [activeTab]);

  const goForward = useCallback(() => {
    const webview = webviewRefs.current[activeTab] as HTMLElement & {
      canGoForward(): boolean;
      goForward(): void;
    };
    if (webview && webview.canGoForward()) {
      webview.goForward();
    }
  }, [activeTab]);

  const reload = useCallback(() => {
    const webview = webviewRefs.current[activeTab] as HTMLElement & {
      reload(): void;
    };
    if (webview) {
      webview.reload();
    }
  }, [activeTab]);

  // Context menu handlers
  const handleContextMenu = useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      event.preventDefault();
      setContextMenu({
        visible: true,
        x: event.clientX,
        y: event.clientY,
      });
    },
    []
  );

  const hideContextMenu = useCallback(() => {
    setContextMenu({ visible: false, x: 0, y: 0 });
  }, []);

  const saveAsPDF = useCallback(async () => {
    try {
      const webview = webviewRefs.current[activeTab] as any;
      if (webview && webview.printToPDF) {
        // console.log("📄 Saving page as PDF...");
        // Use Electron's IPC to handle PDF generation
        // const result = await window.electronAPI?.savePageAsPDF?.();
        // console.log("PDF save feature would be implemented here");
        // console.log("✅ PDF save triggered (functionality pending)");
      } else {
        // console.error("❌ PDF functionality not available");
      }
    } catch (error) {
      // console.error("❌ Error saving PDF:", error);
    }
    hideContextMenu();
  }, [activeTab, hideContextMenu]);

  const printPage = useCallback(() => {
    const webview = webviewRefs.current[activeTab] as any;
    if (webview && webview.print) {
      webview.print();
    }
    hideContextMenu();
  }, [activeTab, hideContextMenu]);

  const copyUrl = useCallback(() => {
    const currentTab = tabs.find((tab) => tab.id === activeTab);
    if (currentTab) {
      navigator.clipboard.writeText(currentTab.url);
      // console.log("📋 URL copied to clipboard");
    }
    hideContextMenu();
  }, [activeTab, tabs, hideContextMenu]);

  const testDownload = useCallback(() => {
    // Create a test file download
    const testContent = `Test file downloaded at ${new Date().toISOString()}\n\nThis is a test download from the Aussie Vault Browser.\nDownload functionality is working correctly!`;
    const blob = new Blob([testContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);

    // Create a temporary link and trigger download
    const a = document.createElement("a");
    a.href = url;
    a.download = `test-download-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    // console.log("🧪 Test download initiated");
    hideContextMenu();
  }, [hideContextMenu]);

  const openInNewTab = useCallback(() => {
    const currentTab = tabs.find((tab) => tab.id === activeTab);
    if (currentTab) {
      // Create new tab functionality
      const newTabId = Date.now().toString();
      setTabs((prev) => [
        ...prev,
        {
          id: newTabId,
          title: "New Tab",
          url: currentTab.url,
          isLoading: false,
        },
      ]);
      setActiveTabWithSync(newTabId);
    }
    hideContextMenu();
  }, [activeTab, tabs, hideContextMenu]);

  // Download management functions
  const addDownloadToState = useCallback((downloadData: any) => {
    const newDownload: DownloadItem = {
      id: downloadData.id,
      filename: downloadData.filename,
      url: downloadData.url,
      size: downloadData.totalBytes || 0,
      totalBytes: downloadData.totalBytes || 0,
      downloadedBytes: 0,
      status: "downloading",
      startTime: new Date(),
      speed: 0,
      progress: 0,
    };

    setDownloads((prev) => {
      // Check if download with this ID already exists
      const existingDownload = prev.find((d) => d.id === downloadData.id);
      if (existingDownload) {
        // console.log(
        //   "⚠️ Download with ID already exists, skipping duplicate:",
        //   downloadData.id
        // );
        return prev; // Don't add duplicate
      }

      // console.log("📥 Added download to state:", newDownload.filename);
      return [...prev, newDownload];
    });

    return newDownload.id;
  }, []);

  const updateDownloadProgress = useCallback((progressData: any) => {
    setDownloads((prev) =>
      prev.map((download) => {
        if (download.id === progressData.id) {
          const progress =
            progressData.totalBytes > 0
              ? Math.round(
                  (progressData.receivedBytes / progressData.totalBytes) * 100
                )
              : 0;

          const updatedDownload = {
            ...download,
            downloadedBytes: progressData.receivedBytes || 0,
            totalBytes: progressData.totalBytes || download.totalBytes,
            speed: progressData.speed || 0,
            progress: progress,
          };

          // console.log(
          //   `📊 Updated download progress: ${updatedDownload.filename} - ${progress}%`
          // );
          return updatedDownload;
        }
        return download;
      })
    );
  }, []);

  const cancelDownload = useCallback((id: string) => {
    // console.log("🚫 Cancelling download:", id);

    // Update UI state to mark as cancelled
    setDownloads((prev) =>
      prev.map((download) =>
        download.id === id
          ? { ...download, status: "cancelled" as const, endTime: new Date() }
          : download
      )
    );

    // console.log("✅ Download marked as cancelled in UI:", id);
  }, []);

  const viewFile = useCallback(async (filePath: string, filename: string) => {
    try {
      // console.log("📁 Opening file:", { filePath, filename });

      // Use Electron's shell to open the file with the system's default application
      if (window.electronAPI?.shell?.openPath) {
        const result = await window.electronAPI.shell.openPath(filePath);
        if (result) {
          // console.error("❌ Failed to open file:", result);
          alert(`Failed to open file: ${result}`);
        } else {
          // console.log("✅ File opened successfully");
        }
      } else {
        // Fallback: try to open using the browser (for blob URLs, etc.)
        // console.log("⚠️ Electron shell not available, trying browser fallback");
        if (filePath.startsWith("blob:") || filePath.startsWith("data:")) {
          const link = document.createElement("a");
          link.href = filePath;
          link.download = filename;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          // console.log("✅ File downloaded via browser fallback");
        } else {
          // console.error("❌ Cannot open file: No suitable method available");
          alert(
            "Cannot open file: File opening is not supported in this environment"
          );
        }
      }
    } catch (error) {
      // console.error("❌ Error opening file:", error);
      alert(
        `Error opening file: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }, []);

  const revealInExplorer = useCallback(
    async (filePath: string, filename: string) => {
      try {
        // console.log("📂 Revealing file in explorer:", { filePath, filename });

        // Use Electron's shell to show the file in the system's file manager
        if (window.electronAPI?.shell?.showItemInFolder) {
          const result = await window.electronAPI.shell.showItemInFolder(
            filePath
          );
          if (result) {
            // console.error("❌ Failed to reveal file:", result);
            alert(`Failed to show file in folder: ${result}`);
          } else {
            // console.log("✅ File revealed in explorer successfully");
          }
        } else {
          // console.error("❌ Cannot reveal file: Shell API not available");
          alert(
            "Cannot show file in folder: This feature is not supported in this environment"
          );
        }
      } catch (error) {
        // console.error("❌ Error revealing file:", error);
        alert(
          `Error showing file in folder: ${
            error instanceof Error ? error.message : "Unknown error"
          }`
        );
      }
    },
    []
  );

  // Clear downloads history
  const clearDownloads = useCallback(() => {
    try {
      setDownloads([]);
      localStorage.removeItem("app-downloads");
      // console.log("🗑️ Downloads history cleared");
    } catch (error) {
      // console.error("❌ Failed to clear downloads:", error);
    }
  }, []);

  const getActiveDownloads = useCallback(() => {
    return downloads.filter((d) => d.status === "downloading");
  }, [downloads]);

  // Click handler to hide context menu
  useEffect(() => {
    const handleClick = () => {
      hideContextMenu();
    };

    if (contextMenu.visible) {
      document.addEventListener("click", handleClick);
      return () => document.removeEventListener("click", handleClick);
    }
  }, [contextMenu.visible, hideContextMenu]);

  // Listen for download events from main process
  useEffect(() => {
    const handleDownloadStarted = (_event: any, downloadData: any) => {
      try {
        // console.log(
        //   "🎯 [REACT] Download started event received:",
        //   downloadData
        // );
        // console.log("🎯 [REACT] Current downloads state before adding:", {
        //   total: downloads.length,
        //   byId: downloads.map((d) => ({
        //     id: d.id,
        //     filename: d.filename,
        //     status: d.status,
        //   })),
        // });

        if (downloadData && downloadData.id && downloadData.filename) {
          addDownloadToState(downloadData);
        } else {
          // Invalid download started data
        }
      } catch (error) {
        // console.error(
        //   "❌ [REACT] Error handling download started event:",
        //   error
        // );
      }
    };

    const handleDownloadProgress = (_event: any, progressData: any) => {
      try {
        const percent =
          progressData.totalBytes > 0
            ? Math.round(
                (progressData.receivedBytes / progressData.totalBytes) * 100
              )
            : 0;
        // console.log("🎯 [REACT] Download progress event received:", {
        //   id: progressData.id,
        //   progress: progressData.receivedBytes + "/" + progressData.totalBytes,
        //   percent: percent + "%",
        // });

        if (progressData && progressData.id) {
          updateDownloadProgress(progressData);
        } else {
          // console.warn(
          //   "⚠️ [REACT] Invalid download progress data:",
          //   progressData
          // );
        }
      } catch (error) {
        // console.error(
        //   "❌ [REACT] Error handling download progress event:",
        //   error
        // );
      }
    };

    const handleDownloadCompleted = (_event: any, completedData: any) => {
      try {
        // console.log(
        //   "🎯 [REACT] Download completed event received:",
        //   completedData
        // );

        if (completedData && completedData.id) {
          setDownloads((prev) =>
            prev.map((download) => {
              if (download.id === completedData.id) {
                const finalStatus =
                  completedData.state === "completed"
                    ? "completed"
                    : completedData.state === "cancelled"
                    ? "cancelled"
                    : "blocked";

                return {
                  ...download,
                  status: finalStatus as "completed" | "cancelled" | "blocked",
                  endTime: new Date(),
                  progress:
                    completedData.state === "completed"
                      ? 100
                      : download.progress,
                  filePath: completedData.filePath,
                };
              }
              return download;
            })
          );
        } else {
          // console.warn(
          //   "⚠️ [REACT] Invalid download completed data:",
          //   completedData
          // );
        }
      } catch (error) {
        // console.error(
        //   "❌ [REACT] Error handling download completed event:",
        //   error
        // );
      }
    };

    const handleDownloadBlocked = (_event: any, blockedData: any) => {
      try {
        // console.log("🎯 [REACT] Download blocked event received:", blockedData);

        if (blockedData && blockedData.filename) {
          // First check if this is an existing download that got blocked
          setDownloads((prev) => {
            const existingDownload = prev.find(
              (d) =>
                d.filename === blockedData.filename &&
                d.url === blockedData.url &&
                d.status === "downloading"
            );

            if (existingDownload) {
              // Update existing download to blocked status
              // console.log(
              //   "📋 Updating existing download to blocked status:",
              //   blockedData.filename
              // );
              return prev.map((download) =>
                download.id === existingDownload.id
                  ? {
                      ...download,
                      status: "blocked" as const,
                      endTime: new Date(),
                    }
                  : download
              );
            } else {
              // Create new blocked download entry (only if no existing download found)
              const blockedDownload = {
                id: `blocked-${Date.now()}-${Math.random()
                  .toString(36)
                  .substr(2, 9)}`,
                filename: blockedData.filename,
                url: blockedData.url,
                size: blockedData.size || 0,
                totalBytes: blockedData.size || 0,
                downloadedBytes: 0,
                status: "blocked" as const,
                startTime: new Date(),
                progress: 0,
              };
              // console.log(
              //   "📥 Created new blocked download entry:",
              //   blockedData.filename
              // );
              return [...prev, blockedDownload];
            }
          });
        } else {
          // console.warn(
          // //   "⚠️ [REACT] Invalid download blocked data:",
          // //   blockedData
          // );
        }
      } catch (error) {
        // console.error(
        //   "❌ [REACT] Error handling download blocked event:",
        //   error
        // );
      }
    };

    // Set up actual download IPC listeners with error handling
    try {
      // console.log("🔧 [REACT] Setting up download IPC listeners...");
      // console.log("🔧 [REACT] secureBrowser availability:", {
      //   exists: !!window.secureBrowser,
      //   onMethod: !!window.secureBrowser?.on,
      //   removeListenerMethod: !!window.secureBrowser?.removeListener,
      // });

      if (window.secureBrowser?.on) {
        // console.log("🔧 [REACT] Attaching download event listeners...");
        window.secureBrowser.on("download-started", handleDownloadStarted);
        window.secureBrowser.on("download-progress", handleDownloadProgress);
        window.secureBrowser.on("download-completed", handleDownloadCompleted);
        window.secureBrowser.on("download-blocked", handleDownloadBlocked);
        // console.log("✅ [REACT] Download IPC listeners attached successfully");

        // Test connection with a simple IPC call
        window.secureBrowser.system
          ?.getEnvironment?.()
          .then(() => {
            // console.log("✅ [REACT] IPC connection test successful")
          })
          .catch((err) => {
            // console.warn("⚠️ [REACT] IPC connection test failed:", err)
          });
      } else {
        // console.warn(
        //   "⚠️ [REACT] secureBrowser.on not available - download events will not work"
        // );
        // console.warn(
        //   "⚠️ [REACT] Available methods:",
        //   Object.keys(window.secureBrowser || {})
        // );
      }
    } catch (error) {
      // console.error("❌ [REACT] Failed to set up download listeners:", error);
    }

    return () => {
      // Cleanup listeners with error handling
      try {
        if (window.secureBrowser?.removeListener) {
          window.secureBrowser.removeListener(
            "download-started",
            handleDownloadStarted
          );
          window.secureBrowser.removeListener(
            "download-progress",
            handleDownloadProgress
          );
          window.secureBrowser.removeListener(
            "download-completed",
            handleDownloadCompleted
          );
          window.secureBrowser.removeListener(
            "download-blocked",
            handleDownloadBlocked
          );
          // console.log("🧹 [REACT] Download listeners cleaned up successfully");
        }
      } catch (error) {
        // console.error(
        //   "❌ [REACT] Error during download listener cleanup:",
        //   error
        // );
      }
    };
  }, []); // Remove dependencies to prevent re-attachment

  const goHome = useCallback(() => {
    const homeUrl = getHomeUrl();

    // Log home navigation
    SecureBrowserDatabaseService.logNavigation(homeUrl, true);
    SecureBrowserDatabaseService.logSecurityEvent(
      "unauthorized_access",
      "User navigated to home page",
      "low",
      homeUrl
    );

    setUrlInput(homeUrl);
    const webview = webviewRefs.current[activeTab] as HTMLElement & {
      src: string;
    };
    if (webview) {
      setTabs((tabs) =>
        tabs.map((tab) =>
          tab.id === activeTab
            ? { ...tab, url: homeUrl, isLoading: true, title: "Loading..." }
            : tab
        )
      );
      webview.src = homeUrl;
    }
  }, [activeTab, getHomeUrl]);

  const createNewTab = useCallback(() => {
    const newTabId = Date.now().toString();
    const homeUrl = getHomeUrl();
    const newTab: Tab = {
      id: newTabId,
      title: "New Tab",
      url: homeUrl,
      isLoading: false,
    };

    // Log new tab creation
    SecureBrowserDatabaseService.logSecurityEvent(
      "unauthorized_access",
      "User created new browser tab",
      "low",
      homeUrl
    );

    setTabs((prevTabs) => [...prevTabs, newTab]);
    setActiveTab(newTabId);
    setUrlInput(homeUrl);
  }, [getHomeUrl]);

  const closeTab = useCallback(
    (tabId: string) => {
      if (tabs.length <= 1) return;

      const newTabs = tabs.filter((tab) => tab.id !== tabId);
      setTabs(newTabs);

      // Clean up webview refs
      delete webviewRefs.current[tabId];
      delete webviewInitialized.current[tabId];

      if (activeTab === tabId) {
        setActiveTabWithSync(newTabs[0].id);
        setUrlInput(newTabs[0].url);
      }
    },
    [tabs, activeTab]
  );

  const createNewWindow = useCallback(async () => {
    if (!allowBrowsing) {
      // Log blocked window creation due to VPN
      SecureBrowserDatabaseService.logSecurityEvent(
        "domain_blocked",
        "New window creation blocked due to VPN disconnection",
        "medium"
      );

      alert(
        `VPN connection required. Cannot create new window until Australian VPN connection is established. Status: ${vpnStatus}`
      );
      return;
    }

    try {
      // Log new window creation attempt
      SecureBrowserDatabaseService.logSecurityEvent(
        "unauthorized_access",
        "User created new browser window",
        "low"
      );

      const result = await window.secureBrowser.window.createNew();
      if (result.success) {
        // console.log(
        //   "✅ New browser window created successfully:",
        //   result.windowId
        // );
      } else {
        // console.error("❌ Failed to create new window:", result.error);

        // Log window creation failure
        SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `Failed to create new window: ${result.error}`,
          "medium"
        );

        alert(`Failed to create new window: ${result.error}`);
      }
    } catch (error) {
      // Error creating new window

      // Log window creation error
      SecureBrowserDatabaseService.logSecurityEvent(
        "unauthorized_access",
        `Error creating new window: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        "medium"
      );

      alert("Failed to create new window. Please try again.");
    }
  }, [allowBrowsing, vpnStatus]);

  // Update URL input when switching tabs (stable version - prevents auto-navigation)
  useEffect(() => {
    const currentTab = tabs.find((tab) => tab.id === activeTab);
    if (currentTab) {
      setUrlInput(currentTab.url);
    }
  }, [activeTab, tabs]);

  // Apply zoom to newly active tab (separate effect to prevent conflicts)
  useEffect(() => {
    if (zoomLevel !== 100) {
      const timeoutId = setTimeout(() => {
        applyZoomToActiveWebview(zoomLevel);
      }, 200); // Balanced delay for responsiveness without conflicts
      
      return () => clearTimeout(timeoutId);
    }
  }, [activeTab, applyZoomToActiveWebview, zoomLevel]);

  // Webview event handlers
  // SharePoint credential injection is now handled in setupWebviewEvents
  // This useEffect was removed to prevent duplicate navigation handlers

  const setupWebviewEvents = useCallback(
    (webview: HTMLElement, tabId: string) => {
      // Prevent setting up events multiple times for the same webview
      if (webviewInitialized.current[tabId]) {
        return;
      }

      webviewInitialized.current[tabId] = true;

      // 🔐 SIMPLE WEBVIEW SETUP: No complex focus management needed with global shortcuts
      // console.log("🔧 Setting up webview for tab:", tabId);

      type WebviewEvent = Event & {
        url: string;
        title?: string;
        errorCode?: number;
        errorDescription?: string;
      };

      webview.addEventListener("did-start-loading", () => {
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === tabId ? { ...tab, isLoading: true } : tab
          )
        );
      });

      webview.addEventListener("did-stop-loading", () => {
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === tabId ? { ...tab, isLoading: false } : tab
          )
        );
      });

      // Handle page load failures
      webview.addEventListener("did-fail-load", (event: Event) => {
        const failEvent = event as WebviewEvent;
        // console.error(
        //   `❌ Page failed to load: ${failEvent.url}, Error: ${failEvent.errorCode} - ${failEvent.errorDescription}`
        // );

        // Update tab title to show error
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === tabId
              ? {
                  ...tab,
                  isLoading: false,
                  title: `Failed to load: ${
                    failEvent.errorDescription || "Network Error"
                  }`,
                }
              : tab
          )
        );

        // Log security event for failed loads
        SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `Page failed to load: ${failEvent.url} - ${failEvent.errorDescription}`,
          "low",
          failEvent.url
        );
      });

      webview.addEventListener("page-title-updated", (event: Event) => {
        const webviewEvent = event as WebviewEvent;
        const newTitle = webviewEvent.title || "Untitled";

        setTabs((tabs) =>
          tabs.map((tab) => {
            if (tab.id === tabId) {
              // Add to history when title is updated (page fully loaded)
              addToHistory(tab.url, newTitle);
              return { ...tab, title: newTitle };
            }
            return tab;
          })
        );
      });

      webview.addEventListener("did-navigate", (event: Event) => {
        const webviewEvent = event as WebviewEvent;

        // Log navigation for monitoring
        SecureBrowserDatabaseService.logNavigation(webviewEvent.url, true);

        // Add to history for navigation
        addToHistory(webviewEvent.url, "Loading...");

        // ALWAYS update URL input when navigation occurs - this fixes the URL bar not updating
        if (tabId === activeTab) {
          setUrlInput(webviewEvent.url);
        }
        
        // Update tab URL without affecting loading state
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === tabId ? { ...tab, url: webviewEvent.url } : tab
          )
        );

        // Check if navigating to SharePoint/Office365 for credential injection
        if (
          webviewEvent.url.includes("sharepoint.com") ||
          webviewEvent.url.includes("login.microsoftonline.com") ||
          webviewEvent.url.includes("office.com")
        ) {
          // Log SharePoint access
          SecureBrowserDatabaseService.logSecurityEvent(
            "unauthorized_access",
            "User accessed SharePoint/Office365 site",
            "low",
            webviewEvent.url
          );

          // Wait for page load, then inject credentials
          setTimeout(async () => {
            try {
              await injectSharePointCredentials(webview);
              
              // Log successful credential injection
              SecureBrowserDatabaseService.logSecurityEvent(
                "unauthorized_access",
                "SharePoint credentials automatically injected",
                "low",
                webviewEvent.url
              );
            } catch (error) {
              // Log credential injection failure
              SecureBrowserDatabaseService.logSecurityEvent(
                "unauthorized_access",
                `Failed to inject SharePoint credentials: ${
                  error instanceof Error ? error.message : "Unknown error"
                }`,
                "medium",
                webviewEvent.url
              );
            }
          }, 2000);
        }
      });

      webview.addEventListener("did-navigate-in-page", (event: Event) => {
        const webviewEvent = event as WebviewEvent;

        // Log in-page navigation for monitoring
        SecureBrowserDatabaseService.logNavigation(webviewEvent.url, true);

        // ALWAYS update URL input for in-page navigation - this fixes URL bar not updating
        if (tabId === activeTab) {
          setUrlInput(webviewEvent.url);
        }
        setTabs((tabs) =>
          tabs.map((tab) =>
            tab.id === tabId ? { ...tab, url: webviewEvent.url } : tab
          )
        );
      });



      // Handle new-window events - COMPLETELY DISABLED FOR LEVEL 3 USERS
      webview.addEventListener("new-window", (event: Event) => {
        const newWindowEvent = event as Event & {
          url: string;
          frameName: string;
          disposition: string;
        };

        // LEVEL 3 USERS: NO RESTRICTIONS - Let them navigate freely like Chrome
        if (user?.accessLevel === 3) {
          // Don't prevent anything - let it work like a normal browser
          return;
        }
        
        // Only block for Level 1 and 2 users
        event.preventDefault();
        
        // Log that we blocked a popup attempt
        SecureBrowserDatabaseService.logSecurityEvent(
          "unauthorized_access",
          `Popup window blocked for security: ${newWindowEvent.url}`,
          "low",
          newWindowEvent.url
        );
      });

      // Note: Download events are now handled in the main process

      // Log console errors and security warnings
      webview.addEventListener("console-message", (event: Event) => {
        const consoleEvent = event as Event & {
          level: number;
          message: string;
          sourceId: string;
        };

        // Log security-related console messages (level 3 = error, level 2 = warning)
        if (consoleEvent.level >= 2) {
          SecureBrowserDatabaseService.logSecurityEvent(
            "unauthorized_access",
            `Console ${consoleEvent.level >= 3 ? "error" : "warning"}: ${
              consoleEvent.message
            }`,
            consoleEvent.level >= 3 ? "low" : "low",
            consoleEvent.sourceId
          );
        }
      });

      // Add context menu event listener for webview content
      const webviewContextMenu = (event: Event) => {
        const mouseEvent = event as MouseEvent;
        mouseEvent.preventDefault();
        mouseEvent.stopPropagation();

        // console.log(
        //   "🖱️ Webview context menu triggered at:",
        //   mouseEvent.clientX,
        //   mouseEvent.clientY
        // );

        setContextMenu({
          visible: true,
          x: mouseEvent.clientX,
          y: mouseEvent.clientY,
        });
      };

      // Listen to context menu events from the webview
      webview.addEventListener("contextmenu", webviewContextMenu, true);

      // Also handle the Electron webview's context-menu event
      if ((webview as any).addEventListener) {
        (webview as any).addEventListener("context-menu", (e: any) => {
          // console.log("🖱️ Electron webview context-menu event:", e);
          e.preventDefault();

          setContextMenu({
            visible: true,
            x: e.params?.x || 100,
            y: e.params?.y || 100,
          });
        });
      }

      // Fallback: Listen for right-click using mousedown events
      const handleMouseDown = (event: Event) => {
        const mouseEvent = event as MouseEvent;
        if (mouseEvent.button === 2) {
          // Right mouse button
          // console.log(
          //   "🖱️ Right mouse button detected on webview at:",
          //   mouseEvent.clientX,
          //   mouseEvent.clientY
          // );
          mouseEvent.preventDefault();

          setContextMenu({
            visible: true,
            x: mouseEvent.clientX,
            y: mouseEvent.clientY,
          });
        }
      };

      webview.addEventListener("mousedown", handleMouseDown, true);
    },
    [activeTab]
  );

  // Memoize webview ref callback to prevent unnecessary re-initialization
  const createWebviewRef = useCallback(
    (tabId: string) => {
      return (ref: HTMLElement | null) => {
        if (ref && !webviewRefs.current[tabId]) {
          webviewRefs.current[tabId] = ref;
          setupWebviewEvents(ref, tabId);
        }
      };
    },
    [setupWebviewEvents]
  );

  const config = useMemo(() => getAccessLevelConfig(), [getAccessLevelConfig]);

  // 🔐 IPC KEYBOARD HANDLER: Set up global keyboard shortcuts via main process
  const lastShortcutTime = useRef<{ [key: string]: number }>({});

  useEffect(() => {
    const handleIPCKeyboardShortcut = (_event: any, shortcut: string) => {
      // console.log(
      //   "⌨️ [IPC] Received keyboard shortcut from main process:",
      //   shortcut
      // );

      // Debounce: prevent duplicate shortcuts within 100ms
      const now = Date.now();
      const lastTime = lastShortcutTime.current[shortcut] || 0;
      if (now - lastTime < 100) {
        // console.log("⚠️ [IPC] Debouncing duplicate shortcut:", shortcut);
        return;
      }
      lastShortcutTime.current[shortcut] = now;

      switch (shortcut) {
        case "zoom-in":
          handleZoomIn();
          break;
        case "zoom-out":
          handleZoomOut();
          break;
        case "zoom-reset":
          // console.log("⌨️ [IPC] Zoom reset via IPC");
          handleZoomReset();
          break;
        case "new-tab":
          // console.log("⌨️ [IPC] Creating new tab via IPC");
          createNewTab();
          break;
        case "new-window":
          createNewWindow();
          break;
        case "close-tab":
          if (tabs.length > 1) {
            closeTab(activeTab);
          }
          break;
        case "reload":
          reload();
          break;
        case "history":
          handleHistoryClick();
          break;
        case "downloads":
          handleDownloadsClick();
          break;
        case "bookmarks":
          handleBookmarksClick();
          break;
        case "task-manager":
          handleTaskManagerClick();
          break;
        default:
          // console.log("⚠️ [IPC] Unknown shortcut:", shortcut);
      }
    };

    // Listen for IPC keyboard shortcuts from main process
    if (window.ipcRenderer?.on) {
      window.ipcRenderer.on("keyboard-shortcut", handleIPCKeyboardShortcut);
      // console.log("✅ [IPC] Keyboard shortcut listener attached");
    } else {
      // console.warn("⚠️ [IPC] ipcRenderer not available, using fallback");
    }

    return () => {
      if (window.ipcRenderer?.off) {
        window.ipcRenderer.off("keyboard-shortcut", handleIPCKeyboardShortcut);
        // console.log("🧹 [IPC] Keyboard shortcut listener removed");
      }
    };
  }, []); // Remove dependencies to prevent re-attachment

  useEffect(() => {
    // 🔐 FALLBACK KEYBOARD HANDLER: Only active if IPC is not available
    const hasIPCSupport = !!window.ipcRenderer?.on;

    if (hasIPCSupport) {
      // console.log(
      //   "⌨️ [FALLBACK] IPC is available, using IPC for all shortcuts - no fallback needed"
      // );
      return; // Don't set up any keyboard listeners if IPC is available
    }

    // console.log(
    //   "⌨️ [FALLBACK] IPC not available, setting up fallback keyboard handlers"
    // );

    const handleKeyDown = (event: KeyboardEvent) => {
      // console.log("⌨️ [FALLBACK] Keyboard event:", {
      //   key: event.key,
      //   ctrlKey: event.ctrlKey,
      //   metaKey: event.metaKey,
      //   target: (event.target as HTMLElement)?.tagName,
      //   activeElement: (document.activeElement as HTMLElement)?.tagName,
      // });

      // Check for Ctrl/Cmd key
      const isModifierPressed = event.ctrlKey || event.metaKey;

      if (isModifierPressed) {
        let handled = false;

        switch (event.key.toLowerCase()) {
          // Zoom controls
          case "=":
          case "+":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Keyboard zoom in triggered");
            handleZoomIn();
            handled = true;
            break;
          case "-":
          case "_":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Keyboard zoom out triggered");
            handleZoomOut();
            handled = true;
            break;
          case "0":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Keyboard zoom reset triggered");
            handleZoomReset();
            handled = true;
            break;

          // Navigation shortcuts
          case "t":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] New tab triggered (Ctrl+T)");
            createNewTab();
            handled = true;
            break;
          case "n":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] New window triggered (Ctrl+N)");
            createNewWindow();
            handled = true;
            break;
          case "h":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] History triggered (Ctrl+H)");
            handleHistoryClick();
            handled = true;
            break;
          case "j":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Downloads triggered (Ctrl+J)");
            handleDownloadsClick();
            handled = true;
            break;
          case "w":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Close tab triggered (Ctrl+W)");
            if (tabs.length > 1) {
              closeTab(activeTab);
            }
            handled = true;
            break;
          case "r":
            event.preventDefault();
            event.stopPropagation();
            // console.log("⌨️ [FALLBACK] Reload triggered (Ctrl+R)");
            reload();
            handled = true;
            break;
        }

        // Handle Ctrl+Shift combinations
        if (event.shiftKey) {
          switch (event.key.toLowerCase()) {
            case "o":
              event.preventDefault();
              event.stopPropagation();
              // console.log("⌨️ [FALLBACK] Bookmarks triggered (Ctrl+Shift+O)");
              handleBookmarksClick();
              handled = true;
              break;
            case "i":
              event.preventDefault();
              event.stopPropagation();
                // console.log(
                //   "⌨️ [FALLBACK] Developer tools triggered (Ctrl+Shift+I)"
                // );
                // TODO: Implement developer tools
              handled = true;
              break;
            case "t":
              event.preventDefault();
              event.stopPropagation();
              // console.log(
              //   "⌨️ [FALLBACK] Task manager triggered (Ctrl+Shift+T)"
              // );
              handleTaskManagerClick();
              handled = true;
              break;
          }
        }

        if (handled) {
          // Force focus back to the browser window to ensure subsequent key events work
          setTimeout(() => {
            const browserWindow = document.querySelector(
              ".browser-window-container"
            );
            if (browserWindow) {
              (browserWindow as HTMLElement).focus();
            }
          }, 10);
        }
      }

      // Handle function keys (no modifier needed)
      if (event.key === "F12") {
        event.preventDefault();
        event.stopPropagation();
        // console.log("⌨️ [FALLBACK] Developer tools triggered (F12)");
        // TODO: Implement developer tools
      }
    };

    // Add mouse wheel zoom support
    const handleWheel = (event: WheelEvent) => {
      const isModifierPressed = event.ctrlKey || event.metaKey;

      if (isModifierPressed) {
        event.preventDefault();
        event.stopPropagation();

        // console.log("🖱️ [ZOOM] Mouse wheel zoom triggered");

        if (event.deltaY < 0) {
          // Scroll up - zoom in
          handleZoomIn();
        } else {
          // Scroll down - zoom out
          handleZoomOut();
        }
      }
    };

    // Add event listeners - simple and reliable
    const addListeners = () => {
      document.addEventListener("keydown", handleKeyDown, true);
      window.addEventListener("keydown", handleKeyDown, true);
      document.addEventListener("wheel", handleWheel, {
        passive: false,
        capture: true,
      });
      window.addEventListener("wheel", handleWheel, {
        passive: false,
        capture: true,
      });

        // console.log(
        //   "🔧 [KEYBOARD] Event listeners attached, IPC support:",
        //   !!window.secureBrowser?.on
        // );
    };

    const removeListeners = () => {
      document.removeEventListener("keydown", handleKeyDown, true);
      window.removeEventListener("keydown", handleKeyDown, true);
      document.removeEventListener("wheel", handleWheel, true);
      window.removeEventListener("wheel", handleWheel, true);

      // console.log("🧹 [KEYBOARD] All keyboard/mouse listeners removed");
    };

    addListeners();

    // Cleanup
    return removeListeners;
  }, [
    handleZoomIn,
    handleZoomOut,
    handleZoomReset,
    createNewTab,
    createNewWindow,
    handleHistoryClick,
    handleDownloadsClick,
    handleBookmarksClick,
    handleTaskManagerClick,
    tabs.length,
    activeTab,
    closeTab,
    reload,
  ]);

  // 🔐 SIMPLE CONTEXT MENU CLOSER: Only handle context menu closing
  useEffect(() => {
    const handleClick = () => {
      hideContextMenu();
    };

    document.addEventListener("click", handleClick);

    return () => {
      document.removeEventListener("click", handleClick);
    };
  }, [hideContextMenu]);

  return (
    <div
      className="flex flex-col h-full bg-white browser-window-container"
      onContextMenu={handleContextMenu}
    >
      {/* Browser Controls - Fixed/Sticky */}
      <div className="flex items-center gap-3 p-3 border-b bg-gradient-to-r from-slate-800 to-slate-900 shadow-lg flex-shrink-0">
        {/* App Logo */}
        <div className="flex items-center gap-2 mr-2">
          <img
            src="/assets/aussie-browser-logo-32.png"
            alt="Aussie Vault Browser"
            className="h-7 w-7 rounded-md"
          />
        </div>

        <div className="flex items-center gap-0.5 bg-slate-700/50 rounded-lg p-1">
          <Button
            variant="ghost"
            onClick={goBack}
            className="h-8 w-8 p-0 text-slate-300 hover:text-white hover:bg-slate-600 transition-all duration-200 rounded-md"
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            onClick={goForward}
            className="h-8 w-8 p-0 text-slate-300 hover:text-white hover:bg-slate-600 transition-all duration-200 rounded-md"
          >
            <ArrowRight className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            onClick={reload}
            className="h-8 w-8 p-0 text-slate-300 hover:text-white hover:bg-slate-600 transition-all duration-200 rounded-md"
          >
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            onClick={goHome}
            className="h-8 w-8 p-0 text-slate-300 hover:text-white hover:bg-slate-600 transition-all duration-200 rounded-md"
          >
            <Home className="h-4 w-4" />
          </Button>

          {/* Bookmark Button */}
          <BookmarkButton
            url={urlInput}
            title={tabs.find((tab) => tab.id === activeTab)?.title || urlInput}
            userId={user?.dbId || 0}
            accessLevel={user?.accessLevel || 1}
            onNavigate={navigateToUrl}
          />
        </div>

        <Button
          variant="outline"
          onClick={createNewWindow}
          className="h-8 px-3 text-slate-300 hover:text-white hover:bg-slate-700 border-slate-600 hover:border-slate-500 transition-all duration-200 bg-slate-800/50"
          title="Open New Browser Window"
        >
          <ExternalLink className="h-4 w-4 mr-2" />
          New Window
        </Button>

        <SearchBar
          value={urlInput}
          onChange={handleUrlChange}
          onSubmit={handleUrlSubmit}
          placeholder={
            user?.accessLevel >= 2
              ? "Search Google or enter URL..."
              : "Enter SharePoint URL..."
          }
          userAccessLevel={user?.accessLevel || 1}
        />

        <div className="flex items-center gap-2">
          {/* VPN Status Indicator */}
          <Badge
            variant={
              vpnStatus === "connected"
                ? "default"
                : vpnStatus === "connecting"
                ? "secondary"
                : "destructive"
            }
            className={`px-3 py-1.5 text-xs font-medium h-8 flex items-center gap-1.5 ${
              vpnStatus === "connected"
                ? "bg-green-600 text-white border-green-500"
                : vpnStatus === "connecting"
                ? "bg-yellow-600 text-white border-yellow-500 animate-pulse"
                : "bg-red-600 text-white border-red-500 animate-pulse"
            }`}
          >
            <Globe className="h-3 w-3" />
            VPN: {connection.location}
            {vpnStatus === "connected" &&
              connection.ipAddress &&
              connection.ipAddress !== "Unknown" &&
              connection.ipAddress !== "Failed" &&
              connection.ipAddress !== "Failed to check" &&
              ` (${connection.ipAddress})`}
          </Badge>

          {/* Access Level Badge */}
          <Badge
            variant={config.variant}
            className="px-3 py-1.5 text-xs font-medium bg-slate-700 text-slate-200 border-slate-600 hover:bg-slate-600 transition-colors h-8 flex items-center"
          >
            <Shield className="h-3 w-3 mr-1" />
            {config.name}
          </Badge>

          {/* Temporary Zoom Debug Badge - Remove after testing */}
          <Badge
            variant="outline"
            className="px-2 py-1 text-xs font-mono bg-green-100 text-green-800 border-green-300 h-8 flex items-center gap-1"
            title="Current zoom level (debug indicator)"
          >
            🔍 {zoomLevel}%
            <button
              onClick={handleZoomIn}
              className="ml-1 px-1 bg-green-200 hover:bg-green-300 rounded text-xs"
              title="Test zoom in"
            >
              +
            </button>
            <button
              onClick={handleZoomOut}
              className="ml-1 px-1 bg-green-200 hover:bg-green-300 rounded text-xs"
              title="Test zoom out"
            >
              −
            </button>
          </Badge>

          {/* SharePoint Vault Auth Indicator */}
          {(urlInput.includes("sharepoint.com") ||
            urlInput.includes("office.com") ||
            urlInput.includes("login.microsoftonline.com")) && (
            <Badge
              variant="outline"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 text-white border-blue-500 h-8 text-xs font-medium"
            >
              <Lock className="h-3 w-3" />
              Vault Auth
            </Badge>
          )}

          {/* URL Blocked Indicator */}
          {!isUrlAllowed(urlInput) && (
            <Badge
              variant="destructive"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600 text-white border-red-500 animate-pulse h-8 text-xs font-medium"
            >
              <AlertTriangle className="h-3 w-3" />
              Blocked
            </Badge>
          )}

          {/* Downloads Button (Always Visible Like Chrome) */}
          <div className="ml-2 mr-2 relative">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleDownloadsClick}
              className="relative p-2 hover:bg-slate-100"
              title="Downloads"
            >
              <div className="relative">
                {/* Enhanced download icon with professional progress indicator */}
                <div className="relative w-4 h-4 group">
                  <FileDown className="w-4 h-4 transition-transform group-hover:scale-110" />

                  {/* Enhanced circular progress indicator for active downloads */}
                  {getActiveDownloads().length > 0 &&
                    (() => {
                      const activeDownloads = getActiveDownloads();
                      const totalProgress =
                        activeDownloads.reduce(
                          (sum, d) => sum + d.progress,
                          0
                        ) / activeDownloads.length;
                      const strokeDasharray = 2 * Math.PI * 8; // radius = 8
                      const strokeDashoffset =
                        strokeDasharray -
                        (strokeDasharray * totalProgress) / 100;

                      return (
                        <svg
                          className="absolute -top-1 -left-1 w-6 h-6 transform -rotate-90"
                          viewBox="0 0 20 20"
                        >
                          {/* Background circle with subtle glow */}
                          <circle
                            cx="10"
                            cy="10"
                            r="8"
                            stroke="rgba(59, 130, 246, 0.2)"
                            strokeWidth="1.5"
                            fill="none"
                          />
                          {/* Progress circle with gradient */}
                          <circle
                            cx="10"
                            cy="10"
                            r="8"
                            stroke="url(#navProgressGradient)"
                            strokeWidth="2.5"
                            fill="none"
                            strokeDasharray={strokeDasharray}
                            strokeDashoffset={strokeDashoffset}
                            strokeLinecap="round"
                            className="transition-all duration-500 ease-out"
                            style={{
                              filter:
                                "drop-shadow(0 0 3px rgba(59, 130, 246, 0.6))",
                            }}
                          />
                          <defs>
                            <linearGradient
                              id="navProgressGradient"
                              x1="0%"
                              y1="0%"
                              x2="100%"
                              y2="100%"
                            >
                              <stop offset="0%" stopColor="#3b82f6" />
                              <stop offset="50%" stopColor="#8b5cf6" />
                              <stop offset="100%" stopColor="#3b82f6" />
                            </linearGradient>
                          </defs>
                        </svg>
                      );
                    })()}

                  {/* Enhanced download count badge */}
                  {getActiveDownloads().length > 0 && (
                    <div className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center z-10 shadow-lg ring-2 ring-white animate-pulse">
                      <span className="text-xs text-white font-bold leading-none">
                        {getActiveDownloads().length}
                      </span>
                    </div>
                  )}

                  {/* Enhanced completed downloads indicator */}
                  {downloads.filter((d) => d.status === "completed").length >
                    0 &&
                    getActiveDownloads().length === 0 && (
                      <div className="absolute -top-1 -right-1 w-3 h-3 bg-gradient-to-br from-green-500 to-emerald-600 rounded-full shadow-md ring-1 ring-white"></div>
                    )}
                </div>
              </div>
            </Button>

            {/* Download Progress Tooltip - Shows on Hover When Active Downloads */}
            {getActiveDownloads().length > 0 && (
              <div className="absolute top-full right-0 mt-1 w-80 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-50 opacity-0 hover:opacity-100 transition-opacity duration-200 pointer-events-none">
                <div className="text-xs font-medium text-gray-700 mb-2">
                  Active Downloads ({getActiveDownloads().length})
                </div>

                {getActiveDownloads()
                  .slice(0, 3)
                  .map((download) => (
                    <div key={download.id} className="mb-3 last:mb-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-gray-700 truncate flex-1">
                          {download.filename}
                        </span>
                        <span className="text-xs text-gray-500 ml-2">
                          {download.progress}%
                        </span>
                      </div>

                      <div className="w-full bg-gray-200 rounded-full h-1.5 mb-1">
                        <div
                          className="bg-blue-600 h-1.5 rounded-full transition-all duration-300"
                          style={{ width: `${download.progress}%` }}
                        ></div>
                      </div>

                      <div className="flex items-center justify-between text-xs text-gray-500">
                        <span>
                          {download.downloadedBytes > 0 &&
                          download.totalBytes > 0
                            ? `${
                                Math.round(
                                  (download.downloadedBytes / 1024 / 1024) * 100
                                ) / 100
                              } MB / ${
                                Math.round(
                                  (download.totalBytes / 1024 / 1024) * 100
                                ) / 100
                              } MB`
                            : "Calculating..."}
                        </span>
                        {download.speed && download.speed > 0 && (
                          <span>
                            {Math.round((download.speed / 1024 / 1024) * 100) /
                              100}{" "}
                            MB/s
                          </span>
                        )}
                      </div>
                    </div>
                  ))}

                {getActiveDownloads().length > 3 && (
                  <div className="text-xs text-gray-500 text-center mt-2 pt-2 border-t">
                    +{getActiveDownloads().length - 3} more downloads
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Browser Menu */}
          <BrowserMenu
            user={user}
            onHistoryClick={handleHistoryClick}
            onDownloadsClick={handleDownloadsClick}
            onBookmarksClick={handleBookmarksClick}
            onSettingsClick={handleSettingsClick}
            onLogout={handleLogout}
            onNewTabClick={createNewTab}
            onNewWindowClick={createNewWindow}
            onTaskManagerClick={handleTaskManagerClick}
            onDebugAuthClick={handleDebugAuthClick}
            onSharePointClick={handleSharePointClick}
            zoomLevel={zoomLevel}
            onZoomIn={handleZoomIn}
            onZoomOut={handleZoomOut}
            onZoomReset={handleZoomReset}
            className="ml-2"
          />
        </div>
      </div>

      {/* Tabs - Fixed/Sticky */}
      <Tabs
        value={activeTab}
        onValueChange={setActiveTabWithSync}
        className="flex-1 flex flex-col"
      >
        <div className="flex items-center border-b bg-gradient-to-r from-slate-100 to-slate-200 shadow-sm flex-shrink-0">
          <TabsList className="h-12 bg-transparent border-0 gap-1 p-1">
            {tabs.map((tab) => (
              <div key={tab.id} className="flex items-center">
                <TabsTrigger
                  value={tab.id}
                  className="flex items-center gap-2 px-4 py-2 rounded-t-lg border-b-2 border-transparent text-slate-600 hover:text-slate-800 hover:bg-white/70 data-[state=active]:bg-white data-[state=active]:text-slate-900 data-[state=active]:border-blue-500 data-[state=active]:shadow-sm transition-all duration-200"
                >
                  <span className="max-w-32 truncate font-medium">
                    {tab.isLoading ? (
                      <span className="flex items-center gap-2">
                        <div className="w-3 h-3 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                        Loading...
                      </span>
                    ) : (
                      tab.title
                    )}
                  </span>
                  {tabs.length > 1 && (
                    <span
                      className="h-5 w-5 flex items-center justify-center hover:bg-red-100 hover:text-red-600 rounded-full transition-all duration-200 cursor-pointer"
                      onClick={(e) => {
                        e.stopPropagation();
                        closeTab(tab.id);
                      }}
                    >
                      <X className="h-3 w-3" />
                    </span>
                  )}
                </TabsTrigger>
              </div>
            ))}
          </TabsList>
          <Button
            variant="ghost"
            size="sm"
            onClick={createNewTab}
            className="ml-3 mr-2 h-8 w-8 p-0 rounded-full bg-slate-200 hover:bg-slate-300 text-slate-600 hover:text-slate-800 transition-all duration-200 shadow-sm hover:shadow-md"
          >
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        {/* Tab Content - Scrollable Area */}
        <div className="flex-1">
          {tabs.map((tab) => (
            <TabsContent
              key={tab.id}
              value={tab.id}
              className="h-full m-0 data-[state=active]:block"
            >
              {(() => {
                // LEVEL 3 USERS: SKIP ALL CHECKS - Always show webview like Chrome
                if (user?.accessLevel === 3) {
                  return (
                    <webview
                      key={`webview-${tab.id}`}
                      ref={createWebviewRef(tab.id)}
                      src={tab.url}
                      style={{
                        width: "100%",
                        height: "100%",
                        border: "none",
                      }}
                      partition="persist:webview"
                      allowpopups
                      webpreferences="webSecurity=no,nodeIntegration=no,contextIsolation=no,allowRunningInsecureContent=yes,javascript=yes,plugins=yes,images=yes,java=yes,experimentalFeatures=yes,nativeWindowOpen=yes,backgroundThrottling=no,offscreen=no,sandbox=no"
                      useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                      httpreferrer=""
                      disablewebsecurity
                    />
                  );
                }

                // For Level 1 and 2 users, do the normal checks
                const shouldShowVPN = !allowBrowsing;
                const shouldShowLoader = isCheckingStatus || (tab.isLoading && !tab.url.startsWith("http"));
                const shouldShowRestriction = !isUrlAllowed(tab.url);
                
                if (shouldShowVPN) {
                  return (
                    <div className="overflow-y-auto max-h-[70vh]">
                      {/* Show VPN Connection Error when VPN is not connected */}
                      <VPNConnectionError
                        onRetry={connectVPN}
                        onCheckStatus={checkVPNStatus}
                        isRetrying={isConnecting}
                        isChecking={isCheckingStatus}
                        errorDetails={
                          lastError || `WireGuard endpoint: ${connection.endpoint}`
                        }
                        actualIP={actualIP}
                        actualCountry={actualCountry}
                      />
                    </div>
                  );
                }
                
                if (shouldShowLoader) {
                  return (
                /* Show beautiful loader while determining permissions or loading */
                <div className="flex-1 flex items-center justify-center bg-gradient-to-br from-slate-50 to-blue-50 min-h-full">
                  <div className="text-center">
                    {/* Beautiful animated loader */}
                    <div className="relative mb-8">
                      {/* Outer rotating ring */}
                      <div className="w-20 h-20 border-4 border-blue-200 rounded-full animate-spin mx-auto">
                        <div className="w-16 h-16 border-4 border-transparent border-t-blue-600 rounded-full animate-spin"></div>
                      </div>
                      {/* Inner pulsing dot */}
                      <div className="absolute inset-0 flex items-center justify-center">
                        <div className="w-3 h-3 bg-blue-600 rounded-full animate-pulse"></div>
                      </div>
                    </div>

                    {/* Loading text */}
                    <div className="space-y-2">
                      <h3 className="text-lg font-semibold text-slate-700">
                        {isCheckingStatus
                          ? "Verifying Access Permissions"
                          : "Securing Connection"}
                      </h3>
                      <p className="text-sm text-slate-500 max-w-sm mx-auto leading-relaxed">
                        {isCheckingStatus
                          ? "Checking your access level and domain permissions..."
                          : "Establishing secure browsing session through Australian VPN..."}
                      </p>
                    </div>

                    {/* Progress indicator */}
                    <div className="mt-6 w-48 mx-auto">
                      <div className="flex items-center space-x-2 text-xs text-slate-400">
                        <div className="flex-1 h-1 bg-slate-200 rounded-full overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 rounded-full animate-pulse"></div>
                        </div>
                      </div>
                      <div className="mt-2 flex items-center justify-center space-x-2">
                        <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
                        <div
                          className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"
                          style={{ animationDelay: "0.1s" }}
                        ></div>
                        <div
                          className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"
                          style={{ animationDelay: "0.2s" }}
                        ></div>
                      </div>
                    </div>

                    {/* Security badges */}
                    <div className="mt-8 flex items-center justify-center space-x-4">
                      <div className="flex items-center space-x-2 px-3 py-1.5 bg-white/70 rounded-full border border-emerald-200">
                        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                        <span className="text-xs font-medium text-emerald-700">
                          VPN Secured
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 px-3 py-1.5 bg-white/70 rounded-full border border-blue-200">
                        <Shield className="w-3 h-3 text-blue-600" />
                        <span className="text-xs font-medium text-blue-700">
                          Level {user?.accessLevel || 1} Access
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                  );
                }
                
                if (shouldShowRestriction) {
                  return (
                /* Show URL restriction error for blocked domains (NEVER for Level 3) */
                <div className="flex-1 flex items-center justify-center bg-gray-50">
                  <div className="text-center max-w-md">
                    <AlertTriangle className="h-16 w-16 text-red-500 mx-auto mb-4" />
                    <h2 className="text-xl font-semibold text-gray-900 mb-2">
                      Access Restricted
                    </h2>
                    <p className="text-gray-600 mb-4">
                      Your access level ({config.name}) does not permit
                      accessing this URL.
                    </p>
                    <div className="text-sm text-gray-500">
                      <p className="mb-2">Allowed domains for your level:</p>
                      <ul className="list-disc list-inside space-y-1">
                        {config.allowedDomains.map((domain, index) => (
                          <li key={index}>{domain}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                  );
                }
                
                // Default case for Level 1/2: show webview only if all checks pass
                return (
                  <webview
                    ref={createWebviewRef(tab.id)}
                    src={tab.url}
                    style={{
                      width: "100%",
                      height: "100%",
                      border: "none",
                    }}
                    partition="persist:webview"
                    allowpopups={user?.accessLevel === 3}
                    webpreferences="webSecurity=no,nodeIntegration=no,contextIsolation=no,allowRunningInsecureContent=yes,javascript=yes,plugins=yes,images=yes,java=yes,experimentalFeatures=yes,nativeWindowOpen=yes,backgroundThrottling=no,offscreen=no,sandbox=no"
                    useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                    httpreferrer=""
                    disablewebsecurity
                  />
                );
              })()}
            </TabsContent>
          ))}
        </div>
      </Tabs>

      {/* History Modal */}
      <HistoryModal
        isOpen={isHistoryModalOpen}
        onClose={() => setIsHistoryModalOpen(false)}
        onNavigate={navigateToUrl}
      />

      {/* Downloads Modal */}
      <DownloadsModal
        isOpen={isDownloadsModalOpen}
        onClose={() => setIsDownloadsModalOpen(false)}
        downloads={downloads}
        onCancelDownload={cancelDownload}
        onViewFile={viewFile}
        onRevealInExplorer={revealInExplorer}
        onClearDownloads={clearDownloads}
      />

      {/* Bookmarks Modal */}
      <BookmarksModal
        isOpen={isBookmarksModalOpen}
        onClose={() => setIsBookmarksModalOpen(false)}
        onNavigate={navigateToUrl}
        userId={user?.dbId || 0}
      />

      {/* Task Manager Modal */}
      <TaskManagerModal
        isOpen={isTaskManagerModalOpen}
        onClose={() => setIsTaskManagerModalOpen(false)}
      />

      {/* Debug Auth Modal */}
      <DebugAuthModal
        isOpen={isDebugAuthModalOpen}
        onClose={() => setIsDebugAuthModalOpen(false)}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
      />

      {/* SharePoint Sidebar */}
      <SharePointSidebar
        isOpen={isSharePointSidebarOpen}
        onClose={() => setIsSharePointSidebarOpen(false)}
        onFileSelect={(file) => {
          // console.log("Selected SharePoint file:", file);
          // Could navigate to file or perform other actions
        }}
      />

      {/* Context Menu */}
      {contextMenu.visible && (
        <div
          className="fixed bg-white border border-gray-300 rounded-lg shadow-xl py-2 z-50 min-w-48"
          style={{
            left: contextMenu.x,
            top: contextMenu.y,
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="text-xs text-gray-600 px-3 py-1 border-b border-gray-200 font-medium">
            Browser Actions
          </div>

          <button
            onClick={saveAsPDF}
            className="w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center gap-2 text-sm text-gray-900 transition-colors"
          >
            <FileDown className="w-4 h-4 text-gray-700" />
            Save as PDF
          </button>

          <button
            onClick={printPage}
            className="w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center gap-2 text-sm text-gray-900 transition-colors"
          >
            <Printer className="w-4 h-4 text-gray-700" />
            Print
          </button>

          <div className="border-t border-gray-200 my-1"></div>

          <button
            onClick={copyUrl}
            className="w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center gap-2 text-sm text-gray-900 transition-colors"
          >
            <Copy className="w-4 h-4 text-gray-700" />
            Copy URL
          </button>

          <button
            onClick={openInNewTab}
            className="w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center gap-2 text-sm text-gray-900 transition-colors"
          >
            <ExternalLink className="w-4 h-4 text-gray-700" />
            Open in New Tab
          </button>

          <div className="border-t border-gray-200 my-1"></div>

          <button
            onClick={reload}
            className="w-full text-left px-3 py-2 hover:bg-gray-50 flex items-center gap-2 text-sm text-gray-900 transition-colors"
          >
            <RotateCcw className="w-4 h-4 text-gray-700" />
            Reload Page
          </button>

          <div className="border-t border-gray-200 my-1"></div>

          <button
            onClick={testDownload}
            className="w-full text-left px-3 py-2 hover:bg-blue-50 flex items-center gap-2 text-sm text-blue-700 transition-colors font-medium"
          >
            <FileDown className="w-4 h-4 text-blue-600" />
            Test Download
          </button>
        </div>
      )}
    </div>
  );
};

export default BrowserWindow;
