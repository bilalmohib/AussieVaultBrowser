import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  X,
  ChevronRight,
  Home,
  Search,
  MoreVertical,
  Download,
  FolderOpen,
  File,
  Loader2,
  RefreshCw,
  ArrowLeft,
  Eye,
} from "lucide-react";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Card } from "../ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import {
  sharepointService,
  SharePointFile,
  SharePointSite,
  SharePointDrive,
  BreadcrumbItem,
} from "../../services/sharepointService";
import { SharePointDiagnostics } from "./SharePointDiagnostics";
import { cn } from "../../lib/utils";
import { FileViewerModal } from "../viewer/FileViewerModal";

interface SharePointSidebarProps {
  isOpen: boolean;
  onClose: () => void;
  onFileSelect?: (file: SharePointFile) => void;
  className?: string;
  initialWidth?: number;
  minWidth?: number;
  maxWidth?: number;
}

interface DragPreviewData {
  file: SharePointFile;
  blob: Blob | null;
  isReady: boolean;
}

// Enable debug mode to show detailed drag information
const DEBUG_DRAG_DROP = true;

export const SharePointSidebar: React.FC<SharePointSidebarProps> = ({
  isOpen,
  onClose,
  onFileSelect,
  className = "",
  initialWidth = 600,
  minWidth = 400,
  maxWidth = 1000,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [width, setWidth] = useState(initialWidth);
  const [isDragging, setIsDragging] = useState(false);
  const [_sites, setSites] = useState<SharePointSite[]>([]);
  const [selectedSite, setSelectedSite] = useState<SharePointSite | null>(null);
  const [selectedDrive, setSelectedDrive] = useState<SharePointDrive | null>(
    null
  );
  const [files, setFiles] = useState<SharePointFile[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [breadcrumb, setBreadcrumb] = useState<BreadcrumbItem[]>([
    { id: null, name: "Root" },
  ]);
  const [dragPreviews, setDragPreviews] = useState<
    Map<string, DragPreviewData>
  >(new Map());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [viewerOpen, setViewerOpen] = useState(false);
  const [viewerFile, setViewerFile] = useState<{
    name: string;
    url: string;
  } | null>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [downloadingFiles, setDownloadingFiles] = useState<Set<string>>(
    new Set()
  );

  const sidebarRef = useRef<HTMLDivElement>(null);
  const resizeHandleRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Initialize SharePoint service
  useEffect(() => {
    const initializeService = async () => {
      if (!isOpen) return;

      setIsLoading(true);
      setError(null);

      try {
        if (!sharepointService.isServiceInitialized()) {
          await sharepointService.initialize();
        }
        await loadSites();
      } catch (err) {
        console.error("Failed to initialize SharePoint service:", err);
        setError(
          err instanceof Error
            ? err.message
            : "Failed to initialize SharePoint service"
        );
      } finally {
        setIsLoading(false);
      }
    };

    initializeService();
  }, [isOpen]);

  // Focus search input when sidebar opens
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      setTimeout(() => {
        searchInputRef.current?.focus();
      }, 300);
    }
  }, [isOpen]);

  // Handle resize events
  const handleResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
    document.addEventListener(
      "mousemove",
      handleResize as unknown as EventListener
    );
    document.addEventListener(
      "mouseup",
      handleResizeEnd as unknown as EventListener
    );
  };

  const handleResize = useCallback(
    (e: globalThis.MouseEvent) => {
      if (isDragging) {
        const windowWidth = window.innerWidth;
        const newWidth = windowWidth - e.clientX;

        // Constrain within min/max width
        const constrainedWidth = Math.min(
          Math.max(newWidth, minWidth),
          maxWidth
        );
        setWidth(constrainedWidth);
      }
    },
    [isDragging, minWidth, maxWidth]
  );

  const handleResizeEnd = useCallback(() => {
    setIsDragging(false);
    document.removeEventListener(
      "mousemove",
      handleResize as unknown as EventListener
    );
    document.removeEventListener(
      "mouseup",
      handleResizeEnd as unknown as EventListener
    );
  }, [handleResize]);

  // Clean up event listeners
  useEffect(() => {
    return () => {
      document.removeEventListener(
        "mousemove",
        handleResize as unknown as EventListener
      );
      document.removeEventListener(
        "mouseup",
        handleResizeEnd as unknown as EventListener
      );
    };
  }, [handleResize, handleResizeEnd]);

  const loadSites = async () => {
    try {
      const sitesData = await sharepointService.getSites();
      setSites(sitesData);

      // Auto-select the first site if available
      if (sitesData.length > 0) {
        const firstSite = sitesData[0];
        setSelectedSite(firstSite);

        // Auto-select the first drive if available
        if (firstSite.drives && firstSite.drives.length > 0) {
          const firstDrive = firstSite.drives[0];
          setSelectedDrive(firstDrive);
          await loadFiles(firstSite.id, firstDrive.id);
        }
      }
    } catch (err) {
      console.error("Failed to load sites:", err);
      setError(
        err instanceof Error ? err.message : "Failed to load SharePoint sites"
      );
    }
  };

  const loadFiles = async (
    siteId: string,
    driveId: string,
    folderId?: string
  ) => {
    setIsLoading(true);
    setError(null);

    try {
      const filesData = await sharepointService.getFiles(
        siteId,
        driveId,
        folderId
      );
      setFiles(filesData);
    } catch (err) {
      console.error("Failed to load files:", err);
      setError(err instanceof Error ? err.message : "Failed to load files");
    } finally {
      setIsLoading(false);
    }
  };

  const handleFolderClick = async (folder: SharePointFile) => {
    if (!selectedSite || !selectedDrive) return;

    // Update breadcrumb
    const newBreadcrumb = [...breadcrumb, { id: folder.id, name: folder.name }];
    setBreadcrumb(newBreadcrumb);

    await loadFiles(selectedSite.id, selectedDrive.id, folder.id);
  };

  const handleBreadcrumbClick = async (index: number) => {
    if (!selectedSite || !selectedDrive) return;

    const newBreadcrumb = breadcrumb.slice(0, index + 1);
    setBreadcrumb(newBreadcrumb);

    const folderId = newBreadcrumb[newBreadcrumb.length - 1].id;
    await loadFiles(selectedSite.id, selectedDrive.id, folderId || undefined);
  };

  const handleRefresh = async () => {
    if (!selectedSite || !selectedDrive) return;

    setIsRefreshing(true);
    const currentFolderId = breadcrumb[breadcrumb.length - 1].id;
    await loadFiles(
      selectedSite.id,
      selectedDrive.id,
      currentFolderId || undefined
    );
    setIsRefreshing(false);
  };

  // Pre-load file for drag operations with enhanced binary download
  const preloadFileForDrag = useCallback(
    async (file: SharePointFile) => {
      if (file.isFolder || !file.downloadUrl) return;

      // Check if already cached with valid blob
      if (
        dragPreviews.has(file.id) &&
        dragPreviews.get(file.id)?.isReady &&
        dragPreviews.get(file.id)?.blob
      ) {
        console.log(`✅ Using cached file: ${file.name}`);
        return;
      }

      try {
        console.log(`🔄 Pre-loading ${file.name} for drag...`);

        // Set loading state
        setDragPreviews(
          (prev) =>
            new Map(
              prev.set(file.id, {
                file,
                blob: null,
                isReady: false,
              })
            )
        );

        // CRITICAL FIX: Use more robust download approach with multiple fallbacks
        let blob: Blob | null = null;
        let attempts = 0;
        const maxAttempts = 2;

        while (!blob && attempts < maxAttempts) {
          attempts++;
          try {
            let response;

            // First attempt: Try with fetch API and proper binary headers
            if (attempts === 1) {
              console.log(
                `🔄 Download attempt ${attempts}: Using fetch with binary headers`
              );
              response = await fetch(file.downloadUrl, {
                method: "GET",
                headers: {
                  Accept: "application/octet-stream",
                  "Cache-Control": "no-cache",
                },
                credentials: "include",
              });
            }
            // Second attempt: Try with different headers
            else {
              console.log(
                `🔄 Download attempt ${attempts}: Using alternative approach`
              );
              response = await fetch(file.downloadUrl, {
                method: "GET",
                cache: "no-store",
                credentials: "include",
              });
            }

            if (!response.ok) {
              throw new Error(`HTTP error ${response.status}`);
            }

            blob = await response.blob();

            // Validate the blob content
            if (blob.size === 0) {
              console.warn("Downloaded blob is empty, will retry");
              blob = null;
              throw new Error("Empty blob");
            }

            console.log(
              `✅ Download successful: ${blob.size} bytes, type: ${blob.type}`
            );
          } catch (err) {
            console.warn(`Download attempt ${attempts} failed:`, err);
            // Will retry if attempts < maxAttempts
          }
        }

        if (!blob) {
          throw new Error(
            `Failed to download file after ${maxAttempts} attempts`
          );
        }

        // Update with ready state
        setDragPreviews(
          (prev) =>
            new Map(
              prev.set(file.id, {
                file,
                blob,
                isReady: true,
              })
            )
        );

        console.log(
          `✅ Successfully pre-loaded ${
            file.name
          } (${sharepointService.formatFileSize(blob.size)}) - Type: ${
            blob.type || "application/octet-stream"
          }`
        );

        return blob; // Return blob for immediate use
      } catch (error) {
        console.error(`❌ Failed to pre-load ${file.name}:`, error);

        // Set error state
        setDragPreviews(
          (prev) =>
            new Map(
              prev.set(file.id, {
                file,
                blob: null,
                isReady: false,
              })
            )
        );

        return null;
      }
    },
    [dragPreviews]
  );

  const handleDragStart = useCallback(
    (e: React.DragEvent, file: SharePointFile) => {
      if (file.isFolder) {
        e.preventDefault();
        return;
      }

      if (DEBUG_DRAG_DROP) {
        console.log("==== DRAG START EVENT ====");
        console.log(`File: ${file.name}`);
        console.log(`DataTransfer type: ${e.dataTransfer.constructor.name}`);
        console.log(`Event target:`, e.currentTarget);

        // Create a status element to show what's happening
        const status = document.createElement("div");
        status.id = "drag-status-indicator";
        status.style.position = "fixed";
        status.style.bottom = "10px";
        status.style.right = "10px";
        status.style.backgroundColor = "rgba(0,0,0,0.8)";
        status.style.color = "white";
        status.style.padding = "8px 12px";
        status.style.borderRadius = "4px";
        status.style.zIndex = "9999";
        status.style.fontFamily = "monospace";
        status.style.fontSize = "12px";
        status.textContent = `Dragging: ${file.name}`;
        document.body.appendChild(status);

        // Remove after 5 seconds
        setTimeout(() => {
          if (document.getElementById("drag-status-indicator")) {
            document.body.removeChild(status);
          }
        }, 5000);
      }

      // Get cached file data
      const cachedData = dragPreviews.get(file.id);

      if (cachedData?.isReady && cachedData.blob) {
        try {
          // SIMPLIFIED - FOCUS ON BASIC FUNCTIONALITY FIRST
          const mimeType = sharepointService.getMimeType(file.name);
          console.log(`File type: ${mimeType}`);

          // Create File object
          const fileObject = new window.File([cachedData.blob], file.name, {
            type: mimeType,
          });

          // Clear data first
          if (e.dataTransfer.items && e.dataTransfer.items.clear) {
            e.dataTransfer.items.clear();
          }

          // Set effect allowed
          e.dataTransfer.effectAllowed = "copy";

          // Add the file - this is the core functionality
          if (
            e.dataTransfer.items &&
            typeof e.dataTransfer.items.add === "function"
          ) {
            e.dataTransfer.items.add(fileObject);
            console.log(`Added file: ${file.name}`);
          }

          // Also provide the file as a download URL (backup method)
          if (file.downloadUrl) {
            e.dataTransfer.setData("text/uri-list", file.downloadUrl);
            e.dataTransfer.setData(
              "DownloadURL",
              `${mimeType}:${file.name}:${file.downloadUrl}`
            );
          }

          // Simple text fallback
          e.dataTransfer.setData("text/plain", file.name);

          console.log(`Drag started for: ${file.name}`);
        } catch (error) {
          console.error(`Error in drag:`, error);

          // Simple fallback with download URL
          if (file.downloadUrl) {
            e.dataTransfer.setData("text/uri-list", file.downloadUrl);
            e.dataTransfer.setData(
              "DownloadURL",
              `application/octet-stream:${file.name}:${file.downloadUrl}`
            );
            e.dataTransfer.setData("text/plain", file.name);
          }
        }
      } else {
        // SIMPLIFIED: Just use the file URL for drag
        console.log(`No cached data for ${file.name}, using URL approach`);

        // Start with basic text
        e.dataTransfer.setData("text/plain", file.name);

        // Use download URL if available
        if (file.downloadUrl) {
          const mimeType = sharepointService.getMimeType(file.name);
          e.dataTransfer.setData("text/uri-list", file.downloadUrl);
          e.dataTransfer.setData(
            "DownloadURL",
            `${mimeType}:${file.name}:${file.downloadUrl}`
          );

          // Start preloading for next time
          setTimeout(() => {
            preloadFileForDrag(file);
          }, 100);
        }
      }

      e.dataTransfer.effectAllowed = "copy";
    },
    [dragPreviews, preloadFileForDrag]
  );

  const handleDragEnd = useCallback(
    (e: React.DragEvent, file: SharePointFile) => {
      if (DEBUG_DRAG_DROP) {
        console.log("==== DRAG END EVENT ====");
        console.log(`File: ${file.name}`);
        console.log(`Drop effect: ${e.dataTransfer.dropEffect}`);
        console.log(`Event target:`, e.currentTarget);

        // Remove the status indicator if it exists
        const indicator = document.getElementById("drag-status-indicator");
        if (indicator && indicator.parentNode) {
          indicator.parentNode.removeChild(indicator);
        }

        // Create a new status for the drag end
        const status = document.createElement("div");
        status.id = "drag-end-indicator";
        status.style.position = "fixed";
        status.style.bottom = "10px";
        status.style.right = "10px";
        status.style.backgroundColor =
          e.dataTransfer.dropEffect === "none"
            ? "rgba(255,0,0,0.8)"
            : "rgba(0,128,0,0.8)";
        status.style.color = "white";
        status.style.padding = "8px 12px";
        status.style.borderRadius = "4px";
        status.style.zIndex = "9999";
        status.style.fontFamily = "monospace";
        status.style.fontSize = "12px";
        status.textContent = `Drop: ${file.name} (${e.dataTransfer.dropEffect})`;
        document.body.appendChild(status);

        // Remove after 5 seconds
        setTimeout(() => {
          if (document.getElementById("drag-end-indicator")) {
            document.body.removeChild(status);
          }
        }, 5000);
      }

      if (
        e.dataTransfer.dropEffect === "copy" ||
        e.dataTransfer.dropEffect === "move"
      ) {
        console.log(`✅ File ${file.name} dropped successfully!`);

        // Show success indicator
        if (sidebarRef.current) {
          const successIndicator = document.createElement("div");
          successIndicator.textContent = `✓ ${file.name} dropped`;
          successIndicator.style.position = "absolute";
          successIndicator.style.bottom = "60px";
          successIndicator.style.left = "50%";
          successIndicator.style.transform = "translateX(-50%)";
          successIndicator.style.background = "#10B981";
          successIndicator.style.color = "white";
          successIndicator.style.padding = "8px 12px";
          successIndicator.style.borderRadius = "4px";
          successIndicator.style.fontSize = "14px";
          successIndicator.style.zIndex = "100";
          successIndicator.style.boxShadow = "0 2px 5px rgba(0,0,0,0.2)";

          sidebarRef.current.appendChild(successIndicator);

          setTimeout(() => {
            if (
              sidebarRef.current &&
              sidebarRef.current.contains(successIndicator)
            ) {
              successIndicator.style.opacity = "0";
              successIndicator.style.transition = "opacity 0.5s";
              setTimeout(() => {
                if (
                  sidebarRef.current &&
                  sidebarRef.current.contains(successIndicator)
                ) {
                  sidebarRef.current.removeChild(successIndicator);
                }
              }, 500);
            }
          }, 2000);
        }
      }
    },
    []
  );

  const filteredFiles = files.filter((file) =>
    file.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const renderFileItem = (file: SharePointFile) => {
    const dragData = dragPreviews.get(file.id);
    const isPreloading = dragData && !dragData.isReady;
    const isReady = dragData?.isReady ?? false;
    const isDownloading = downloadingFiles.has(file.id);

    return (
      <div
        key={file.id}
        className={cn(
          "group flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-all duration-200 cursor-pointer border border-transparent hover:border-gray-200 dark:hover:border-gray-700",
          file.isFolder && "hover:bg-blue-50 dark:hover:bg-blue-900/20",
          !file.isFolder &&
            "cursor-grab hover:shadow-md hover:border-blue-300 dark:hover:border-blue-700",
          !file.isFolder && isReady && "bg-blue-50/30 dark:bg-blue-900/10"
        )}
        draggable={!file.isFolder}
        onMouseEnter={() => {
          // Aggressively preload on hover for better drag experience
          if (!file.isFolder) {
            // Start preloading immediately with high priority
            console.log(`🔄 Mouse entered ${file.name} - starting preload`);
            preloadFileForDrag(file);

            // Add visual cue that preloading is happening
            const element = document.activeElement;
            if (element instanceof HTMLElement) {
              element.style.cursor = "grab";
            }
          }
        }}
        onDragStart={(e) => handleDragStart(e, file)}
        onDragEnd={(e) => handleDragEnd(e, file)}
        onClick={() => {
          if (file.isFolder) {
            handleFolderClick(file);
          } else {
            onFileSelect?.(file);
          }
        }}
        title={
          !file.isFolder && isReady
            ? "Drag this file to upload it to a website"
            : undefined
        }
      >
        <div className="flex-shrink-0 text-2xl">
          {sharepointService.getFileIcon(file)}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-gray-900 dark:text-gray-100 truncate">
              {file.name}
            </span>
            {file.isFolder && (
              <ChevronRight className="w-4 h-4 text-gray-400 group-hover:text-gray-600 dark:group-hover:text-gray-300 transition-colors" />
            )}
          </div>

          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {file.isFolder
                ? "Folder"
                : sharepointService.formatFileSize(file.size)}
            </span>
            <span className="text-xs text-gray-400 dark:text-gray-500">
              {sharepointService.formatDate(file.lastModified)}
            </span>
          </div>
        </div>

        {!file.isFolder && (
          <div className="flex-shrink-0 flex items-center gap-2">
            {isPreloading && (
              <Loader2 className="w-4 h-4 animate-spin text-orange-500" />
            )}
            {isReady && (
              <Badge
                variant="secondary"
                className="text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300"
              >
                Ready
              </Badge>
            )}

            {/* View Button */}
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                if (!file.downloadUrl) return;
                setViewerFile({ name: file.name, url: file.downloadUrl });
                setViewerOpen(true);
              }}
              className="h-8 w-8 p-0 transition-all hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300 hover:scale-110"
              title="View file"
            >
              <Eye className="w-4 h-4" />
            </Button>

            {/* Download Button - Always visible for files */}
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                if (!file.downloadUrl) return;

                // Set downloading state
                setDownloadingFiles((prev) => new Set(prev.add(file.id)));

                // Route through Electron so it hits will-download and our choice dialog/progress
                if (window.electronAPI?.downloads?.startByUrl) {
                  window.electronAPI.downloads.startByUrl(
                    file.downloadUrl,
                    file.name
                  );
                } else {
                  // Fallback
                  window.location.href = file.downloadUrl;
                }

                // Reset download state after a short delay
                setTimeout(() => {
                  setDownloadingFiles((prev) => {
                    const next = new Set(prev);
                    next.delete(file.id);
                    return next;
                  });
                }, 2000);
              }}
              className={`h-8 w-8 p-0 transition-all hover:bg-blue-100 dark:hover:bg-blue-900 text-blue-600 dark:text-blue-400 hover:scale-110 ${
                isDownloading ? "animate-pulse" : ""
              }`}
              title="Download file"
              disabled={isDownloading}
            >
              {isDownloading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <MoreVertical className="w-4 h-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={(e) => {
                    e.stopPropagation();
                    if (file.webUrl) {
                      window.open(file.webUrl, "_blank");
                    }
                  }}
                >
                  <FolderOpen className="w-4 h-4 mr-2" />
                  Open in SharePoint
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        )}
      </div>
    );
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/10" onClick={onClose} />

      {/* Sidebar */}
      <div
        ref={sidebarRef}
        style={{ width: `${width}px` }}
        className={cn(
          "relative ml-auto h-full bg-white dark:bg-gray-900 shadow-2xl transform transition-all duration-300 ease-out",
          isOpen ? "translate-x-0" : "translate-x-full",
          isDragging ? "transition-none" : "",
          className
        )}
      >
        {/* File viewer modal mounted here */}
        <FileViewerModal
          open={viewerOpen}
          onOpenChange={setViewerOpen}
          filename={viewerFile?.name || ""}
          url={viewerFile?.url || ""}
        />
        {/* Resize Handle */}
        <div
          ref={resizeHandleRef}
          className={cn(
            "absolute left-0 top-0 bottom-0 w-4 cursor-ew-resize bg-transparent flex items-center justify-center z-10",
            isDragging ? "bg-blue-500/30" : "hover:bg-blue-500/20"
          )}
          onMouseDown={handleResizeStart}
          title="Drag to resize panel width"
        >
          <div
            className={cn(
              "h-16 w-1 rounded-full transition-colors",
              isDragging ? "bg-blue-500" : "bg-gray-300 dark:bg-gray-700"
            )}
          />

          {isDragging && (
            <div className="absolute top-1/2 left-6 transform -translate-y-1/2 bg-blue-500 text-white text-xs px-2 py-1 rounded shadow-md">
              {width}px
            </div>
          )}
        </div>
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 bg-gradient-to-r from-blue-600 to-blue-700 text-white">
          <div className="flex items-center gap-3">
            {showDiagnostics && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDiagnostics(false)}
                className="text-white hover:bg-white/20 mr-2"
              >
                <ArrowLeft className="w-4 h-4" />
              </Button>
            )}
            <File className="w-6 h-6" />
            <div>
              <h2 className="text-lg font-semibold">
                {showDiagnostics
                  ? "SharePoint Diagnostics"
                  : "SharePoint Files"}
              </h2>
              <p className="text-sm text-blue-100">
                {showDiagnostics
                  ? "Connection troubleshooting"
                  : selectedSite?.name || "No site selected"}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!showDiagnostics && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleRefresh}
                disabled={isRefreshing || !selectedSite || !selectedDrive}
                className="text-white hover:bg-white/20"
              >
                <RefreshCw
                  className={cn("w-4 h-4", isRefreshing && "animate-spin")}
                />
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="text-white hover:bg-white/20"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Search */}
        {!showDiagnostics && (
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <Input
                ref={searchInputRef}
                placeholder="Search files and folders..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-white dark:bg-gray-900 text-black"
              />
            </div>
          </div>
        )}

        {/* Breadcrumb */}
        {!showDiagnostics && breadcrumb.length > 1 && (
          <div className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
            <div className="flex items-center gap-1 text-sm">
              <Home
                className="w-4 h-4 text-gray-500 cursor-pointer hover:text-gray-700 dark:hover:text-gray-300"
                onClick={() => handleBreadcrumbClick(0)}
              />
              {breadcrumb.slice(1).map((item, index) => (
                <React.Fragment key={item.id || index}>
                  <ChevronRight className="w-4 h-4 text-gray-400" />
                  <span
                    className={cn(
                      "cursor-pointer hover:text-blue-600 dark:hover:text-blue-400 transition-colors",
                      index === breadcrumb.length - 2
                        ? "text-blue-600 dark:text-blue-400 font-medium"
                        : "text-gray-600 dark:text-gray-400"
                    )}
                    onClick={() => handleBreadcrumbClick(index + 1)}
                  >
                    {item.name}
                  </span>
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-auto">
          {showDiagnostics ? (
            <SharePointDiagnostics />
          ) : isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <Loader2 className="w-8 h-8 animate-spin text-blue-600 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400">
                  Loading SharePoint files...
                </p>
              </div>
            </div>
          ) : error ? (
            <div className="p-4">
              <Card className="p-6 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800">
                <div className="text-center">
                  <div className="text-red-600 dark:text-red-400 mb-2">❌</div>
                  <h3 className="text-lg font-semibold text-red-800 dark:text-red-200 mb-2">
                    Connection Error
                  </h3>
                  <p className="text-sm text-red-700 dark:text-red-300 mb-4">
                    {error}
                  </p>
                  <div className="flex flex-col gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setError(null);
                        loadSites();
                      }}
                      className="border-red-300 text-red-700 hover:bg-red-100 dark:border-red-700 dark:text-red-300 dark:hover:bg-red-900/40"
                    >
                      Try Again
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => setShowDiagnostics(true)}
                      className="bg-blue-100 text-blue-700 hover:bg-blue-200 dark:bg-blue-900/40 dark:text-blue-300"
                    >
                      Run Diagnostics
                    </Button>
                  </div>
                </div>
              </Card>
            </div>
          ) : filteredFiles.length === 0 ? (
            <div className="flex items-center justify-center h-64">
              <div className="text-center">
                <FolderOpen className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400">
                  {searchTerm
                    ? "No files match your search"
                    : "This folder is empty"}
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 space-y-2">
              {filteredFiles.map(renderFileItem)}
            </div>
          )}
        </div>

        {/* Footer */}
        {!showDiagnostics && (
          <div className="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 p-4">
            <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
              <span>{filteredFiles.length} items</span>
              <div className="flex items-center gap-4">
                <Badge
                  variant="outline"
                  className="bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300"
                >
                  Drag & Drop Ready
                </Badge>
                <span className="text-xs">
                  Hover files to preload • Drag to browser
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
