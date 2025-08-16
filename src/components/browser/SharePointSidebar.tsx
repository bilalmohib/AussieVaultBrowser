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
    document.addEventListener('mousemove', handleResize as unknown as EventListener);
    document.addEventListener('mouseup', handleResizeEnd as unknown as EventListener);
  };

  const handleResize = useCallback((e: globalThis.MouseEvent) => {
    if (isDragging) {
      const windowWidth = window.innerWidth;
      const newWidth = windowWidth - e.clientX;
      
      // Constrain within min/max width
      const constrainedWidth = Math.min(Math.max(newWidth, minWidth), maxWidth);
      setWidth(constrainedWidth);
    }
  }, [isDragging, minWidth, maxWidth]);

  const handleResizeEnd = useCallback(() => {
    setIsDragging(false);
    document.removeEventListener('mousemove', handleResize as unknown as EventListener);
    document.removeEventListener('mouseup', handleResizeEnd as unknown as EventListener);
  }, [handleResize]);

  // Clean up event listeners
  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleResize as unknown as EventListener);
      document.removeEventListener('mouseup', handleResizeEnd as unknown as EventListener);
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

  // Pre-load file for drag operations
  const preloadFileForDrag = useCallback(
    async (file: SharePointFile) => {
      if (file.isFolder || !file.downloadUrl) return;

      // Check if already cached
      if (dragPreviews.has(file.id) && dragPreviews.get(file.id)?.isReady) {
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

        // Force download as binary blob using fetch API with proper headers
        const response = await fetch(file.downloadUrl, {
          method: 'GET',
          headers: {
            'Accept': 'application/octet-stream',
          },
          credentials: 'include',
        });
        
        if (!response.ok) {
          throw new Error(`Failed to download file: ${response.status} ${response.statusText}`);
        }
        
        const blob = await response.blob();

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
          `✅ Pre-loaded ${file.name} (${sharepointService.formatFileSize(
            blob.size
          )}) - Type: ${blob.type}`
        );
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

      console.log(`🚀 Starting drag for: ${file.name}`);

      // Get cached file data
      const cachedData = dragPreviews.get(file.id);

      if (cachedData?.isReady && cachedData.blob) {
        try {
          // Determine the correct MIME type
          const fileExtension = file.name.split('.').pop()?.toLowerCase();
          let mimeType = cachedData.blob.type || "application/octet-stream";
          
          // If blob doesn't have a type, try to determine based on extension
          if (mimeType === "application/octet-stream" || mimeType === "") {
            if (fileExtension === "pdf") mimeType = "application/pdf";
            else if (["png", "jpg", "jpeg", "gif"].includes(fileExtension || "")) {
              mimeType = `image/${fileExtension}`;
            }
            else if (["docx", "doc"].includes(fileExtension || "")) {
              mimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
            }
            // Add more mime types as needed
          }
          
          console.log(`📎 File MIME type: ${mimeType}`);

          // Create File object from cached blob with proper type
          const fileObject = new window.File(
            [cachedData.blob],
            file.name,
            { type: mimeType }
          );

          // Clear any existing data in the dataTransfer
          if (e.dataTransfer.items && e.dataTransfer.items.clear) {
            e.dataTransfer.items.clear();
          }

          // Method 1: Use DataTransfer.items.add
          if (
            e.dataTransfer.items &&
            typeof e.dataTransfer.items.add === "function"
          ) {
            e.dataTransfer.items.add(fileObject);
            console.log(`✅ File added to drag via items.add(): ${file.name}`);
          } 
          // Method 2: Set as a DataTransfer file
          else if (e.dataTransfer.files && "length" in e.dataTransfer.files) {
            // This is a hack using the internal __proto__ to modify files collection
            // It's not ideal but sometimes necessary for browser compatibility
            try {
              const dt = e.dataTransfer;
              const fileList = dt.files;
              const dataTransferItemsList = fileList as unknown as DataTransferItemList;
              if (dataTransferItemsList) {
                Object.defineProperty(dataTransferItemsList, '0', {
                  value: fileObject,
                  writable: false
                });
                Object.defineProperty(dataTransferItemsList, 'length', {
                  value: 1,
                  writable: false
                });
                console.log(`✅ File added to drag via files collection: ${file.name}`);
              }
            } catch (err) {
              console.error("Failed to set file in dataTransfer.files", err);
            }
          }
          
          // Backup method: Use DownloadURL format which some sites recognize
          e.dataTransfer.setData(
            "DownloadURL",
            `${mimeType}:${file.name}:${file.downloadUrl || ''}`
          );

          // Add URL alternatives (helpful for some sites)
          e.dataTransfer.setData("text/uri-list", file.downloadUrl || '');
          e.dataTransfer.setData("text/plain", file.name);
          
          e.dataTransfer.effectAllowed = "copy";
          
          console.log(`✅ Enhanced drag support configured for: ${file.name}`);
        } catch (error) {
          console.error(`❌ Error adding file to drag:`, error);
          // Fallback to URL-based drag
          e.dataTransfer.setData("text/plain", file.name);
          if (file.downloadUrl) {
            e.dataTransfer.setData("text/uri-list", file.downloadUrl);
            e.dataTransfer.setData(
              "DownloadURL",
              `application/octet-stream:${file.name}:${file.downloadUrl}`
            );
          }
        }
      } else {
        console.log(`⚠️ No preloaded data available for ${file.name}, using URL fallback`);
        // Fallback to URL-based drag
        e.dataTransfer.setData("text/plain", file.name);
        if (file.downloadUrl) {
          e.dataTransfer.setData("text/uri-list", file.downloadUrl);
          e.dataTransfer.setData(
            "DownloadURL",
            `application/octet-stream:${file.name}:${file.downloadUrl}`
          );
        }
        
        // If we don't have the blob yet, try to preload it now
        if (file.downloadUrl && !dragPreviews.has(file.id)) {
          preloadFileForDrag(file);
        }
      }

      e.dataTransfer.effectAllowed = "copy";
    },
    [dragPreviews, preloadFileForDrag]
  );

  const handleDragEnd = useCallback(
    (e: React.DragEvent, file: SharePointFile) => {
      console.log(
        `🏁 Drag ended for: ${file.name}, dropEffect: ${e.dataTransfer.dropEffect}`
      );

      if (
        e.dataTransfer.dropEffect === "copy" ||
        e.dataTransfer.dropEffect === "move"
      ) {
        console.log(`✅ File ${file.name} dropped successfully!`);
        
        // Show success indicator
        if (sidebarRef.current) {
          const successIndicator = document.createElement('div');
          successIndicator.textContent = `✓ ${file.name} dropped`;
          successIndicator.style.position = 'absolute';
          successIndicator.style.bottom = '60px';
          successIndicator.style.left = '50%';
          successIndicator.style.transform = 'translateX(-50%)';
          successIndicator.style.background = '#10B981';
          successIndicator.style.color = 'white';
          successIndicator.style.padding = '8px 12px';
          successIndicator.style.borderRadius = '4px';
          successIndicator.style.fontSize = '14px';
          successIndicator.style.zIndex = '100';
          successIndicator.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
          
          sidebarRef.current.appendChild(successIndicator);
          
          setTimeout(() => {
            if (sidebarRef.current && sidebarRef.current.contains(successIndicator)) {
              successIndicator.style.opacity = '0';
              successIndicator.style.transition = 'opacity 0.5s';
              setTimeout(() => {
                if (sidebarRef.current && sidebarRef.current.contains(successIndicator)) {
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
          !file.isFolder && isReady && "hover:shadow-md hover:border-blue-300 dark:hover:border-blue-700"
        )}
        draggable={!file.isFolder}
        onMouseEnter={() => !file.isFolder && preloadFileForDrag(file)}
        onDragStart={(e) => handleDragStart(e, file)}
        onDragEnd={(e) => handleDragEnd(e, file)}
        onClick={() => {
          if (file.isFolder) {
            handleFolderClick(file);
          } else {
            onFileSelect?.(file);
          }
        }}
        title={!file.isFolder && isReady ? "Drag this file to upload it to a website" : undefined}
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

            {/* Download Button - Always visible for files */}
            <Button
              variant="ghost"
              size="sm"
              onClick={async (e) => {
                e.stopPropagation();
                console.log(`🚀 Download button clicked for: ${file.name}`);
                console.log(`📥 Download URL: ${file.downloadUrl}`);

                if (!file.downloadUrl) {
                  console.error(
                    "❌ No download URL available for file:",
                    file.name
                  );
                  alert("Download URL not available for this file");
                  return;
                }

                // Set downloading state
                setDownloadingFiles((prev) => new Set(prev.add(file.id)));

                try {
                  // Method 1: Try direct download with anchor element
                  console.log("🔗 Attempting direct download...");
                  const link = document.createElement("a");
                  link.href = file.downloadUrl;
                  link.download = file.name;
                  link.style.display = "none";
                  link.setAttribute("target", "_blank");

                  document.body.appendChild(link);
                  link.click();
                  document.body.removeChild(link);

                  console.log(`✅ Download initiated for: ${file.name}`);

                  // Remove downloading state after a delay
                  setTimeout(() => {
                    setDownloadingFiles((prev) => {
                      const next = new Set(prev);
                      next.delete(file.id);
                      return next;
                    });
                  }, 3000);
                } catch (error) {
                  console.error("❌ Download failed, trying fallback:", error);

                  // Remove downloading state
                  setDownloadingFiles((prev) => {
                    const next = new Set(prev);
                    next.delete(file.id);
                    return next;
                  });

                  // Fallback: Open in new tab
                  try {
                    window.open(file.downloadUrl, "_blank");
                    console.log("🔄 Opened download URL in new tab");
                  } catch (fallbackError) {
                    console.error("❌ Fallback also failed:", fallbackError);
                    alert(
                      `Failed to download ${file.name}. Please try opening the file in SharePoint.`
                    );
                  }
                }
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
      <div
        className="absolute inset-0 bg-black/10"
        onClick={onClose}
      />

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
          <div className={cn(
            "h-16 w-1 rounded-full transition-colors", 
            isDragging ? "bg-blue-500" : "bg-gray-300 dark:bg-gray-700"
          )}/>
          
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
