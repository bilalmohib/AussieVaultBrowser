import React, { useState, useEffect, useCallback } from "react";
import { DownloadChoiceDialog } from "./DownloadChoiceDialog";
import { DownloadProgress } from "./DownloadProgress";
import { toast } from "sonner";

interface DownloadChoiceData {
  id: string;
  filename: string;
  url: string;
  totalBytes: number;
  sessionName: string;
}

interface DownloadProgressData {
  id: string;
  filename: string;
  state: string;
  receivedBytes?: number;
  totalBytes?: number;
  speed?: number;
  type: "local" | "meta";
  phase?: "downloading" | "uploading";
}

interface DownloadCompletedData {
  id: string;
  filename: string;
  state: string;
  filePath?: string | null;
  type: "local" | "meta";
  metaFileId?: string;
  error?: string;
}

export const DownloadManager: React.FC = () => {
  const [pendingChoice, setPendingChoice] = useState<DownloadChoiceData | null>(
    null
  );
  const [activeDownloads, setActiveDownloads] = useState<
    Map<string, DownloadProgressData>
  >(new Map());
  const [showChoiceDialog, setShowChoiceDialog] = useState(false);

  // Handle download choice required event
  const handleDownloadChoiceRequired = useCallback(
    (_event: any, data: DownloadChoiceData) => {
      console.log("📥 Download choice required for:", data.filename);
      setPendingChoice(data);
      setShowChoiceDialog(true);
    },
    []
  );

  // Handle download choice processed event
  const handleDownloadChoiceProcessed = useCallback(
    (_event: any, data: any) => {
      console.log(
        "✅ Download choice processed:",
        data.choice,
        "for",
        data.filename
      );
      toast.info(
        `Download method selected: ${
          data.choice === "local" ? "Local Storage" : "Meta Cloud"
        }`,
        {
          description: data.filename,
        }
      );
    },
    []
  );

  // Handle download started event
  const handleDownloadStarted = useCallback(
    (_event: any, data: DownloadProgressData) => {
      console.log("🚀 Download started:", data.filename, `(${data.type})`);
      setActiveDownloads((prev) => new Map(prev.set(data.id, data)));

      const storageType = data.type === "local" ? "locally" : "to Meta storage";
      toast.info(`Download started ${storageType}`, {
        description: data.filename,
      });
    },
    []
  );

  // Handle download progress event
  const handleDownloadProgress = useCallback(
    (_event: any, data: DownloadProgressData) => {
      setActiveDownloads((prev) => {
        const updated = new Map(prev);
        updated.set(data.id, data);
        return updated;
      });
    },
    []
  );

  // Handle download completed event
  const handleDownloadCompleted = useCallback(
    (_event: any, data: DownloadCompletedData) => {
      console.log("✅ Download completed:", data.filename, `(${data.type})`);

      // Remove from active downloads
      setActiveDownloads((prev) => {
        const updated = new Map(prev);
        updated.delete(data.id);
        return updated;
      });

      // Show completion notification
      if (data.state === "completed") {
        if (data.type === "local") {
          toast.success("Download completed locally", {
            description: data.filename,
            action:
              data.filePath && window.electronAPI?.shell?.showItemInFolder
                ? {
                    label: "Open Folder",
                    onClick: () =>
                      window.electronAPI?.shell?.showItemInFolder(
                        data.filePath!
                      ),
                  }
                : undefined,
          });
        } else if (data.type === "meta") {
          toast.success("Uploaded to Meta storage", {
            description: data.filename,
            action: {
              label: "View in Meta",
              onClick: () => {
                // TODO: Open Meta storage in browser
                console.log("Opening Meta storage for file:", data.metaFileId);
              },
            },
          });
        }
      } else {
        toast.error("Download failed", {
          description: data.error || `Failed to download ${data.filename}`,
        });
      }
    },
    []
  );

  // Handle download blocked event
  const handleDownloadBlocked = useCallback((_event: any, data: any) => {
    console.log("🚫 Download blocked:", data.filename);
    toast.error("Download blocked by security policy", {
      description: data.filename,
    });
  }, []);

  // Set up event listeners with retry mechanism
  useEffect(() => {
    let timeoutId: NodeJS.Timeout;
    let retryCount = 0;
    const maxRetries = 10;

    const setupEventListeners = () => {
      const electronAPI = window.electronAPI;

      console.log(
        "🔍 Debug: electronAPI availability (attempt",
        retryCount + 1,
        "):",
        {
          electronAPI: !!electronAPI,
          on: !!electronAPI?.on,
          removeListener: !!electronAPI?.removeListener,
          downloads: !!electronAPI?.downloads,
          metaStorage: !!electronAPI?.metaStorage,
          keys: electronAPI ? Object.keys(electronAPI) : [],
        }
      );

      if (!electronAPI?.on || !electronAPI?.removeListener) {
        if (retryCount < maxRetries) {
          retryCount++;
          console.log(
            `⏰ Retrying electronAPI setup in 500ms (${retryCount}/${maxRetries})`
          );
          timeoutId = setTimeout(setupEventListeners, 500);
          return;
        } else {
          console.warn(
            "❌ Electron API not available for download events after",
            maxRetries,
            "attempts. Available methods:",
            electronAPI ? Object.keys(electronAPI) : "electronAPI is undefined"
          );
          return;
        }
      }

      console.log("✅ Setting up download event listeners");
      setupListeners(electronAPI);
    };

    const setupListeners = (electronAPI: typeof window.electronAPI) => {
      if (!electronAPI?.on || !electronAPI?.removeListener) return;

      electronAPI.on("download-choice-required", handleDownloadChoiceRequired);
      electronAPI.on(
        "download-choice-processed",
        handleDownloadChoiceProcessed
      );
      electronAPI.on("download-started", handleDownloadStarted);
      electronAPI.on("download-progress", handleDownloadProgress);
      electronAPI.on("download-completed", handleDownloadCompleted);
      electronAPI.on("download-blocked", handleDownloadBlocked);
    };

    setupEventListeners();

    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }

      const electronAPI = window.electronAPI;
      if (electronAPI?.removeListener) {
        electronAPI.removeListener(
          "download-choice-required",
          handleDownloadChoiceRequired
        );
        electronAPI.removeListener(
          "download-choice-processed",
          handleDownloadChoiceProcessed
        );
        electronAPI.removeListener("download-started", handleDownloadStarted);
        electronAPI.removeListener("download-progress", handleDownloadProgress);
        electronAPI.removeListener(
          "download-completed",
          handleDownloadCompleted
        );
        electronAPI.removeListener("download-blocked", handleDownloadBlocked);
      }
    };
  }, [
    handleDownloadChoiceRequired,
    handleDownloadChoiceProcessed,
    handleDownloadStarted,
    handleDownloadProgress,
    handleDownloadCompleted,
    handleDownloadBlocked,
  ]);

  // Handle user choice selection
  const handleChoiceSelected = async (
    downloadId: string,
    choice: "local" | "meta"
  ) => {
    try {
      if (!window.electronAPI?.downloads) {
        throw new Error("Electron API not available");
      }

      if (choice === "local") {
        await window.electronAPI.downloads.chooseLocal(downloadId);
      } else {
        await window.electronAPI.downloads.chooseMeta(downloadId);
      }
    } catch (error) {
      console.error("Failed to process download choice:", error);
      toast.error("Failed to process download choice");
    }
  };

  // Close choice dialog
  const handleCloseChoiceDialog = () => {
    setShowChoiceDialog(false);
    setPendingChoice(null);
  };

  return (
    <>
      {/* Download Choice Dialog */}
      <DownloadChoiceDialog
        downloadData={pendingChoice}
        isOpen={showChoiceDialog}
        onClose={handleCloseChoiceDialog}
        onChoiceSelected={handleChoiceSelected}
      />

      {/* Active Downloads Progress */}
      {Array.from(activeDownloads.values()).map((download) => (
        <DownloadProgress
          key={download.id}
          download={download}
          onClose={(id) => {
            setActiveDownloads((prev) => {
              const updated = new Map(prev);
              updated.delete(id);
              return updated;
            });
          }}
        />
      ))}
    </>
  );
};
