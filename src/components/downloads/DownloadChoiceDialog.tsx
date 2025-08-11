import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Download, Cloud, HardDrive, FileText, Settings } from "lucide-react";

interface DownloadChoiceData {
  id: string;
  filename: string;
  url: string;
  totalBytes: number;
  sessionName: string;
}

interface MetaStorageStatus {
  connected: boolean;
  accountName: string | null;
  storageQuota: {
    used: number;
    total: number;
  } | null;
}

interface DownloadChoiceDialogProps {
  downloadData: DownloadChoiceData | null;
  isOpen: boolean;
  onClose: () => void;
  onChoiceSelected: (downloadId: string, choice: "local" | "meta") => void;
}

export const DownloadChoiceDialog: React.FC<DownloadChoiceDialogProps> = ({
  downloadData,
  isOpen,
  onClose,
  onChoiceSelected,
}) => {
  const [metaStorageStatus, setMetaStorageStatus] =
    useState<MetaStorageStatus | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [showMetaAuth, setShowMetaAuth] = useState(false);

  useEffect(() => {
    if (isOpen && downloadData) {
      checkMetaStorageStatus();
    }
  }, [isOpen, downloadData]);

  const checkMetaStorageStatus = async () => {
    try {
      const status = await window.electronAPI?.metaStorage?.getStatus?.();
      if (status) {
        setMetaStorageStatus(status as MetaStorageStatus);
      } else {
        setMetaStorageStatus({
          connected: false,
          accountName: null,
          storageQuota: null,
        });
      }
    } catch (error) {
      console.error("Failed to check Meta storage status:", error);
      setMetaStorageStatus({
        connected: false,
        accountName: null,
        storageQuota: null,
      });
    }
  };

  const handleConnectMeta = async () => {
    setConnecting(true);
    try {
      // In a real implementation, you would redirect to Meta OAuth
      // For now, simulate connection with a fake token
      const fakeToken = "simulated_meta_access_token";
      const result = await window.electronAPI?.metaStorage?.connect?.(
        fakeToken
      );

      if (result && (result as any).success) {
        setMetaStorageStatus({
          connected: true,
          accountName: (result as any).accountName ?? null,
          storageQuota: (result as any).storageQuota ?? null,
        });
        setShowMetaAuth(false);
      }
    } catch (error) {
      console.error("Failed to connect to Meta storage:", error);
    } finally {
      setConnecting(false);
    }
  };

  const handleLocalDownload = () => {
    if (downloadData) {
      onChoiceSelected(downloadData.id, "local");
      onClose();
    }
  };

  const handleMetaUpload = () => {
    if (downloadData) {
      if (metaStorageStatus?.connected) {
        onChoiceSelected(downloadData.id, "meta");
        onClose();
      } else {
        setShowMetaAuth(true);
      }
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  if (!downloadData) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-[780px] w-[90vw] p-0 overflow-hidden overflow-x-hidden rounded-2xl shadow-2xl border bg-white">
        {/* Header */}
        <div className="px-6 py-5 border-b bg-white/85 backdrop-blur-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2.5 text-[15px] font-semibold tracking-tight">
              <Download className="h-5 w-5 text-blue-600 shrink-0" />
              <span>Choose Download Method</span>
            </DialogTitle>
            <DialogDescription className="text-slate-600 text-sm">
              Where would you like to save this file?
            </DialogDescription>
          </DialogHeader>
        </div>

        <div className="px-6 py-5">
          <div className="space-y-5 w-full">
            {/* File Information */}
            <div className="rounded-lg border bg-white/80 backdrop-blur px-4 py-3 flex flex-col gap-1 shadow-sm overflow-hidden">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-800 min-w-0">
                <FileText className="h-4 w-4 text-slate-500 shrink-0" />
                <span className="truncate" title={downloadData.filename}>
                  {downloadData.filename}
                </span>
                <span className="ml-auto pl-2 text-[11px] font-normal text-slate-500 whitespace-nowrap shrink-0">
                  {formatFileSize(downloadData.totalBytes)}
                </span>
              </div>
              <div
                className="text-[11px] leading-snug text-slate-500 overflow-hidden text-ellipsis break-all"
                title={downloadData.url}
              >
                From: {downloadData.url}
              </div>
            </div>

            {!showMetaAuth ? (
              <div className="grid gap-4 sm:grid-cols-2">
                {/* Local Download Option */}
                <div
                  role="button"
                  tabIndex={0}
                  onClick={handleLocalDownload}
                  onKeyDown={(e) => e.key === "Enter" && handleLocalDownload()}
                  className="group relative border rounded-xl p-4 bg-white flex flex-col min-h-[210px] cursor-pointer outline-none transition-all hover:shadow-sm focus-visible:ring-2 focus-visible:ring-blue-500/50 overflow-hidden"
                >
                  <div className="flex items-start gap-3">
                    <div className="h-9 w-9 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center ring-1 ring-blue-100 shrink-0">
                      <HardDrive className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-slate-800 mb-0.5 text-sm">
                        Local Download
                      </h3>
                      <p className="text-[11px] text-slate-600 leading-snug">
                        Save directly to this computer.
                      </p>
                    </div>
                  </div>
                  <ul className="mt-3 space-y-1 text-[11px] text-slate-600">
                    <li className="flex items-start gap-1.5">
                      <span className="mt-1 h-1.5 w-1.5 rounded-full bg-blue-500/70" />
                      Instant access
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="mt-1 h-1.5 w-1.5 rounded-full bg-blue-500/70" />
                      Works offline
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="mt-1 h-1.5 w-1.5 rounded-full bg-blue-500/70" />
                      Uses local storage
                    </li>
                  </ul>
                  <Button
                    onClick={handleLocalDownload}
                    className="mt-auto w-full bg-blue-600 hover:bg-blue-700 text-white shadow-sm text-sm h-9"
                    variant="default"
                  >
                    <HardDrive className="h-4 w-4 mr-2" />
                    Download Locally
                  </Button>
                  <div className="absolute inset-0 rounded-xl ring-2 ring-blue-500/0 group-hover:ring-blue-500/30 group-focus-visible:ring-blue-500/50 pointer-events-none transition" />
                </div>

                {/* Meta Storage Option */}
                <div
                  role="button"
                  tabIndex={0}
                  onClick={handleMetaUpload}
                  onKeyDown={(e) => e.key === "Enter" && handleMetaUpload()}
                  className="group relative border rounded-xl p-4 bg-white flex flex-col min-h-[210px] cursor-pointer outline-none transition-all hover:shadow-sm focus-visible:ring-2 focus-visible:ring-emerald-500/50 overflow-hidden"
                >
                  <div className="flex items-start gap-3">
                    <div className="h-9 w-9 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center ring-1 ring-emerald-100 shrink-0">
                      <Cloud className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-slate-800 mb-0.5 text-sm">
                        Meta Storage
                      </h3>
                      <p className="text-[11px] text-slate-600 leading-snug">
                        Sync to your Meta cloud.
                      </p>
                    </div>
                  </div>

                  {metaStorageStatus?.connected ? (
                    <div className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 text-[11px] font-medium text-emerald-700">
                        {metaStorageStatus.accountName}
                      </div>
                      {metaStorageStatus.storageQuota && (
                        <div className="text-[10px] text-slate-500 font-medium">
                          {formatFileSize(metaStorageStatus.storageQuota.used)}{" "}
                          /{" "}
                          {formatFileSize(metaStorageStatus.storageQuota.total)}{" "}
                          used
                        </div>
                      )}
                      <ul className="space-y-1 text-[11px] text-slate-600">
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/70" />
                          Access anywhere
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/70" />
                          Automatic sync
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/70" />
                          Share with others
                        </li>
                      </ul>
                    </div>
                  ) : (
                    <div className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 text-[11px] font-medium text-amber-600">
                        Not connected
                      </div>
                      <ul className="space-y-1 text-[11px] text-slate-600">
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/60" />
                          Access anywhere
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/60" />
                          Automatic sync
                        </li>
                        <li className="flex items-start gap-1.5">
                          <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500/60" />
                          Share with others
                        </li>
                      </ul>
                    </div>
                  )}

                  {metaStorageStatus?.connected ? (
                    <Button
                      onClick={handleMetaUpload}
                      className="mt-auto w-full bg-emerald-600 hover:bg-emerald-700 text-white shadow-sm text-sm h-9"
                      variant="default"
                    >
                      <Cloud className="h-4 w-4 mr-2" /> Upload to Meta
                    </Button>
                  ) : (
                    <Button
                      onClick={handleMetaUpload}
                      className="mt-auto w-full border-emerald-300 text-emerald-700 hover:bg-emerald-50 shadow-sm text-sm h-9"
                      variant="outline"
                    >
                      <Settings className="h-4 w-4 mr-2" /> Connect & Upload
                    </Button>
                  )}
                  <div className="absolute inset-0 rounded-xl ring-2 ring-emerald-500/0 group-hover:ring-emerald-500/30 group-focus-visible:ring-emerald-500/50 pointer-events-none transition" />
                </div>
              </div>
            ) : (
              /* Meta Authentication Flow */
              <div className="space-y-4">
                <div className="text-center">
                  <Cloud className="h-12 w-12 text-emerald-600 mx-auto mb-4" />
                  <h3 className="text-lg font-medium mb-2">
                    Connect to Meta Storage
                  </h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Connect your Meta account to save files to Meta cloud
                    storage
                  </p>
                </div>

                <div className="bg-muted p-4 rounded-lg">
                  <h4 className="font-medium mb-2">
                    Benefits of Meta Storage:
                  </h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li>• Access files from any device</li>
                    <li>• Automatic synchronization</li>
                    <li>• Share files with friends and colleagues</li>
                    <li>• Integrated with Meta ecosystem</li>
                    <li>• Secure cloud storage</li>
                  </ul>
                </div>

                <div className="flex gap-2">
                  <Button
                    onClick={() => setShowMetaAuth(false)}
                    variant="outline"
                    className="flex-1"
                  >
                    Back
                  </Button>
                  <Button
                    onClick={handleConnectMeta}
                    disabled={connecting}
                    className="flex-1"
                  >
                    {connecting ? "Connecting..." : "Connect Meta Account"}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>

        <DialogFooter className="flex items-center justify-between px-6 py-4 border-t bg-white/85 text-[11px]">
          <div className="flex items-center gap-2 text-slate-500 overflow-hidden">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-blue-500"></span>
            <span className="truncate">
              Auto-download locally in 30 seconds
            </span>
          </div>
          <Button
            size="sm"
            variant="ghost"
            onClick={onClose}
            className="text-slate-600 hover:text-slate-900 h-8 px-3"
          >
            Cancel
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};
