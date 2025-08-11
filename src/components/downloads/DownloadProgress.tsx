import React from "react";
import { Progress } from "../ui/progress";
import { Badge } from "../ui/badge";
import { Card, CardContent } from "../ui/card";
import { Cloud, HardDrive, FileText, Upload } from "lucide-react";

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

interface DownloadProgressProps {
  download: DownloadProgressData;
}

export const DownloadProgress: React.FC<DownloadProgressProps> = ({
  download,
}) => {
  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatSpeed = (bytesPerSecond: number) => {
    return `${formatFileSize(bytesPerSecond)}/s`;
  };

  const getProgressPercent = () => {
    if (!download.receivedBytes || !download.totalBytes) return 0;
    return (download.receivedBytes / download.totalBytes) * 100;
  };

  const getStatusText = () => {
    if (download.type === "meta") {
      if (download.phase === "downloading") {
        return "Downloading for Meta upload...";
      } else if (download.phase === "uploading") {
        return "Uploading to Meta storage...";
      }
    }
    return download.state === "downloading" ? "Downloading..." : download.state;
  };

  const getIcon = () => {
    if (download.type === "meta") {
      if (download.phase === "uploading") {
        return <Upload className="h-4 w-4" />;
      }
      return <Cloud className="h-4 w-4" />;
    }
    return <HardDrive className="h-4 w-4" />;
  };

  const getTypeColor = () => {
    return download.type === "meta" ? "bg-green-500" : "bg-blue-500";
  };

  return (
    <Card className="fixed bottom-4 right-4 w-80 z-50 shadow-lg">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-full ${getTypeColor()} text-white`}>
            {getIcon()}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <FileText className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium truncate">
                {download.filename}
              </span>
            </div>

            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline" className="text-xs">
                {download.type === "meta" ? "Meta Storage" : "Local"}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {getStatusText()}
              </span>
            </div>

            {download.receivedBytes !== undefined &&
              download.totalBytes !== undefined && (
                <div className="space-y-1">
                  <Progress value={getProgressPercent()} className="h-2" />
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>
                      {formatFileSize(download.receivedBytes)} /{" "}
                      {formatFileSize(download.totalBytes)}
                    </span>
                    {download.speed && (
                      <span>{formatSpeed(download.speed)}</span>
                    )}
                  </div>
                </div>
              )}

            {download.type === "meta" && download.phase === "uploading" && (
              <div className="mt-2">
                <div className="flex items-center gap-2 text-xs text-green-600">
                  <Upload className="h-3 w-3" />
                  <span>Uploading to Meta cloud...</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
