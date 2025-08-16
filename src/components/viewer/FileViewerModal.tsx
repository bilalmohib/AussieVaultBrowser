import React, { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../ui/dialog";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  filename: string;
  url: string;
};

export const FileViewerModal: React.FC<Props> = ({
  open,
  onOpenChange,
  filename,
  url,
}) => {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let revoked = false;
    const load = async () => {
      setError(null);
      setObjectUrl(null);
      try {
        // Try to fetch the file for embedding (handles auth cookies via include)
        const resp = await fetch(url, { credentials: "include" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const blob = await resp.blob();
        const obj = URL.createObjectURL(blob);
        if (!revoked) setObjectUrl(obj);
      } catch (e: any) {
        setError(e?.message ?? "Failed to load file");
      }
    };
    if (open) load();
    return () => {
      revoked = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [open, url]);

  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const isImage = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg"].includes(
    ext
  );
  const isPdf = ext === "pdf";
  const isText = ["txt", "md", "csv", "log", "json", "xml"].includes(ext);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[90vw] w-[90vw] h-[90vh] p-0">
        <DialogHeader className="px-6 pt-4 pb-2">
          <DialogTitle className="truncate" title={filename}>
            {filename}
          </DialogTitle>
        </DialogHeader>
        <div className="w-full h-[calc(100%-56px)] bg-background">
          {!error && !objectUrl && (
            <div className="w-full h-full flex items-center justify-center text-muted-foreground">
              Loading preview…
            </div>
          )}
          {error && (
            <div className="p-6 text-sm text-red-600">
              Preview failed: {error}
            </div>
          )}
          {objectUrl && (
            <div className="w-full h-full">
              {isImage && (
                <img
                  src={objectUrl}
                  alt={filename}
                  className="max-w-full max-h-full object-contain mx-auto"
                />
              )}
              {isPdf && (
                <iframe
                  src={objectUrl}
                  title={filename}
                  className="w-full h-full"
                />
              )}
              {isText && (
                <iframe
                  src={objectUrl}
                  title={filename}
                  className="w-full h-full"
                />
              )}
              {!isImage && !isPdf && !isText && (
                <iframe
                  src={objectUrl}
                  title={filename}
                  className="w-full h-full"
                />
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default FileViewerModal;
