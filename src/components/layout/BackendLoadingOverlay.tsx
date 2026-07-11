import { Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface BackendLoadingOverlayProps {
  message: string;
  failed: boolean;
  onRetry: () => void;
}

export function BackendLoadingOverlay({
  message,
  failed,
  onRetry,
}: BackendLoadingOverlayProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95">
      <div className="flex max-w-md flex-col items-center gap-4 text-center">
        {!failed ? (
          <Loader2 className="h-10 w-10 animate-spin text-primary" />
        ) : (
          <RefreshCw className="h-10 w-10 text-warning" />
        )}
        <div>
          <h2 className="text-lg font-semibold">
            {failed ? "Backend Unavailable" : "Starting NullScan"}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{message}</p>
        </div>
        {failed && (
          <Button onClick={onRetry}>
            <RefreshCw className="h-4 w-4" />
            Retry Connection
          </Button>
        )}
      </div>
    </div>
  );
}
