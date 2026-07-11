import { Badge } from "@/components/ui/badge";
import type { HealthResponse, ScanStatus } from "@/lib/api";

interface StatusBarProps {
  health: HealthResponse | null;
  scanStatus: ScanStatus | null;
  backendReady: boolean;
}

export function StatusBar({ health, scanStatus, backendReady }: StatusBarProps) {
  const scanState = scanStatus?.state ?? "idle";
  const cacheAge =
    health?.cache_age_hours != null
      ? `${health.cache_age_hours.toFixed(1)}h ago`
      : "unknown";

  return (
    <footer className="flex h-8 shrink-0 items-center justify-between border-t border-border bg-card px-4 text-xs text-muted-foreground">
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5">
          <span
            className={`h-2 w-2 rounded-full ${backendReady ? "bg-success" : "bg-destructive"}`}
          />
          Backend: {backendReady ? "Connected" : "Disconnected"}
        </span>
        {health && (
          <span>
            Threat DB: {health.cache_count.toLocaleString()} names ({cacheAge})
          </span>
        )}
        {health?.warnings?.[0] && (
          <span className="truncate text-warning">{health.warnings[0]}</span>
        )}
      </div>
      <div className="flex items-center gap-2">
        <span>Scanner:</span>
        <Badge variant={scanState === "running" ? "default" : "secondary"}>
          {scanState}
        </Badge>
        {scanStatus?.workers ? (
          <span>{scanStatus.workers} workers</span>
        ) : null}
      </div>
    </footer>
  );
}
