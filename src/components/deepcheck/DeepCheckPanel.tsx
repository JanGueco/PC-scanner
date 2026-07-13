import { ExternalLink, Loader2, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { DeepCheckState, VtResult } from "@/lib/deepcheck";
import {
  formatDeepCheckDate,
  vtScanResultText,
  vtStatusLabel,
} from "@/lib/deepcheck";
import { openExternalUrl } from "@/lib/shell";
import { cn } from "@/lib/utils";

interface DeepCheckPanelProps {
  title: string;
  buttonLabel: string;
  state: DeepCheckState | null;
  hasApiKey: boolean;
  checking: boolean;
  errorMessage?: string;
  rateLimitSeconds?: number;
  onDeepCheck: () => void;
  lastCheckedLabel?: string;
  resultLabel?: string;
}

function statusBadgeClass(result: VtResult): string {
  switch (result) {
    case "clean":
      return "border-emerald-500/30 bg-emerald-500/15 text-emerald-400";
    case "malicious":
      return "border-red-500/30 bg-red-500/15 text-red-400";
    case "suspicious":
      return "border-amber-500/30 bg-amber-500/15 text-amber-400";
    case "undetected":
      return "border-zinc-500/30 bg-zinc-500/15 text-zinc-400";
  }
}

export function DeepCheckPanel({
  title,
  buttonLabel,
  state,
  hasApiKey,
  checking,
  errorMessage,
  rateLimitSeconds = 0,
  onDeepCheck,
  lastCheckedLabel = "Last checked:",
  resultLabel = "Result:",
}: DeepCheckPanelProps) {
  const disabled = checking || !hasApiKey || rateLimitSeconds > 0;
  const checked = Boolean(state?.last_deep_checked && state.vt_result);

  return (
    <div className="mt-4 rounded-md border border-border bg-background/40 p-4">
      <p className="text-sm font-medium">{title}</p>

      <Button
        size="sm"
        className="mt-3"
        disabled={disabled}
        onClick={(event) => {
          event.stopPropagation();
          onDeepCheck();
        }}
      >
        {checking ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Checking...
          </>
        ) : !hasApiKey ? (
          <>
            <Lock className="h-4 w-4" />
            Deep Check Unavailable
          </>
        ) : (
          buttonLabel
        )}
      </Button>

      {!hasApiKey && (
        <p className="mt-2 text-xs text-muted-foreground">
          Add your VirusTotal API key in Settings to use Deep Check
        </p>
      )}

      {rateLimitSeconds > 0 && (
        <p className="mt-2 text-xs text-amber-400">
          Rate limit reached. Try again in {rateLimitSeconds} second
          {rateLimitSeconds === 1 ? "" : "s"}.
        </p>
      )}

      {errorMessage && !rateLimitSeconds && (
        <p className="mt-2 text-xs text-destructive">{errorMessage}</p>
      )}

      {!checked && !checking && !errorMessage && hasApiKey && (
        <p className="mt-2 text-xs text-muted-foreground">Not yet deep checked</p>
      )}

      {checked && state?.vt_result && (
        <div className="mt-3 space-y-2 text-sm">
          <p className="text-muted-foreground">
            {lastCheckedLabel} {formatDeepCheckDate(state.last_deep_checked!)}
          </p>
          <p>
            {resultLabel}{" "}
            <span className="text-foreground">{vtScanResultText(state)}</span>
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground">Status:</span>
            <Badge
              variant="outline"
              className={cn("rounded-md px-2 py-0.5 text-[11px]", statusBadgeClass(state.vt_result))}
            >
              {vtStatusLabel(state.vt_result)}
            </Badge>
          </div>
          {state.vt_result === "undetected" && (
            <p className="text-xs text-muted-foreground">
              VT: Unknown — VirusTotal has no record of this file. This could mean it&apos;s rare or
              new, not necessarily safe.
            </p>
          )}
          {state.vt_permalink && (
            <Button
              variant="ghost"
              size="sm"
              className="h-auto p-0 text-primary hover:bg-transparent"
              onClick={(event) => {
                event.stopPropagation();
                void openExternalUrl(state.vt_permalink!);
              }}
            >
              View Full Report
              <ExternalLink className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
