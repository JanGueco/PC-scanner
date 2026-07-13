import { Badge } from "@/components/ui/badge";
import type { VtResult } from "@/lib/deepcheck";
import { cn } from "@/lib/utils";

interface VtResultBadgeProps {
  result: VtResult;
  compact?: boolean;
  className?: string;
}

const styles: Record<VtResult, string> = {
  clean: "border-emerald-500/30 bg-emerald-500/15 text-emerald-400",
  malicious: "border-red-500/30 bg-red-500/15 text-red-400",
  suspicious: "border-amber-500/30 bg-amber-500/15 text-amber-400",
  undetected: "border-zinc-500/30 bg-zinc-500/15 text-zinc-400",
};

const labels: Record<VtResult, string> = {
  clean: "VT: Clean",
  malicious: "VT: Malicious",
  suspicious: "VT: Suspicious",
  undetected: "VT: Unknown",
};

export function VtResultBadge({ result, compact = false, className }: VtResultBadgeProps) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-md font-medium whitespace-nowrap",
        compact ? "px-1.5 py-0 text-[10px]" : "px-2 py-0.5 text-[11px]",
        styles[result],
        className,
      )}
    >
      {labels[result]}
    </Badge>
  );
}
