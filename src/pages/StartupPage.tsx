import { useEffect } from "react";
import { Loader2, RefreshCw, Rocket } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { StartupItem } from "@/lib/api";
import { cn } from "@/lib/utils";

type StartupSource = StartupItem["source"];

export interface StartupPageProps {
  items: StartupItem[];
  loaded: boolean;
  loading: boolean;
  error: string;
  onEnsureLoaded: () => void;
  onRefresh: () => void;
}

function sourceBadge(source: StartupSource) {
  switch (source) {
    case "Registry (HKCU)":
      return {
        label: "HKCU",
        className: "border-blue-500/30 bg-blue-500/15 text-blue-400",
      };
    case "Registry (HKLM)":
      return {
        label: "HKLM",
        className: "border-purple-500/30 bg-purple-500/15 text-purple-400",
      };
    case "Startup Folder":
      return {
        label: "Folder",
        className: "border-amber-500/30 bg-amber-500/15 text-amber-400",
      };
  }
}

function StartupTableRow({ item }: { item: StartupItem }) {
  const source = sourceBadge(item.source);

  return (
    <TableRow className="border-border hover:bg-[#1F2937]">
      <TableCell className="overflow-hidden px-3 py-3 whitespace-nowrap">
        <span className="block truncate font-bold text-white">{item.name}</span>
      </TableCell>
      <TableCell className="overflow-hidden px-3 py-3 whitespace-nowrap">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="block cursor-default truncate font-mono text-xs text-[#6B7280]">
              {item.path}
            </span>
          </TooltipTrigger>
          <TooltipContent side="top" className="break-all">
            {item.path}
          </TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell className="overflow-hidden px-3 py-3 whitespace-nowrap">
        <Badge
          variant="outline"
          className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium", source.className)}
        >
          {source.label}
        </Badge>
      </TableCell>
      <TableCell className="overflow-hidden px-3 py-3 whitespace-nowrap">
        <Badge variant="success" className="rounded-md px-2 py-0.5 text-[11px]">
          {item.status}
        </Badge>
      </TableCell>
    </TableRow>
  );
}

export function StartupPage({
  items,
  loaded,
  loading,
  error,
  onEnsureLoaded,
  onRefresh,
}: StartupPageProps) {
  useEffect(() => {
    onEnsureLoaded();
  }, [onEnsureLoaded]);

  if (loading && !loaded) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        Loading startup items...
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-semibold">Startup Items</h1>
              {!error && items.length > 0 && (
                <Badge variant="secondary" className="rounded-md px-2 py-0.5 text-xs font-normal">
                  {items.length} item{items.length === 1 ? "" : "s"}
                </Badge>
              )}
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              Programs configured to run when Windows starts
            </p>
          </div>
          <Button variant="outline" onClick={onRefresh} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Refresh
          </Button>
        </div>

        {error && (
          <Card>
            <CardContent className="py-6 text-sm text-destructive">{error}</CardContent>
          </Card>
        )}

        {!error && items.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
              <Rocket className="h-10 w-10 text-muted-foreground" />
              <h2 className="text-lg font-semibold">No startup items found</h2>
              <p className="text-sm text-muted-foreground">
                No entries were found in registry run keys or startup folders.
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="p-0">
              <div className="dark-table-scroll max-h-[min(62vh,680px)] overflow-y-auto overflow-x-hidden">
                <table className="w-full table-fixed caption-bottom text-sm">
                  <colgroup>
                    <col className="w-[20%]" />
                    <col className="w-[55%]" />
                    <col className="w-[15%]" />
                    <col className="w-[10%]" />
                  </colgroup>
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="h-9 overflow-hidden px-3 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Name
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-3 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Path
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-3 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Source
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-3 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Status
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((item) => (
                      <StartupTableRow
                        key={`${item.source}-${item.name}-${item.path}`}
                        item={item}
                      />
                    ))}
                  </TableBody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}
