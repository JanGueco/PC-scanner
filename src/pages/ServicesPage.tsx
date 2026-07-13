import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Cpu, Loader2 } from "lucide-react";
import { DeepCheckPanel } from "@/components/deepcheck/DeepCheckPanel";
import {
  FlaggedContextMenu,
  type ContextMenuItem,
} from "@/components/deepcheck/FlaggedContextMenu";
import { VtResultBadge } from "@/components/deepcheck/VtResultBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
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
import type { ServiceFlagLabel, ServiceScanEntry, ServiceSignatureInfo, ServicesScanStatus } from "@/lib/api";
import type { DeepCheckState } from "@/lib/deepcheck";
import { copyToClipboard } from "@/lib/shell";
import { cn } from "@/lib/utils";
import { useDeepCheckAction } from "@/hooks/useDeepCheckAction";
import { useRelativeTime } from "@/hooks/useRelativeTime";

const PAGE_SIZE = 50;

export type ServicesTabScanStatus = "never" | "scanning" | "complete";

export interface ServicesPageProps {
  services: ServiceScanEntry[];
  listLoading: boolean;
  listLoaded: boolean;
  listError: string;
  scanStatus: ServicesTabScanStatus;
  lastScannedAt: number | null;
  scanProgress: ServicesScanStatus | null;
  scanError: string;
  hasVtApiKey: boolean;
  serviceDeepChecks: Record<string, DeepCheckState>;
  onEnsureLoaded: () => void;
  onScan: () => void;
  onUpdateServiceDeepCheck: (serviceName: string, state: DeepCheckState) => void;
}

type ServiceStatus = ServiceScanEntry["status"];
type ServiceStartType = ServiceScanEntry["start_type"];

function statusBadge(status: ServiceStatus) {
  switch (status) {
    case "Running":
      return {
        label: "Running",
        className: "border-emerald-500/30 bg-emerald-500/15 text-emerald-400",
      };
    case "Stopped":
      return {
        label: "Stopped",
        className: "border-zinc-500/30 bg-zinc-500/15 text-zinc-400",
      };
    case "Paused":
      return {
        label: "Paused",
        className: "border-amber-500/30 bg-amber-500/15 text-amber-400",
      };
    default:
      return {
        label: status,
        className: "border-zinc-500/30 bg-zinc-500/15 text-zinc-400",
      };
  }
}

function startTypeBadge(startType: ServiceStartType) {
  switch (startType) {
    case "Automatic":
      return {
        label: "Automatic",
        className: "border-blue-500/30 bg-blue-500/15 text-blue-400",
      };
    case "Manual":
      return {
        label: "Manual",
        className: "border-zinc-500/30 bg-zinc-500/15 text-zinc-400",
      };
    case "Disabled":
      return {
        label: "Disabled",
        className: "border-red-500/30 bg-red-500/15 text-red-400",
      };
    default:
      return {
        label: startType,
        className: "border-zinc-500/30 bg-zinc-500/15 text-zinc-400",
      };
  }
}

interface FlagBadgeConfig {
  label: string;
  tooltip: string;
  className: string;
}

function flagBadge(label: ServiceFlagLabel | null | undefined): FlagBadgeConfig | null {
  switch (label) {
    case "third_party":
      return {
        label: "Third Party",
        tooltip: "Valid digital signature from a non-Microsoft publisher. Passed malware name check.",
        className: "border-zinc-500/30 bg-zinc-500/15 text-zinc-300",
      };
    case "review":
      return {
        label: "⚠ Review",
        tooltip:
          "Name matched malware database. Use Deep Check to verify with VirusTotal.",
        className: "border-amber-500/30 bg-amber-500/15 text-amber-400",
      };
    case "suspicious_system":
      return {
        label: "⚠ Suspicious",
        tooltip:
          "System file with invalid or missing signature. This may indicate a trojanized executable.",
        className: "border-red-500/30 bg-red-500/15 text-red-400",
      };
    case "malicious":
      return {
        label: "✕ Malicious",
        tooltip: "SHA256 hash confirmed in malware database.",
        className: "border-red-700/40 bg-red-700/20 text-red-300",
      };
    case "unverifiable":
      return {
        label: "? Unverify",
        tooltip:
          "Signature could not be verified — run Maat as Administrator to check this file.",
        className: "border-zinc-600/30 bg-zinc-600/10 text-zinc-500",
      };
    default:
      return null;
  }
}

function rowHighlightClass(label: ServiceFlagLabel | null | undefined, flagged: boolean): string {
  if (label === "suspicious_system" || label === "malicious") {
    return "bg-[rgba(239,68,68,0.05)] hover:bg-[rgba(239,68,68,0.08)]";
  }
  if (flagged || label === "review") {
    return "bg-[rgba(245,158,11,0.05)] hover:bg-[rgba(245,158,11,0.08)]";
  }
  return "";
}

function signatureStatusText(signature: ServiceSignatureInfo): string {
  if (signature.verification_error || signature.signature_status === "unverifiable") {
    return "Unverifiable";
  }
  if (signature.signature_status === "not_signed") {
    return "Not Signed";
  }
  if (signature.signature_status === "invalid") {
    return "Invalid ✗";
  }
  return "Valid ✓";
}

function signatureStatusClass(signature: ServiceSignatureInfo): string {
  if (signature.verification_error || signature.signature_status === "unverifiable") {
    return "text-zinc-400";
  }
  if (signature.signature_status === "not_signed" || signature.signature_status === "invalid") {
    return "text-red-400";
  }
  if (signature.signed_by_microsoft) {
    return "text-emerald-400";
  }
  return "text-blue-400";
}

function SignatureDetails({ signature }: { signature: ServiceSignatureInfo }) {
  return (
    <div className="mt-4 rounded-md border border-border bg-background/40 p-4">
      <p className="text-sm font-medium">Digital Signature</p>
      <div className="mt-2 space-y-1 text-sm">
        <p>
          <span className="text-muted-foreground">Status:</span>{" "}
          <span className={signatureStatusClass(signature)}>{signatureStatusText(signature)}</span>
        </p>
        <p>
          <span className="text-muted-foreground">Signer:</span>{" "}
          <span className="font-mono">{signature.signer || "N/A"}</span>
        </p>
        {signature.verification_error && (
          <p className="text-xs text-muted-foreground">{signature.verification_error}</p>
        )}
      </div>
    </div>
  );
}

interface ServiceRowProps {
  service: ServiceScanEntry;
  hasVtApiKey: boolean;
  deepCheckState: DeepCheckState | null;
  onUpdateDeepCheck: (serviceName: string, state: DeepCheckState) => void;
  onContextMenu: (event: React.MouseEvent, service: ServiceScanEntry) => void;
  pendingDeepCheck?: boolean;
  onPendingDeepCheckHandled?: () => void;
  pendingExpand?: boolean;
  onPendingExpandHandled?: () => void;
}

function ServiceRow({
  service,
  hasVtApiKey,
  deepCheckState,
  onUpdateDeepCheck,
  onContextMenu,
  pendingDeepCheck = false,
  onPendingDeepCheckHandled,
  pendingExpand = false,
  onPendingExpandHandled,
}: ServiceRowProps) {
  const [expanded, setExpanded] = useState(false);
  const status = statusBadge(service.status);
  const startType = startTypeBadge(service.start_type);
  const flag = flagBadge(service.flag_label);
  const highlightClass = rowHighlightClass(service.flag_label, service.flagged);
  const { checking, errorMessage, rateLimitSeconds, runDeepCheck, deepCheckState: vtState } =
    useDeepCheckAction({
      storageKey: service.name,
      type: "service",
      identifier: service.name,
      sha256: service.sha256,
      path: service.executable_path || undefined,
      state: deepCheckState,
      onUpdate: onUpdateDeepCheck,
    });

  useEffect(() => {
    if (!pendingDeepCheck) return;
    setExpanded(true);
    void runDeepCheck().finally(() => onPendingDeepCheckHandled?.());
  }, [pendingDeepCheck, runDeepCheck, onPendingDeepCheckHandled]);

  useEffect(() => {
    if (!pendingExpand) return;
    setExpanded(true);
    onPendingExpandHandled?.();
  }, [pendingExpand, onPendingExpandHandled]);

  return (
    <>
      <TableRow
        className={cn("h-11 cursor-pointer border-border hover:bg-[#1F2937]", highlightClass)}
        onClick={() => setExpanded(!expanded)}
        onContextMenu={(event) => {
          if (service.flagged) {
            onContextMenu(event, service);
          }
        }}
      >
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          {expanded ? (
            <ChevronDown className="mx-auto h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="mx-auto h-4 w-4 text-muted-foreground" />
          )}
        </TableCell>
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="block truncate font-bold text-white">{service.display_name}</span>
            </TooltipTrigger>
            <TooltipContent side="top">{service.display_name}</TooltipContent>
          </Tooltip>
        </TableCell>
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          <Badge
            variant="outline"
            className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium", status.className)}
          >
            {status.label}
          </Badge>
        </TableCell>
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          <Badge
            variant="outline"
            className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium", startType.className)}
          >
            {startType.label}
          </Badge>
        </TableCell>
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="block cursor-default truncate font-mono text-xs text-[#6B7280]">
                {service.executable_path || "—"}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" className="break-all">
              {service.executable_path || "—"}
            </TooltipContent>
          </Tooltip>
        </TableCell>
        <TableCell className="overflow-hidden px-2 py-2 whitespace-nowrap">
          {flag ? (
            <div className="flex flex-col items-start gap-1">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className={cn(
                      "rounded-md px-1.5 py-0.5 text-[10px] font-medium whitespace-nowrap",
                      flag.className,
                    )}
                  >
                    {flag.label}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  {flag.tooltip}
                </TooltipContent>
              </Tooltip>
              {service.flagged && vtState?.vt_result && (
                <VtResultBadge result={vtState.vt_result} compact />
              )}
            </div>
          ) : null}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow className={highlightClass || "bg-muted/20"}>
          <TableCell colSpan={6} className="px-4 py-3">
            <div className="space-y-2 pl-6 text-sm">
              <p>
                <span className="text-muted-foreground">Service name:</span>{" "}
                <span className="font-mono">{service.name}</span>
              </p>
              <p>
                <span className="text-muted-foreground">Executable:</span>{" "}
                <span className="font-mono">{service.executable_path || "—"}</span>
              </p>
              {service.sha256 && (
                <p>
                  <span className="text-muted-foreground">SHA256:</span>{" "}
                  <span className="font-mono">{service.sha256}</span>
                </p>
              )}
              {service.database && (
                <p>
                  <span className="text-muted-foreground">Database:</span> {service.database}
                </p>
              )}
              {service.signature && <SignatureDetails signature={service.signature} />}
              {service.flagged && (
                <DeepCheckPanel
                  title="VirusTotal Deep Check"
                  buttonLabel="Deep Check this Service"
                  state={vtState}
                  hasApiKey={hasVtApiKey}
                  checking={checking}
                  errorMessage={errorMessage}
                  rateLimitSeconds={rateLimitSeconds}
                  onDeepCheck={runDeepCheck}
                  lastCheckedLabel="Last deep checked:"
                  resultLabel="Scan result:"
                />
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

export function ServicesPage({
  services,
  listLoading,
  listLoaded,
  listError,
  scanStatus,
  lastScannedAt,
  scanProgress,
  scanError,
  hasVtApiKey,
  serviceDeepChecks,
  onEnsureLoaded,
  onScan,
  onUpdateServiceDeepCheck,
}: ServicesPageProps) {
  const [showFlaggedOnly, setShowFlaggedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    service: ServiceScanEntry;
  } | null>(null);
  const [pendingDeepCheckName, setPendingDeepCheckName] = useState<string | null>(null);
  const [pendingExpandName, setPendingExpandName] = useState<string | null>(null);
  const lastScannedLabel = useRelativeTime(lastScannedAt);
  const scanning = scanStatus === "scanning";

  useEffect(() => {
    onEnsureLoaded();
  }, [onEnsureLoaded]);

  const filtered = useMemo(() => {
    if (!showFlaggedOnly) return services;
    return services.filter((service) => service.flagged);
  }, [services, showFlaggedOnly]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const flaggedCount = services.filter((service) => service.flagged).length;
  const trustedCount = services.filter(
    (service) =>
      service.signature?.signature_valid && service.signature?.signed_by_microsoft,
  ).length;
  const error = listError || scanError;

  const handleContextMenu = (event: React.MouseEvent, service: ServiceScanEntry) => {
    event.preventDefault();
    event.stopPropagation();
    setContextMenu({ x: event.clientX, y: event.clientY, service });
  };

  const contextItems: ContextMenuItem[] = contextMenu
    ? [
        {
          id: "deep-check",
          label: "🔍 Deep Check with VirusTotal",
          icon: "search",
          disabled: !hasVtApiKey,
          onSelect: () => setPendingDeepCheckName(contextMenu.service.name),
        },
        {
          id: "copy-hash",
          label: "📋 Copy SHA256",
          icon: "copy-hash",
          disabled: !contextMenu.service.sha256,
          onSelect: () => {
            if (contextMenu.service.sha256) {
              void copyToClipboard(contextMenu.service.sha256);
            }
          },
        },
        {
          id: "copy-path",
          label: "📁 Copy Executable Path",
          icon: "copy-path",
          disabled: !contextMenu.service.executable_path,
          onSelect: () => void copyToClipboard(contextMenu.service.executable_path),
        },
        {
          id: "details",
          label: "ℹ️ View Service Details",
          icon: "details",
          onSelect: () => setPendingExpandName(contextMenu.service.name),
        },
      ]
    : [];

  if (listLoading && !listLoaded) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        Loading services...
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold">Windows Services</h1>
            <p className="text-sm text-muted-foreground">
              Cross-check service executables against the malware database
            </p>
            {scanStatus === "complete" && (
              <p className="mt-1 text-xs text-muted-foreground">
                Last scanned: {lastScannedLabel}
              </p>
            )}
          </div>
          <Button onClick={onScan} disabled={scanning || listLoading}>
            {scanning ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {scanProgress && scanProgress.total > 0
                  ? `Scanning ${scanProgress.current}/${scanProgress.total}...`
                  : "Scanning..."}
              </>
            ) : (
              "Scan Services"
            )}
          </Button>
        </div>

        {scanning && scanProgress && scanProgress.total > 0 && (
          <p className="text-sm text-muted-foreground">
            Checking {scanProgress.service_name || "services"} — {scanProgress.flagged} flagged so
            far
          </p>
        )}

        {error && (
          <Card>
            <CardContent className="py-6 text-sm text-destructive">{error}</CardContent>
          </Card>
        )}

        {!error && services.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
              <Cpu className="h-10 w-10 text-muted-foreground" />
              <h2 className="text-lg font-semibold">No services found</h2>
              <p className="text-sm text-muted-foreground">
                Could not enumerate Windows services on this system.
              </p>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="space-y-4 p-0 pt-4">
              <div className="dark-table-scroll max-h-[min(62vh,680px)] overflow-y-auto overflow-x-hidden px-0">
                <table className="w-full table-fixed caption-bottom text-sm">
                  <colgroup>
                    <col style={{ width: "3%" }} />
                    <col style={{ width: "26%" }} />
                    <col style={{ width: "10%" }} />
                    <col style={{ width: "12%" }} />
                    <col style={{ width: "37%" }} />
                    <col style={{ width: "12%" }} />
                  </colgroup>
                  <TableHeader className="sticky top-0 z-10 bg-card">
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead
                        colSpan={4}
                        className="h-9 overflow-hidden px-3 text-left text-sm font-medium whitespace-nowrap"
                      >
                        {services.length} Service{services.length === 1 ? "" : "s"}
                        <span className="mx-2 text-muted-foreground">•</span>
                        <span className="font-normal text-muted-foreground">
                          {scanStatus === "complete"
                            ? `Last scanned: ${lastScannedLabel}`
                            : "Not yet scanned"}
                        </span>
                        {scanStatus === "complete" && (
                          <>
                            <span className="ml-2 font-normal text-muted-foreground">
                              • {flaggedCount} flagged
                            </span>
                            <span className="ml-2 font-normal text-muted-foreground">
                              • {trustedCount} trusted (Microsoft-signed)
                            </span>
                          </>
                        )}
                      </TableHead>
                      <TableHead colSpan={2} className="h-9 px-3 whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <span className="text-xs text-muted-foreground">Show flagged only</span>
                          <Switch checked={showFlaggedOnly} onCheckedChange={setShowFlaggedOnly} />
                        </div>
                      </TableHead>
                    </TableRow>
                    <TableRow className="border-border hover:bg-transparent">
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap" />
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Display Name
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Status
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Start Type
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Executable Path
                      </TableHead>
                      <TableHead className="h-9 overflow-hidden px-2 text-xs font-medium text-[#4B5563] whitespace-nowrap">
                        Flag
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {paginated.map((service) => (
                      <ServiceRow
                        key={service.name}
                        service={service}
                        hasVtApiKey={hasVtApiKey}
                        deepCheckState={serviceDeepChecks[service.name] ?? null}
                        onUpdateDeepCheck={onUpdateServiceDeepCheck}
                        onContextMenu={handleContextMenu}
                        pendingDeepCheck={pendingDeepCheckName === service.name}
                        onPendingDeepCheckHandled={() => setPendingDeepCheckName(null)}
                        pendingExpand={pendingExpandName === service.name}
                        onPendingExpandHandled={() => setPendingExpandName(null)}
                      />
                    ))}
                  </TableBody>
                </table>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 pb-4 text-sm text-muted-foreground">
                  <span>
                    Page {page} of {totalPages}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page <= 1}
                      onClick={() => setPage((current) => current - 1)}
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page >= totalPages}
                      onClick={() => setPage((current) => current + 1)}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      <FlaggedContextMenu
        open={Boolean(contextMenu)}
        x={contextMenu?.x ?? 0}
        y={contextMenu?.y ?? 0}
        items={contextItems}
        onClose={() => setContextMenu(null)}
      />
    </TooltipProvider>
  );
}
