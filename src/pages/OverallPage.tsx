import { useCallback, useState } from "react";
import { CheckCircle2, Loader2, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getScanResults,
  getScanStatus,
  getStartupList,
  scanServices,
  startScan,
  type ScanMode,
  type ScanResults,
  type ScanStatus,
} from "@/lib/api";
import { truncatePath } from "@/lib/utils";

type PhaseState = "pending" | "running" | "done" | "error";

interface PhaseCardProps {
  title: string;
  state: PhaseState;
  result?: string;
  live?: string;
  hasIssues?: boolean;
}

function PhaseCard({ title, state, result, live, hasIssues }: PhaseCardProps) {
  const borderClass =
    state === "running"
      ? "border-primary animate-pulse"
      : state === "done"
        ? hasIssues
          ? "border-warning"
          : "border-success"
        : state === "error"
          ? "border-destructive"
          : "border-border opacity-60";

  return (
    <Card className={`transition-all ${borderClass}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">{title}</CardTitle>
          {state === "running" && <Loader2 className="h-4 w-4 animate-spin text-primary" />}
          {state === "done" && !hasIssues && (
            <CheckCircle2 className="h-4 w-4 text-success" />
          )}
          {state === "done" && hasIssues && (
            <ShieldAlert className="h-4 w-4 text-warning" />
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <Badge variant={state === "done" ? "secondary" : "outline"} className="capitalize">
          {state}
        </Badge>
        {result && <p className="text-muted-foreground">{result}</p>}
        {live && state === "running" && (
          <p className="font-mono text-xs text-muted-foreground">{truncatePath(live, 80)}</p>
        )}
      </CardContent>
    </Card>
  );
}

interface OverallPageProps {
  defaultPath: string;
  defaultMode: ScanMode;
  backendReady: boolean;
  onScanComplete: (results: ScanResults) => void;
  onStatusChange: (status: ScanStatus) => void;
}

export function OverallPage({
  defaultPath,
  defaultMode,
  backendReady,
  onScanComplete,
  onStatusChange,
}: OverallPageProps) {
  const [running, setRunning] = useState(false);
  const [startupState, setStartupState] = useState<PhaseState>("pending");
  const [servicesState, setServicesState] = useState<PhaseState>("pending");
  const [fileState, setFileState] = useState<PhaseState>("pending");
  const [startupResult, setStartupResult] = useState("");
  const [servicesResult, setServicesResult] = useState("");
  const [fileResult, setFileResult] = useState("");
  const [liveFile, setLiveFile] = useState("");
  const [summary, setSummary] = useState<{
    startupCount: number;
    servicesFlagged: number;
    fileSuspicious: number;
    fileMalicious: number;
  } | null>(null);
  const [fileResults, setFileResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState("");

  const pollScanStatus = useCallback(async (): Promise<ScanStatus> => {
    const status = await getScanStatus();
    onStatusChange(status);
    setLiveFile(status.file_path);
    setFileResult(
      `Scanning file ${status.current.toLocaleString()} of ${status.total.toLocaleString()} — ` +
        `${status.suspicious} suspicious, ${status.malicious} malicious`,
    );
    return status;
  }, [onStatusChange]);

  const runFullScan = async () => {
    if (!backendReady) return;
    setRunning(true);
    setError("");
    setSummary(null);
    setFileResults(null);
    setStartupState("running");
    setServicesState("pending");
    setFileState("pending");

    try {
      const startupItems = await getStartupList();
      setStartupState("done");
      setStartupResult(`${startupItems.length} startup items found`);

      setServicesState("running");
      const servicesScan = await scanServices();
      const servicesFlagged = servicesScan.flagged;
      setServicesState("done");
      setServicesResult(
        `${servicesScan.total} services checked, ${servicesFlagged} flagged for review`,
      );

      setFileState("running");
      await startScan(defaultPath, defaultMode);

      let status = await pollScanStatus();
      while (status.state === "running") {
        await new Promise((resolve) => setTimeout(resolve, 500));
        status = await pollScanStatus();
      }

      const results = await getScanResults();
      setFileResults(results);
      setFileState(status.state === "error" ? "error" : "done");
      setFileResult(
        `${results.summary.total_scanned.toLocaleString()} files scanned, ` +
          `${results.summary.suspicious} suspicious, ${results.summary.malicious} malicious`,
      );

      setSummary({
        startupCount: startupItems.length,
        servicesFlagged,
        fileSuspicious: results.summary.suspicious,
        fileMalicious: results.summary.malicious,
      });
    } catch {
      setError("Full scan was interrupted or failed. Check individual tabs for details.");
      setStartupState((s) => (s === "running" ? "error" : s));
      setServicesState((s) => (s === "running" ? "error" : s));
      setFileState((s) => (s === "running" ? "error" : s));
    } finally {
      setRunning(false);
    }
  };

  const fileHasIssues =
    (summary?.fileSuspicious ?? 0) + (summary?.fileMalicious ?? 0) > 0;

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <div className="text-center">
        <h1 className="text-3xl font-semibold">Full System Check</h1>
        <p className="mt-2 text-muted-foreground">
          Run startup, services, and file scans in one sequence
        </p>
      </div>

      <Button
        size="lg"
        className="h-14 w-full text-lg"
        disabled={!backendReady || running}
        onClick={runFullScan}
      >
        {running ? (
          <>
            <Loader2 className="h-5 w-5 animate-spin" />
            Running Full Scan...
          </>
        ) : (
          "Run Full Scan"
        )}
      </Button>

      {error && (
        <Card>
          <CardContent className="py-4 text-sm text-destructive">{error}</CardContent>
        </Card>
      )}

      <div className="space-y-4">
        <PhaseCard
          title="Phase 1: Startup Items"
          state={startupState}
          result={startupResult}
          hasIssues={false}
        />
        <PhaseCard
          title="Phase 2: Services Scan"
          state={servicesState}
          result={servicesResult}
          hasIssues={(summary?.servicesFlagged ?? 0) > 0}
        />
        <PhaseCard
          title="Phase 3: File Scan"
          state={fileState}
          result={fileResult}
          live={liveFile}
          hasIssues={fileHasIssues}
        />
      </div>

      {summary && (
        <Card>
          <CardHeader>
            <CardTitle>Scan Complete</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p>Startup Items: {summary.startupCount} found</p>
            <p>Services: {summary.servicesFlagged} flagged for review</p>
            <p>
              Files: {summary.fileSuspicious + summary.fileMalicious} threats detected
              {summary.fileMalicious > 0 && (
                <span className="text-destructive"> ({summary.fileMalicious} malicious)</span>
              )}
            </p>
            {fileResults && (
              <Button
                className="mt-2"
                onClick={() => onScanComplete(fileResults)}
              >
                View Full Results
              </Button>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
