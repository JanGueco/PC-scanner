import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen, ShieldAlert, ShieldCheck, ShieldX, Square } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import {
  getScanStatus,
  startScan,
  stopScan,
  type ScanMode,
  type ScanStatus,
} from "@/lib/api";
import { truncatePath } from "@/lib/utils";

interface ScanPageProps {
  defaultPath: string;
  defaultMode: ScanMode;
  backendReady: boolean;
  onScanComplete: () => void;
  onStatusChange: (status: ScanStatus) => void;
}

export function ScanPage({
  defaultPath,
  defaultMode,
  backendReady,
  onScanComplete,
  onStatusChange,
}: ScanPageProps) {
  const [scanPath, setScanPath] = useState(defaultPath);
  const [mode, setMode] = useState<ScanMode>(defaultMode);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState<ScanStatus | null>(null);

  useEffect(() => {
    setScanPath(defaultPath);
  }, [defaultPath]);

  useEffect(() => {
    setMode(defaultMode);
  }, [defaultMode]);

  const pollStatus = useCallback(async () => {
    try {
      const next = await getScanStatus();
      setStatus(next);
      onStatusChange(next);
      if (next.state === "completed" || next.state === "cancelled") {
        setScanning(false);
        onScanComplete();
      }
    } catch {
      setScanning(false);
    }
  }, [onScanComplete, onStatusChange]);

  useEffect(() => {
    if (!scanning) return;
    const interval = setInterval(pollStatus, 500);
    pollStatus();
    return () => clearInterval(interval);
  }, [scanning, pollStatus]);

  const handleBrowse = async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      defaultPath: scanPath || "C:\\",
    });
    if (selected && typeof selected === "string") {
      setScanPath(selected);
    }
  };

  const handleStart = async () => {
    if (!scanPath) return;
    await startScan(scanPath, mode);
    setScanning(true);
    setStatus(null);
  };

  const handleStop = async () => {
    await stopScan();
    await pollStatus();
  };

  const progress =
    status && status.total > 0 ? Math.round((status.current / status.total) * 100) : 0;

  if (scanning && status) {
    return (
      <div className="mx-auto flex max-w-2xl flex-col gap-6">
        <div className="text-center">
          <h1 className="text-2xl font-semibold">Scan in Progress</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Scanning file {status.current.toLocaleString()} of {status.total.toLocaleString()}
          </p>
        </div>

        <Card>
          <CardContent className="space-y-4 pt-6">
            <Progress value={progress} />
            <p className="font-mono text-xs text-muted-foreground">
              {truncatePath(status.file_path || "—", 90)}
            </p>
            <div className="flex flex-wrap justify-center gap-3">
              <Badge variant="success">
                <ShieldCheck className="mr-1 h-3 w-3" />
                Clean: {status.clean}
              </Badge>
              <Badge variant="warning">
                <ShieldAlert className="mr-1 h-3 w-3" />
                Suspicious: {status.suspicious}
              </Badge>
              <Badge variant="destructive">
                <ShieldX className="mr-1 h-3 w-3" />
                Malicious: {status.malicious}
              </Badge>
            </div>
            <div className="flex justify-center pt-2">
              <Button variant="destructive" onClick={handleStop}>
                <Square className="h-4 w-4 fill-current" />
                Stop Scan
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-xl flex-col items-center gap-8 pt-12">
      <div className="text-center">
        <h1 className="text-3xl font-semibold">File System Scanner</h1>
        <p className="mt-2 text-muted-foreground">
          On-demand malware detection using threat intelligence databases
        </p>
      </div>

      <Button
        size="lg"
        className="h-16 w-56 text-lg"
        disabled={!backendReady || !scanPath}
        onClick={handleStart}
      >
        Start Scan
      </Button>

      <Card className="w-full">
        <CardContent className="space-y-5 pt-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Scan Mode</p>
              <p className="text-sm text-muted-foreground">
                {mode === "fast"
                  ? "Uses all CPU threads"
                  : "Uses 2 threads — leaves headroom for other tasks"}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className={mode === "fast" ? "text-foreground" : "text-muted-foreground"}>
                Fast
              </span>
              <Switch
                checked={mode === "background"}
                onCheckedChange={(checked) => setMode(checked ? "background" : "fast")}
              />
              <span className={mode === "background" ? "text-foreground" : "text-muted-foreground"}>
                Background
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <p className="font-medium">Scan Directory</p>
            <div className="flex gap-2">
              <div className="flex-1 truncate rounded-md border border-input bg-background px-3 py-2 font-mono text-sm">
                {scanPath || "No directory selected"}
              </div>
              <Button variant="outline" onClick={handleBrowse}>
                <FolderOpen className="h-4 w-4" />
                Browse
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
