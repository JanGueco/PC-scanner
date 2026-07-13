import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, ShieldCheck } from "lucide-react";
import { DeepCheckPanel } from "@/components/deepcheck/DeepCheckPanel";
import {
  FlaggedContextMenu,
  type ContextMenuItem,
} from "@/components/deepcheck/FlaggedContextMenu";
import { VtResultBadge } from "@/components/deepcheck/VtResultBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useDeepCheckAction } from "@/hooks/useDeepCheckAction";
import type { FlaggedFile, ScanResults } from "@/lib/api";
import type { DeepCheckState } from "@/lib/deepcheck";
import { copyToClipboard, openFileLocation } from "@/lib/shell";
import { downloadBlob, formatDuration, truncatePath } from "@/lib/utils";

interface ResultsPageProps {
  results: ScanResults | null;
  hasVtApiKey: boolean;
  fileDeepChecks: Record<string, DeepCheckState>;
  onUpdateFileDeepCheck: (path: string, state: DeepCheckState) => void;
}

type SortKey = "file_name" | "path" | "status" | "match_type";
type SortDir = "asc" | "desc";

function exportCsv(results: ScanResults) {
  const headers = ["file_name", "path", "status", "match_type", "sha256", "database"];
  const rows = results.flagged_files.map((f) =>
    [f.file_name, f.path, f.status, f.match_type, f.sha256 ?? "", f.database ?? ""]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(","),
  );
  downloadBlob([headers.join(","), ...rows].join("\n"), "maat-results.csv", "text/csv");
}

function exportJson(results: ScanResults) {
  downloadBlob(JSON.stringify(results, null, 2), "maat-results.json", "application/json");
}

interface FlaggedRowProps {
  file: FlaggedFile;
  hasVtApiKey: boolean;
  deepCheckState: DeepCheckState | null;
  onUpdateDeepCheck: (path: string, state: DeepCheckState) => void;
  onContextMenu: (event: React.MouseEvent, file: FlaggedFile) => void;
  pendingDeepCheck?: boolean;
  onPendingDeepCheckHandled?: () => void;
}

function FlaggedRow({
  file,
  hasVtApiKey,
  deepCheckState,
  onUpdateDeepCheck,
  onContextMenu,
  pendingDeepCheck = false,
  onPendingDeepCheckHandled,
}: FlaggedRowProps) {
  const [expanded, setExpanded] = useState(false);
  const { checking, errorMessage, rateLimitSeconds, runDeepCheck, deepCheckState: vtState } =
    useDeepCheckAction({
      storageKey: file.path,
      type: "file",
      identifier: file.path,
      sha256: file.sha256,
      path: file.path,
      state: deepCheckState,
      onUpdate: onUpdateDeepCheck,
    });

  useEffect(() => {
    if (!pendingDeepCheck) return;
    setExpanded(true);
    void runDeepCheck().finally(() => onPendingDeepCheckHandled?.());
  }, [pendingDeepCheck, runDeepCheck, onPendingDeepCheckHandled]);

  return (
    <>
      <TableRow
        className="cursor-pointer"
        onClick={() => setExpanded(!expanded)}
        onContextMenu={(event) => onContextMenu(event, file)}
      >
        <TableCell>
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </TableCell>
        <TableCell className="font-medium">{file.file_name}</TableCell>
        <TableCell className="font-mono text-xs">{truncatePath(file.path, 50)}</TableCell>
        <TableCell>
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant={file.status === "malicious" ? "destructive" : "warning"}>
              {file.status}
            </Badge>
            {vtState?.vt_result && (
              <VtResultBadge result={vtState.vt_result} compact />
            )}
          </div>
        </TableCell>
        <TableCell className="capitalize">{file.match_type}</TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={5} className="bg-muted/30">
            <div className="space-y-2 py-2 pl-8 text-sm">
              <p>
                <span className="text-muted-foreground">Full path:</span>{" "}
                <span className="font-mono">{file.path}</span>
              </p>
              {file.sha256 && (
                <p>
                  <span className="text-muted-foreground">SHA256:</span>{" "}
                  <span className="font-mono">{file.sha256}</span>
                </p>
              )}
              {file.database && (
                <p>
                  <span className="text-muted-foreground">Database:</span> {file.database}
                </p>
              )}
              <DeepCheckPanel
                title="VirusTotal Deep Check"
                buttonLabel="Deep Check this File"
                state={vtState}
                hasApiKey={hasVtApiKey}
                checking={checking}
                errorMessage={errorMessage}
                rateLimitSeconds={rateLimitSeconds}
                onDeepCheck={runDeepCheck}
              />
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

export function ResultsPage({
  results,
  hasVtApiKey,
  fileDeepChecks,
  onUpdateFileDeepCheck,
}: ResultsPageProps) {
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("status");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    file: FlaggedFile;
  } | null>(null);
  const [pendingDeepCheckPath, setPendingDeepCheckPath] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!results) return [];
    let files = results.flagged_files;
    if (filter) {
      const q = filter.toLowerCase();
      files = files.filter(
        (f) =>
          f.file_name.toLowerCase().includes(q) ||
          f.path.toLowerCase().includes(q) ||
          f.status.includes(q),
      );
    }
    return [...files].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      const cmp = String(av).localeCompare(String(bv));
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [results, filter, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const handleContextMenu = (event: React.MouseEvent, file: FlaggedFile) => {
    event.preventDefault();
    event.stopPropagation();
    setContextMenu({ x: event.clientX, y: event.clientY, file });
  };

  const contextItems: ContextMenuItem[] = contextMenu
    ? [
        {
          id: "deep-check",
          label: "🔍 Deep Check with VirusTotal",
          icon: "search",
          disabled: !hasVtApiKey,
          onSelect: () => setPendingDeepCheckPath(contextMenu.file.path),
        },
        {
          id: "copy-hash",
          label: "📋 Copy SHA256",
          icon: "copy-hash",
          disabled: !contextMenu.file.sha256,
          onSelect: () => {
            if (contextMenu.file.sha256) {
              void copyToClipboard(contextMenu.file.sha256);
            }
          },
        },
        {
          id: "copy-path",
          label: "📁 Copy File Path",
          icon: "copy-path",
          onSelect: () => void copyToClipboard(contextMenu.file.path),
        },
        {
          id: "open-location",
          label: "🔗 Open File Location",
          icon: "open-location",
          onSelect: () => void openFileLocation(contextMenu.file.path),
        },
      ]
    : [];

  if (!results) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        No results available. Run a scan first.
      </div>
    );
  }

  const { summary } = results;
  const hasThreats = results.flagged_files.length > 0;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Scan Results</h1>
          <p className="text-sm text-muted-foreground font-mono">{summary.scan_path}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportJson(results)}>
            <Download className="h-4 w-4" />
            JSON
          </Button>
          <Button variant="outline" size="sm" onClick={() => exportCsv(results)}>
            <Download className="h-4 w-4" />
            CSV
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <p className="text-sm text-muted-foreground">Files Scanned</p>
              <p className="text-2xl font-semibold">{summary.total_scanned.toLocaleString()}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Duration</p>
              <p className="text-2xl font-semibold">{formatDuration(summary.duration_seconds)}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Threats Found</p>
              <p className="text-2xl font-semibold text-destructive">
                {summary.suspicious + summary.malicious}
              </p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Skipped</p>
              <p className="text-2xl font-semibold">{summary.skipped}</p>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <Badge variant="success">Clean: {summary.clean}</Badge>
            <Badge variant="warning">Suspicious: {summary.suspicious}</Badge>
            <Badge variant="destructive">Malicious: {summary.malicious}</Badge>
          </div>
        </CardContent>
      </Card>

      {!hasThreats ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <ShieldCheck className="h-12 w-12 text-success" />
            <h2 className="text-lg font-semibold">No Threats Detected</h2>
            <p className="text-sm text-muted-foreground">
              {summary.total_scanned === 0
                ? "The scan directory contained no files."
                : "All scanned files passed threat checks."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle>Flagged Files ({filtered.length})</CardTitle>
            <Input
              placeholder="Filter results..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="max-w-xs"
            />
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead className="cursor-pointer" onClick={() => toggleSort("file_name")}>
                    File Name
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => toggleSort("path")}>
                    Path
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => toggleSort("status")}>
                    Status
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => toggleSort("match_type")}>
                    Match Type
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((file) => (
                  <FlaggedRow
                    key={`${file.path}-${file.sha256}`}
                    file={file}
                    hasVtApiKey={hasVtApiKey}
                    deepCheckState={fileDeepChecks[file.path] ?? null}
                    onUpdateDeepCheck={onUpdateFileDeepCheck}
                    onContextMenu={handleContextMenu}
                    pendingDeepCheck={pendingDeepCheckPath === file.path}
                    onPendingDeepCheckHandled={() => setPendingDeepCheckPath(null)}
                  />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <FlaggedContextMenu
        open={Boolean(contextMenu)}
        x={contextMenu?.x ?? 0}
        y={contextMenu?.y ?? 0}
        items={contextItems}
        onClose={() => setContextMenu(null)}
      />
    </div>
  );
}
