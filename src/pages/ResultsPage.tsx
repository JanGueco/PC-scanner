import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, ShieldCheck } from "lucide-react";
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
import type { FlaggedFile, ScanResults } from "@/lib/api";
import { downloadBlob, formatDuration, truncatePath } from "@/lib/utils";

interface ResultsPageProps {
  results: ScanResults | null;
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
  downloadBlob([headers.join(","), ...rows].join("\n"), "nullscan-results.csv", "text/csv");
}

function exportJson(results: ScanResults) {
  downloadBlob(JSON.stringify(results, null, 2), "nullscan-results.json", "application/json");
}

function FlaggedRow({ file }: { file: FlaggedFile }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <TableRow className="cursor-pointer" onClick={() => setExpanded(!expanded)}>
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
          <Badge variant={file.status === "malicious" ? "destructive" : "warning"}>
            {file.status}
          </Badge>
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
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

export function ResultsPage({ results }: ResultsPageProps) {
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("status");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

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
                  <FlaggedRow key={`${file.path}-${file.sha256}`} file={file} />
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
