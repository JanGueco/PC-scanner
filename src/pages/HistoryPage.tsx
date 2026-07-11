import { useEffect, useState } from "react";
import { Clock, FolderSearch } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { getHistory, type HistoryEntry } from "@/lib/api";
import { formatDuration, formatScanMode } from "@/lib/utils";

interface HistoryPageProps {
  onSelectEntry: (entry: HistoryEntry) => void;
}

export function HistoryPage({ onSelectEntry }: HistoryPageProps) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHistory()
      .then(setEntries)
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-muted-foreground">Loading history...</div>;
  }

  if (entries.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
        <Clock className="h-10 w-10" />
        <p>No scan history yet.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-4">
      <h1 className="text-2xl font-semibold">Scan History</h1>
      {entries.map((entry) => (
        <Card
          key={entry.id}
          className="cursor-pointer transition-colors hover:border-primary/50"
          onClick={() => onSelectEntry(entry)}
        >
          <CardContent className="flex items-center justify-between py-4">
            <div className="flex items-start gap-3">
              <FolderSearch className="mt-0.5 h-5 w-5 text-primary" />
              <div>
                <p className="font-mono text-sm">{entry.scan_path}</p>
                <p className="text-xs text-muted-foreground">
                  {new Date(entry.timestamp).toLocaleString()} ·{" "}
                  {entry.total_scanned.toLocaleString()} files ·{" "}
                  {formatDuration(entry.duration_seconds)} · {formatScanMode(entry.mode)}
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              <Badge variant="warning">{entry.suspicious}</Badge>
              <Badge variant="destructive">{entry.malicious}</Badge>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
