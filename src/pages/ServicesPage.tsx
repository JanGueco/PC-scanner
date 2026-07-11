import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Cpu, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getServicesList,
  scanServices,
  type ServiceScanEntry,
} from "@/lib/api";
import { truncatePath } from "@/lib/utils";

const PAGE_SIZE = 50;

function ServiceRow({ service }: { service: ServiceScanEntry }) {
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
        <TableCell className="font-medium">{service.display_name}</TableCell>
        <TableCell>{service.status}</TableCell>
        <TableCell>{service.start_type}</TableCell>
        <TableCell className="font-mono text-xs">
          {truncatePath(service.executable_path || "—", 50)}
        </TableCell>
        <TableCell>
          {service.flagged ? (
            <Badge variant="warning">Review Recommended</Badge>
          ) : null}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30">
            <div className="space-y-2 py-2 pl-8 text-sm">
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
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

export function ServicesPage() {
  const [services, setServices] = useState<ServiceScanEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [showFlaggedOnly, setShowFlaggedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const [scanned, setScanned] = useState(false);

  const loadServices = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getServicesList();
      setServices(
        data.map((entry) => ({
          ...entry,
          flagged: false,
          sha256: null,
          database: null,
          match_type: null,
        })),
      );
      setScanned(false);
      setPage(1);
    } catch {
      setError("Failed to load Windows services.");
      setServices([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadServices();
  }, [loadServices]);

  const handleScan = async () => {
    setScanning(true);
    setError("");
    try {
      const result = await scanServices();
      setServices(result.entries);
      setScanned(true);
      setPage(1);
    } catch {
      setError("Failed to scan services against the threat database.");
    } finally {
      setScanning(false);
    }
  };

  const filtered = useMemo(() => {
    if (!showFlaggedOnly) return services;
    return services.filter((s) => s.flagged);
  }, [services, showFlaggedOnly]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-5 w-5 animate-spin" />
        Loading services...
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Windows Services</h1>
          <p className="text-sm text-muted-foreground">
            Cross-check service executables against the malware database
          </p>
        </div>
        <Button onClick={handleScan} disabled={scanning}>
          {scanning ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Scanning...
            </>
          ) : (
            "Scan Services"
          )}
        </Button>
      </div>

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
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle>
              {filtered.length} Service{filtered.length === 1 ? "" : "s"}
              {scanned && (
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({services.filter((s) => s.flagged).length} flagged for review)
                </span>
              )}
            </CardTitle>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Show flagged only</span>
              <Switch checked={showFlaggedOnly} onCheckedChange={setShowFlaggedOnly} />
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Display Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Start Type</TableHead>
                  <TableHead>Executable Path</TableHead>
                  <TableHead>Flag</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginated.map((service) => (
                  <ServiceRow key={service.name} service={service} />
                ))}
              </TableBody>
            </Table>
            {totalPages > 1 && (
              <div className="flex items-center justify-between text-sm text-muted-foreground">
                <span>
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() => setPage((p) => p - 1)}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= totalPages}
                    onClick={() => setPage((p) => p + 1)}
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
  );
}
