import { useCallback, useEffect, useState } from "react";
import { AppShell } from "@/components/layout/AppShell";
import { BackendLoadingOverlay } from "@/components/layout/BackendLoadingOverlay";
import type { AppPage } from "@/components/layout/Sidebar";
import { HistoryPage } from "@/pages/HistoryPage";
import { OverallPage } from "@/pages/OverallPage";
import { ResultsPage } from "@/pages/ResultsPage";
import { ScanPage } from "@/pages/ScanPage";
import { ServicesPage } from "@/pages/ServicesPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { StartupPage } from "@/pages/StartupPage";
import {
  getApiErrorMessage,
  getHealth,
  getScanResults,
  getServicesList,
  getSettings,
  getStartupList,
  scanServices,
  type HealthResponse,
  type HistoryEntry,
  type ScanMode,
  type ScanResults,
  type ScanStatus,
  type ServiceScanEntry,
  type ServicesScanStatus,
  type StartupItem,
} from "@/lib/api";
import type { DeepCheckState } from "@/lib/deepcheck";

const MAX_HEALTH_RETRIES = 30;

function hasConfiguredVtKey(maskedKey: string): boolean {
  return maskedKey.trim().length > 0;
}

function toScanEntries(
  entries: Awaited<ReturnType<typeof getServicesList>>,
): ServiceScanEntry[] {
  return entries.map((entry) => ({
    ...entry,
    flagged: false,
    flag_label: null,
    sha256: null,
    database: null,
    match_type: null,
    signature: null,
  }));
}

function App() {
  const [page, setPage] = useState<AppPage>("overall");
  const [backendReady, setBackendReady] = useState(false);
  const [healthFailed, setHealthFailed] = useState(false);
  const [healthMessage, setHealthMessage] = useState("Connecting to scanner backend...");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [defaultPath, setDefaultPath] = useState("C:\\");
  const [defaultMode, setDefaultMode] = useState<ScanMode>("fast");

  const [startupItems, setStartupItems] = useState<StartupItem[]>([]);
  const [startupLoaded, setStartupLoaded] = useState(false);
  const [startupLoading, setStartupLoading] = useState(false);
  const [startupError, setStartupError] = useState("");

  const [services, setServices] = useState<ServiceScanEntry[]>([]);
  const [servicesListLoaded, setServicesListLoaded] = useState(false);
  const [servicesListLoading, setServicesListLoading] = useState(false);
  const [servicesListError, setServicesListError] = useState("");
  const [servicesScanStatus, setServicesScanStatus] = useState<
    "never" | "scanning" | "complete"
  >("never");
  const [servicesLastScannedAt, setServicesLastScannedAt] = useState<number | null>(null);
  const [servicesScanProgress, setServicesScanProgress] = useState<ServicesScanStatus | null>(null);
  const [servicesScanError, setServicesScanError] = useState("");

  const [hasVtApiKey, setHasVtApiKey] = useState(false);
  const [fileDeepChecks, setFileDeepChecks] = useState<Record<string, DeepCheckState>>({});
  const [serviceDeepChecks, setServiceDeepChecks] = useState<Record<string, DeepCheckState>>({});

  const loadSettings = useCallback(async () => {
    try {
      const settings = await getSettings();
      setDefaultPath(settings.default_scan_path);
      setDefaultMode(settings.default_scan_mode);
      setHasVtApiKey(hasConfiguredVtKey(settings.virustotal_api_key));
    } catch {
      // Settings unavailable until backend is ready
    }
  }, []);

  const checkHealth = useCallback(async () => {
    setHealthFailed(false);
    setHealthMessage("Connecting to scanner backend...");
    for (let attempt = 0; attempt < MAX_HEALTH_RETRIES; attempt += 1) {
      try {
        const response = await getHealth();
        setHealth(response);
        setBackendReady(true);
        await loadSettings();
        return;
      } catch {
        setHealthMessage(`Waiting for backend... (${attempt + 1}/${MAX_HEALTH_RETRIES})`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    setHealthFailed(true);
    setHealthMessage("Could not connect to the FastAPI backend on port 8787.");
  }, [loadSettings]);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  const ensureStartupLoaded = useCallback(async () => {
    if (startupLoaded || startupLoading) return;

    setStartupLoading(true);
    setStartupError("");
    try {
      const data = await getStartupList();
      setStartupItems(data);
      setStartupLoaded(true);
    } catch {
      setStartupError("Failed to load startup items.");
      setStartupItems([]);
    } finally {
      setStartupLoading(false);
    }
  }, [startupLoaded, startupLoading]);

  const refreshStartup = useCallback(async () => {
    setStartupLoading(true);
    setStartupError("");
    try {
      const data = await getStartupList();
      setStartupItems(data);
      setStartupLoaded(true);
    } catch {
      setStartupError("Failed to load startup items.");
      setStartupItems([]);
    } finally {
      setStartupLoading(false);
    }
  }, []);

  const ensureServicesLoaded = useCallback(async () => {
    if (servicesListLoaded || servicesListLoading) return;

    setServicesListLoading(true);
    setServicesListError("");
    try {
      const data = await getServicesList();
      setServices((current) => (current.length > 0 ? current : toScanEntries(data)));
      setServicesListLoaded(true);
    } catch (err) {
      setServicesListError(getApiErrorMessage(err, "Failed to load Windows services."));
      if (services.length === 0) {
        setServices([]);
      }
    } finally {
      setServicesListLoading(false);
    }
  }, [services.length, servicesListLoaded, servicesListLoading]);

  const handleServicesScanStart = useCallback(() => {
    setServicesScanStatus("scanning");
    setServicesScanError("");
    setServicesScanProgress(null);
  }, []);

  const handleServicesScan = useCallback(async () => {
    handleServicesScanStart();

    try {
      const result = await scanServices(setServicesScanProgress);
      setServices(result.entries);
      setServicesScanStatus("complete");
      setServicesLastScannedAt(Date.now());
      setServicesListLoaded(true);
      setServicesListError("");
    } catch (err) {
      setServicesScanError(
        getApiErrorMessage(err, "Failed to scan services against the threat database."),
      );
      setServicesScanStatus(servicesLastScannedAt ? "complete" : "never");
    } finally {
      setServicesScanProgress(null);
    }
  }, [servicesLastScannedAt, handleServicesScanStart]);

  const handleStartupFetched = useCallback((items: StartupItem[]) => {
    setStartupItems(items);
    setStartupLoaded(true);
    setStartupError("");
  }, []);

  const handleServicesScanComplete = useCallback((entries: ServiceScanEntry[]) => {
    setServices(entries);
    setServicesScanStatus("complete");
    setServicesLastScannedAt(Date.now());
    setServicesListLoaded(true);
    setServicesListError("");
    setServicesScanError("");
    setServicesScanProgress(null);
  }, []);

  const handleScanComplete = async () => {
    try {
      const scanResults = await getScanResults();
      setResults(scanResults);
      setPage("results");
    } catch {
      setPage("results");
    }
  };

  const handleOverallComplete = (scanResults: ScanResults) => {
    setResults(scanResults);
    setPage("results");
  };

  const handleHistorySelect = (entry: HistoryEntry) => {
    setResults(entry.results);
    setPage("results");
  };

  const handleUpdateFileDeepCheck = useCallback((path: string, state: DeepCheckState) => {
    setFileDeepChecks((current) => ({ ...current, [path]: state }));
  }, []);

  const handleUpdateServiceDeepCheck = useCallback((serviceName: string, state: DeepCheckState) => {
    setServiceDeepChecks((current) => ({ ...current, [serviceName]: state }));
  }, []);

  const renderPage = () => {
    switch (page) {
      case "overall":
        return (
          <OverallPage
            defaultPath={defaultPath}
            defaultMode={defaultMode}
            backendReady={backendReady}
            onScanComplete={handleOverallComplete}
            onStatusChange={setScanStatus}
            onStartupFetched={handleStartupFetched}
            onServicesScanStart={handleServicesScanStart}
            onServicesScanProgress={setServicesScanProgress}
            onServicesScanComplete={handleServicesScanComplete}
          />
        );
      case "scan":
        return (
          <ScanPage
            defaultPath={defaultPath}
            defaultMode={defaultMode}
            backendReady={backendReady}
            onScanComplete={handleScanComplete}
            onStatusChange={setScanStatus}
          />
        );
      case "startup":
        return (
          <StartupPage
            items={startupItems}
            loaded={startupLoaded}
            loading={startupLoading}
            error={startupError}
            onEnsureLoaded={ensureStartupLoaded}
            onRefresh={refreshStartup}
          />
        );
      case "services":
        return (
          <ServicesPage
            services={services}
            listLoading={servicesListLoading}
            listLoaded={servicesListLoaded}
            listError={servicesListError}
            scanStatus={servicesScanStatus}
            lastScannedAt={servicesLastScannedAt}
            scanProgress={servicesScanProgress}
            scanError={servicesScanError}
            hasVtApiKey={hasVtApiKey}
            serviceDeepChecks={serviceDeepChecks}
            onEnsureLoaded={ensureServicesLoaded}
            onScan={handleServicesScan}
            onUpdateServiceDeepCheck={handleUpdateServiceDeepCheck}
          />
        );
      case "results":
        return (
          <ResultsPage
            results={results}
            hasVtApiKey={hasVtApiKey}
            fileDeepChecks={fileDeepChecks}
            onUpdateFileDeepCheck={handleUpdateFileDeepCheck}
          />
        );
      case "history":
        return <HistoryPage onSelectEntry={handleHistorySelect} />;
      case "settings":
        return <SettingsPage onSettingsSaved={loadSettings} />;
      default:
        return null;
    }
  };

  const sidebarActivePage: AppPage = page === "results" ? "scan" : page;

  if (!backendReady) {
    return (
      <BackendLoadingOverlay
        message={healthMessage}
        failed={healthFailed}
        onRetry={checkHealth}
      />
    );
  }

  return (
    <AppShell
      activePage={sidebarActivePage}
      onNavigate={setPage}
      health={health}
      scanStatus={scanStatus}
      backendReady={backendReady}
    >
      {renderPage()}
    </AppShell>
  );
}

export default App;
