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
  getHealth,
  getScanResults,
  getSettings,
  type HealthResponse,
  type HistoryEntry,
  type ScanMode,
  type ScanResults,
  type ScanStatus,
} from "@/lib/api";

const MAX_HEALTH_RETRIES = 30;

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

  const loadSettings = useCallback(async () => {
    try {
      const settings = await getSettings();
      setDefaultPath(settings.default_scan_path);
      setDefaultMode(settings.default_scan_mode);
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
        return <StartupPage />;
      case "services":
        return <ServicesPage />;
      case "results":
        return <ResultsPage results={results} />;
      case "history":
        return <HistoryPage onSelectEntry={handleHistorySelect} />;
      case "settings":
        return <SettingsPage />;
      default:
        return null;
    }
  };

  const sidebarActivePage: AppPage =
    page === "results" ? "scan" : page;

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
