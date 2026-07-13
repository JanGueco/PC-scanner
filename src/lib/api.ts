import axios, { isAxiosError } from "axios";

export type ScanMode = "fast" | "background";
export type ScanState = "idle" | "running" | "completed" | "cancelled" | "error";
export type ThreatStatus = "suspicious" | "malicious";

export interface ScanStatus {
  state: ScanState;
  current: number;
  total: number;
  file_path: string;
  clean: number;
  suspicious: number;
  malicious: number;
  skipped: number;
  workers: number;
  message: string;
}

export interface FlaggedFile {
  file_name: string;
  path: string;
  status: ThreatStatus;
  match_type: "name" | "sha256";
  sha256: string | null;
  database: string | null;
}

export interface ScanSummary {
  total_scanned: number;
  duration_seconds: number;
  clean: number;
  suspicious: number;
  malicious: number;
  skipped: number;
  scan_path: string;
  mode: ScanMode;
}

export interface ScanResults {
  summary: ScanSummary;
  flagged_files: FlaggedFile[];
}

export interface EnvKeyStatus {
  malwarebazaar: boolean;
  virustotal: boolean;
}

export type ApiKeySource = "env" | "app";

export interface AppSettings {
  default_scan_path: string;
  default_scan_mode: ScanMode;
  malwarebazaar_auth_key: string;
  virustotal_api_key: string;
  api_key_source: ApiKeySource;
  env_keys_detected: EnvKeyStatus;
}

export interface HealthResponse {
  status: "ok" | "degraded";
  cache_age_hours: number | null;
  cache_count: number;
  warnings: string[];
}

export interface HistoryEntry {
  id: string;
  timestamp: string;
  scan_path: string;
  mode: ScanMode;
  total_scanned: number;
  duration_seconds: number;
  clean: number;
  suspicious: number;
  malicious: number;
  skipped: number;
  results: ScanResults;
}

export interface StartupItem {
  name: string;
  path: string;
  source: "Registry (HKCU)" | "Registry (HKLM)" | "Startup Folder";
  status: "Enabled";
}

export interface ServiceEntry {
  name: string;
  display_name: string;
  status: "Running" | "Stopped" | "Paused" | "Unknown";
  start_type: "Automatic" | "Manual" | "Disabled" | "Unknown";
  executable_path: string;
}

export interface ServiceSignatureInfo {
  signature_valid: boolean;
  signer: string | null;
  signed_by_microsoft: boolean;
  signature_status: "valid" | "invalid" | "not_signed" | "unverifiable";
  verification_error: string | null;
}

export type ServiceFlagLabel =
  | "third_party"
  | "review"
  | "suspicious_system"
  | "malicious"
  | "unverifiable";

export interface ServiceScanEntry extends ServiceEntry {
  flagged: boolean;
  flag_label: ServiceFlagLabel | null;
  sha256: string | null;
  database: string | null;
  match_type: "name" | "sha256" | null;
  signature: ServiceSignatureInfo | null;
}

export interface ServicesScanResponse {
  total: number;
  flagged: number;
  trusted: number;
  entries: ServiceScanEntry[];
}

export type ServicesScanState = "idle" | "running" | "completed" | "error";

export interface ServicesScanStatus {
  state: ServicesScanState;
  current: number;
  total: number;
  service_name: string;
  flagged: number;
  message: string;
}

const api = axios.create({
  baseURL: "http://127.0.0.1:8787",
  timeout: 10000,
});

export function getApiErrorMessage(error: unknown, fallback: string): string {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }
    if (error.code === "ECONNABORTED") {
      return "Request timed out. The backend may still be busy — try again in a moment.";
    }
    if (error.message) {
      return error.message;
    }
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

export async function getHealth(): Promise<HealthResponse> {
  const { data } = await api.get<HealthResponse>("/health");
  return data;
}

export async function getSettings(): Promise<AppSettings> {
  const { data } = await api.get<AppSettings>("/settings");
  return data;
}

export async function updateSettings(settings: Partial<AppSettings>): Promise<AppSettings> {
  const { data } = await api.put<AppSettings>("/settings", settings);
  return data;
}

export async function startScan(path: string, mode: ScanMode): Promise<void> {
  await api.post("/scan/start", { path, mode });
}

export async function getScanStatus(): Promise<ScanStatus> {
  const { data } = await api.get<ScanStatus>("/scan/status");
  return data;
}

export async function stopScan(): Promise<void> {
  await api.post("/scan/stop");
}

export async function getScanResults(): Promise<ScanResults> {
  const { data } = await api.get<ScanResults>("/scan/results");
  return data;
}

export async function getHistory(): Promise<HistoryEntry[]> {
  const { data } = await api.get<HistoryEntry[]>("/history");
  return data;
}

export async function getHistoryEntry(id: string): Promise<HistoryEntry> {
  const { data } = await api.get<HistoryEntry>(`/history/${id}`);
  return data;
}

export async function getStartupList(): Promise<StartupItem[]> {
  const { data } = await api.get<StartupItem[]>("/startup/list");
  return data;
}

export async function getServicesList(): Promise<ServiceEntry[]> {
  const { data } = await api.get<ServiceEntry[]>("/services/list", { timeout: 120000 });
  return data;
}

export async function startServicesScan(): Promise<void> {
  await api.post("/services/scan/start");
}

export async function getServicesScanStatus(): Promise<ServicesScanStatus> {
  const { data } = await api.get<ServicesScanStatus>("/services/scan/status");
  return data;
}

export async function getServicesScanResults(): Promise<ServicesScanResponse> {
  const { data } = await api.get<ServicesScanResponse>("/services/scan/results", {
    timeout: 120000,
  });
  return data;
}

export async function scanServices(
  onProgress?: (status: ServicesScanStatus) => void,
): Promise<ServicesScanResponse> {
  await startServicesScan();

  while (true) {
    const status = await getServicesScanStatus();
    onProgress?.(status);

    if (status.state === "completed") {
      return getServicesScanResults();
    }
    if (status.state === "error") {
      throw new Error(status.message || "Services scan failed");
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

export default api;
