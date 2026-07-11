import axios from "axios";

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

export interface AppSettings {
  default_scan_path: string;
  default_scan_mode: ScanMode;
  malwarebazaar_auth_key: string;
  virustotal_api_key: string;
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

export interface ServiceScanEntry extends ServiceEntry {
  flagged: boolean;
  sha256: string | null;
  database: string | null;
  match_type: "name" | "sha256" | null;
}

export interface ServicesScanResponse {
  total: number;
  flagged: number;
  entries: ServiceScanEntry[];
}

const api = axios.create({
  baseURL: "http://127.0.0.1:8787",
  timeout: 10000,
});

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

export async function scanServices(): Promise<ServicesScanResponse> {
  const { data } = await api.post<ServicesScanResponse>("/services/scan", undefined, {
    timeout: 300000,
  });
  return data;
}

export default api;
