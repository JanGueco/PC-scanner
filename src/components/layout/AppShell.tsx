import type { ReactNode } from "react";
import { Sidebar, type AppPage } from "./Sidebar";
import { StatusBar } from "./StatusBar";
import { TitleBar } from "./TitleBar";
import type { HealthResponse, ScanStatus } from "@/lib/api";

interface AppShellProps {
  activePage: AppPage;
  onNavigate: (page: AppPage) => void;
  health: HealthResponse | null;
  scanStatus: ScanStatus | null;
  backendReady: boolean;
  children: ReactNode;
}

export function AppShell({
  activePage,
  onNavigate,
  health,
  scanStatus,
  backendReady,
  children,
}: AppShellProps) {
  return (
    <div className="flex h-full flex-col bg-background">
      <TitleBar />
      <div className="flex min-h-0 flex-1">
        <Sidebar activePage={activePage} onNavigate={onNavigate} />
        <main className="min-w-0 flex-1 overflow-auto p-6">{children}</main>
      </div>
      <StatusBar health={health} scanStatus={scanStatus} backendReady={backendReady} />
    </div>
  );
}
