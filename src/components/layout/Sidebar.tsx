import { History, ScanSearch, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

export type AppPage = "scan" | "history" | "settings" | "results";

interface SidebarProps {
  activePage: AppPage;
  onNavigate: (page: AppPage) => void;
}

const navItems: { id: AppPage; icon: typeof ScanSearch; label: string }[] = [
  { id: "scan", icon: ScanSearch, label: "Scan" },
  { id: "history", icon: History, label: "History" },
  { id: "settings", icon: Settings, label: "Settings" },
];

export function Sidebar({ activePage, onNavigate }: SidebarProps) {
  return (
    <aside className="flex w-16 shrink-0 flex-col items-center gap-2 border-r border-border bg-card py-4">
      {navItems.map(({ id, icon: Icon, label }) => (
        <button
          key={id}
          type="button"
          title={label}
          onClick={() => onNavigate(id)}
          className={cn(
            "flex h-11 w-11 items-center justify-center rounded-lg transition-colors",
            activePage === id
              ? "bg-primary text-primary-foreground"
              : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
          )}
        >
          <Icon className="h-5 w-5" />
        </button>
      ))}
    </aside>
  );
}
