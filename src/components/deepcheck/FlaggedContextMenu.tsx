import { useEffect } from "react";
import { Copy, ExternalLink, FolderOpen, Info, Search } from "lucide-react";
import { cn } from "@/lib/utils";

export interface ContextMenuItem {
  id: string;
  label: string;
  icon: "search" | "copy-hash" | "copy-path" | "open-location" | "details";
  onSelect: () => void;
  disabled?: boolean;
}

interface FlaggedContextMenuProps {
  open: boolean;
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}

const iconMap = {
  search: Search,
  "copy-hash": Copy,
  "copy-path": Copy,
  "open-location": FolderOpen,
  details: Info,
};

export function FlaggedContextMenu({ open, x, y, items, onClose }: FlaggedContextMenuProps) {
  useEffect(() => {
    if (!open) return undefined;

    const handlePointer = () => onClose();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };

    window.addEventListener("pointerdown", handlePointer);
    window.addEventListener("keydown", handleKey);
    window.addEventListener("scroll", handlePointer, true);

    return () => {
      window.removeEventListener("pointerdown", handlePointer);
      window.removeEventListener("keydown", handleKey);
      window.removeEventListener("scroll", handlePointer, true);
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed z-50 min-w-56 rounded-md border border-border bg-card py-1 shadow-lg"
      style={{ left: x, top: y }}
      onPointerDown={(event) => event.stopPropagation()}
      onContextMenu={(event) => event.preventDefault()}
    >
      {items.map((item) => {
        const Icon = iconMap[item.icon];
        return (
          <button
            key={item.id}
            type="button"
            disabled={item.disabled}
            className={cn(
              "flex w-full items-center gap-2 px-3 py-2 text-left text-sm",
              "hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-50",
            )}
            onClick={() => {
              item.onSelect();
              onClose();
            }}
          >
            <Icon className="h-4 w-4 text-muted-foreground" />
            <span>{item.label}</span>
          </button>
        );
      })}
    </div>
  );
}

export function ContextMenuHint() {
  return null;
}

export { ExternalLink };
