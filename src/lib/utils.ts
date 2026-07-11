import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function truncatePath(path: string, maxLength = 80): string {
  if (path.length <= maxLength) return path;
  const start = Math.floor(maxLength * 0.3);
  const end = Math.floor(maxLength * 0.6);
  return `${path.slice(0, start)}...${path.slice(-end)}`;
}

export function formatScanMode(mode: string): string {
  if (mode === "background" || mode === "thorough") return "Background";
  return "Fast";
}
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  return `${mins}m ${secs}s`;
}

export function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
