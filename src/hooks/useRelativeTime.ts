import { useEffect, useState } from "react";
import { formatTimeAgo } from "@/lib/utils";

export function useRelativeTime(timestamp: number | null): string {
  const [, setTick] = useState(0);

  useEffect(() => {
    if (!timestamp) return undefined;

    const interval = window.setInterval(() => {
      setTick((value) => value + 1);
    }, 30_000);

    return () => window.clearInterval(interval);
  }, [timestamp]);

  return formatTimeAgo(timestamp);
}
