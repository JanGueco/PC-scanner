import { useCallback, useEffect, useState } from "react";
import {
  deepCheck,
  DeepCheckError,
  toDeepCheckState,
  type DeepCheckState,
} from "@/lib/deepcheck";

interface UseDeepCheckActionOptions {
  storageKey: string;
  type: "file" | "service";
  identifier: string;
  sha256: string | null;
  path?: string;
  state: DeepCheckState | null;
  onUpdate: (key: string, state: DeepCheckState) => void;
}

export function useDeepCheckAction({
  storageKey,
  type,
  identifier,
  sha256,
  path,
  state,
  onUpdate,
}: UseDeepCheckActionOptions) {
  const [checking, setChecking] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [rateLimitSeconds, setRateLimitSeconds] = useState(0);

  useEffect(() => {
    if (rateLimitSeconds <= 0) return undefined;

    const timer = window.setInterval(() => {
      setRateLimitSeconds((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => window.clearInterval(timer);
  }, [rateLimitSeconds]);

  const runDeepCheck = useCallback(async () => {
    setChecking(true);
    setErrorMessage("");

    try {
      const response = await deepCheck({
        type,
        identifier,
        sha256: sha256 ?? undefined,
        path: path || undefined,
      });
      onUpdate(storageKey, toDeepCheckState(response));
    } catch (error) {
      if (error instanceof DeepCheckError) {
        setErrorMessage(error.message);
        if (error.code === "rate_limited" && error.retryAfterSeconds) {
          setRateLimitSeconds(error.retryAfterSeconds);
        }
      } else {
        setErrorMessage("Deep check failed. Please try again.");
      }
    } finally {
      setChecking(false);
    }
  }, [storageKey, type, identifier, sha256, path, onUpdate]);

  return {
    checking,
    errorMessage,
    rateLimitSeconds,
    runDeepCheck,
    deepCheckState: state,
  };
}
