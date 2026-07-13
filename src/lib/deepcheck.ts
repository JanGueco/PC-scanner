import { isAxiosError } from "axios";
import api from "@/lib/api";

export type VtResult = "clean" | "malicious" | "suspicious" | "undetected";

export interface DeepCheckResponse {
  sha256: string;
  identifier: string;
  result: VtResult;
  detections: number;
  total_engines: number;
  permalink: string;
  checked_at: string;
}

export interface DeepCheckState {
  sha256: string | null;
  vt_result: VtResult | null;
  vt_detections: number | null;
  vt_total_engines: number | null;
  vt_permalink: string | null;
  last_deep_checked: string | null;
}

export type DeepCheckErrorCode =
  | "no_api_key"
  | "rate_limited"
  | "network"
  | "hash_failed"
  | "unknown";

export class DeepCheckError extends Error {
  code: DeepCheckErrorCode;
  retryAfterSeconds?: number;

  constructor(code: DeepCheckErrorCode, message: string, retryAfterSeconds?: number) {
    super(message);
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface DeepCheckRequest {
  sha256?: string;
  type: "file" | "service";
  identifier: string;
  path?: string;
}

export async function deepCheck(request: DeepCheckRequest): Promise<DeepCheckResponse> {
  try {
    const { data } = await api.post<DeepCheckResponse>("/deepcheck", request, {
      timeout: 45_000,
    });
    return data;
  } catch (error) {
    if (isAxiosError(error) && error.response?.data) {
      const payload = error.response.data as {
        error?: string;
        retry_after_seconds?: number;
        detail?: string;
      };

      if (payload.error === "no_api_key") {
        throw new DeepCheckError(
          "no_api_key",
          "Add your VirusTotal API key in Settings to use Deep Check",
        );
      }

      if (payload.error === "rate_limited") {
        throw new DeepCheckError(
          "rate_limited",
          "Rate limit reached. Try again in a few seconds.",
          payload.retry_after_seconds,
        );
      }

      if (error.response.status === 503) {
        throw new DeepCheckError(
          "network",
          payload.detail || "Could not reach VirusTotal. Check your internet connection.",
        );
      }

      if (error.response.status === 400 && payload.detail) {
        throw new DeepCheckError("hash_failed", payload.detail);
      }
    }

    if (isAxiosError(error) && !error.response) {
      throw new DeepCheckError(
        "network",
        "Could not reach VirusTotal. Check your internet connection.",
      );
    }

    throw new DeepCheckError("unknown", "Deep check failed. Please try again.");
  }
}

export function toDeepCheckState(response: DeepCheckResponse): DeepCheckState {
  return {
    sha256: response.sha256,
    vt_result: response.result,
    vt_detections: response.detections,
    vt_total_engines: response.total_engines,
    vt_permalink: response.permalink,
    last_deep_checked: response.checked_at,
  };
}

export function formatDeepCheckDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function vtStatusLabel(result: VtResult): string {
  switch (result) {
    case "clean":
      return "Clean";
    case "malicious":
      return "Malicious";
    case "suspicious":
      return "Suspicious";
    case "undetected":
      return "Unknown";
  }
}

export function vtScanResultText(state: DeepCheckState): string {
  if (!state.vt_result) return "";
  if (state.vt_result === "clean") {
    return `0 / ${state.vt_total_engines ?? 0} engines flagged`;
  }
  if (state.vt_result === "undetected") {
    return "VirusTotal has no record of this file";
  }
  return `${state.vt_detections ?? 0} / ${state.vt_total_engines ?? 0} engines flagged`;
}
