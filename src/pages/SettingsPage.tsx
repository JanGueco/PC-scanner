import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { CircleHelp, Eye, EyeOff, FolderOpen, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { getSettings, updateSettings, type ApiKeySource, type ScanMode } from "@/lib/api";
import { openExternalUrl } from "@/lib/shell";
import { cn, formatScanMode } from "@/lib/utils";

interface SettingsPageProps {
  onSettingsSaved?: () => void;
}

interface ApiKeyFieldProps {
  label: string;
  helpUrl: string;
  helpTooltip: string;
  value: string;
  onChange: (value: string) => void;
  showValue: boolean;
  onToggleShow: () => void;
  disabled: boolean;
  placeholder: string;
  hint: string;
  envDetected?: boolean;
}

function ApiKeyHelpButton({ helpUrl, helpTooltip }: { helpUrl: string; helpTooltip: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-6 w-6 shrink-0 p-0 text-muted-foreground hover:text-foreground"
          aria-label={helpTooltip}
          onClick={() => void openExternalUrl(helpUrl)}
        >
          <CircleHelp className="h-3.5 w-3.5" />
        </Button>
      </TooltipTrigger>
      <TooltipContent side="top">{helpTooltip}</TooltipContent>
    </Tooltip>
  );
}

function ApiKeyField({
  label,
  helpUrl,
  helpTooltip,
  value,
  onChange,
  showValue,
  onToggleShow,
  disabled,
  placeholder,
  hint,
  envDetected,
}: ApiKeyFieldProps) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5">
        <label className="text-sm font-medium">{label}</label>
        <ApiKeyHelpButton helpUrl={helpUrl} helpTooltip={helpTooltip} />
      </div>
      <div className="relative">
        <Input
          type={showValue ? "text" : "password"}
          placeholder={placeholder}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          disabled={disabled}
          className="pr-10"
        />
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="absolute top-0 right-0 h-full px-3"
          disabled={disabled}
          onClick={onToggleShow}
        >
          {showValue ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        {typeof envDetected === "boolean" ? (
          envDetected ? "Detected in backend/.env" : "Not set in backend/.env"
        ) : (
          hint
        )}
      </p>
    </div>
  );
}

export function SettingsPage({ onSettingsSaved }: SettingsPageProps) {
  const [defaultPath, setDefaultPath] = useState("C:\\");
  const [mode, setMode] = useState<ScanMode>("fast");
  const [apiKeySource, setApiKeySource] = useState<ApiKeySource>("env");
  const [envKeysDetected, setEnvKeysDetected] = useState({
    malwarebazaar: false,
    virustotal: false,
  });
  const [mbKey, setMbKey] = useState("");
  const [vtKey, setVtKey] = useState("");
  const [mbKeyMasked, setMbKeyMasked] = useState("");
  const [vtKeyMasked, setVtKeyMasked] = useState("");
  const [showMbKey, setShowMbKey] = useState(false);
  const [showVtKey, setShowVtKey] = useState(false);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  const envAvailable = envKeysDetected.malwarebazaar || envKeysDetected.virustotal;
  const useEnvSource = apiKeySource === "env";

  useEffect(() => {
    getSettings()
      .then((settings) => {
        setDefaultPath(settings.default_scan_path);
        setMode(settings.default_scan_mode);
        setApiKeySource(settings.api_key_source);
        setEnvKeysDetected(settings.env_keys_detected);
        setMbKeyMasked(settings.malwarebazaar_auth_key);
        setVtKeyMasked(settings.virustotal_api_key);
        setMbKey(
          settings.api_key_source === "app" && !settings.malwarebazaar_auth_key.includes("*")
            ? settings.malwarebazaar_auth_key
            : "",
        );
        setVtKey(
          settings.api_key_source === "app" && !settings.virustotal_api_key.includes("*")
            ? settings.virustotal_api_key
            : "",
        );
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!envAvailable && apiKeySource === "env") {
      setApiKeySource("app");
    }
  }, [envAvailable, apiKeySource]);

  const handleBrowse = async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      defaultPath: defaultPath || "C:\\",
    });
    if (selected && typeof selected === "string") {
      setDefaultPath(selected);
    }
  };

  const handleSave = async () => {
    const payload: Record<string, string | ScanMode | ApiKeySource> = {
      default_scan_path: defaultPath,
      default_scan_mode: mode,
      api_key_source: envAvailable ? apiKeySource : "app",
    };

    if (payload.api_key_source === "app") {
      if (mbKey && !mbKey.includes("*")) {
        payload.malwarebazaar_auth_key = mbKey;
      }
      if (vtKey && !vtKey.includes("*")) {
        payload.virustotal_api_key = vtKey;
      }
    }

    const updated = await updateSettings(payload);
    setApiKeySource(updated.api_key_source);
    setEnvKeysDetected(updated.env_keys_detected);
    setMbKeyMasked(updated.malwarebazaar_auth_key);
    setVtKeyMasked(updated.virustotal_api_key);
    onSettingsSaved?.();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  if (loading) {
    return <div className="text-muted-foreground">Loading settings...</div>;
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="mx-auto flex max-w-xl flex-col gap-6">
        <div>
          <h1 className="text-2xl font-semibold">Settings</h1>
          <p className="text-sm text-muted-foreground">Configure default scan behavior and API keys</p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Scan Defaults</CardTitle>
            <CardDescription>Applied when starting a new scan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-2">
              <label className="text-sm font-medium">Default Scan Directory</label>
              <div className="flex gap-2">
                <Input
                  value={defaultPath}
                  onChange={(event) => setDefaultPath(event.target.value)}
                  className="font-mono"
                />
                <Button variant="outline" onClick={handleBrowse}>
                  <FolderOpen className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">Default Scan Mode</p>
                <p className="text-xs text-muted-foreground">
                  {mode === "fast"
                    ? "Fast (all CPU threads)"
                    : "Background (2 threads, PC stays responsive)"}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm">{formatScanMode("fast")}</span>
                <Switch
                  checked={mode === "background"}
                  onCheckedChange={(checked) => setMode(checked ? "background" : "fast")}
                />
                <span className="text-sm">{formatScanMode("background")}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>API Keys</CardTitle>
            <CardDescription>Threat intelligence service credentials</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium">API Key Source</p>
                <p className="text-xs text-muted-foreground">
                  {useEnvSource
                    ? "Using keys from backend/.env"
                    : "Using keys saved in app settings"}
                </p>
                {!envAvailable && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    No keys found in backend/.env — enter keys below instead.
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                <span
                  className={cn(
                    "text-sm",
                    useEnvSource ? "font-medium text-foreground" : "text-muted-foreground",
                    !envAvailable && "opacity-50",
                  )}
                >
                  .env file
                </span>
                <Switch
                  checked={!useEnvSource}
                  disabled={!envAvailable}
                  onCheckedChange={(checked) => setApiKeySource(checked ? "app" : "env")}
                />
                <span
                  className={cn(
                    "text-sm",
                    !useEnvSource ? "font-medium text-foreground" : "text-muted-foreground",
                  )}
                >
                  Enter here
                </span>
              </div>
            </div>

            <ApiKeyField
              label="MalwareBazaar Auth-Key"
              helpUrl="https://auth.abuse.ch/"
              helpTooltip="Open auth.abuse.ch to register and get a free Auth-Key"
              value={useEnvSource ? mbKeyMasked : mbKey}
              onChange={setMbKey}
              showValue={showMbKey}
              onToggleShow={() => setShowMbKey((value) => !value)}
              disabled={useEnvSource}
              placeholder={
                useEnvSource ? "Loaded from backend/.env" : "Enter your MalwareBazaar Auth-Key"
              }
              hint="Required for full filename cache and hash verification"
              envDetected={useEnvSource ? envKeysDetected.malwarebazaar : undefined}
            />

            <ApiKeyField
              label="VirusTotal API Key"
              helpUrl="https://www.virustotal.com/gui/my-apikey"
              helpTooltip="Open VirusTotal to create an account and copy your API key"
              value={useEnvSource ? vtKeyMasked : vtKey}
              onChange={setVtKey}
              showValue={showVtKey}
              onToggleShow={() => setShowVtKey((value) => !value)}
              disabled={useEnvSource}
              placeholder={
                useEnvSource ? "Loaded from backend/.env" : "Enter your VirusTotal API key"
              }
              hint="Free tier: 4 requests/minute · 500 requests/day. Personal use only."
              envDetected={useEnvSource ? envKeysDetected.virustotal : undefined}
            />
          </CardContent>
        </Card>

        <Button onClick={handleSave}>
          <Save className="h-4 w-4" />
          {saved ? "Saved!" : "Save Settings"}
        </Button>
      </div>
    </TooltipProvider>
  );
}
