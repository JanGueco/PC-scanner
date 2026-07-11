import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { getSettings, updateSettings, type ScanMode } from "@/lib/api";
import { formatScanMode } from "@/lib/utils";

export function SettingsPage() {
  const [defaultPath, setDefaultPath] = useState("C:\\");
  const [mode, setMode] = useState<ScanMode>("fast");
  const [mbKey, setMbKey] = useState("");
  const [vtKey, setVtKey] = useState("");
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSettings()
      .then((s) => {
        setDefaultPath(s.default_scan_path);
        setMode(s.default_scan_mode);
        setMbKey(s.malwarebazaar_auth_key.includes("*") ? "" : s.malwarebazaar_auth_key);
        setVtKey("");
      })
      .finally(() => setLoading(false));
  }, []);

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
    const payload: Record<string, string | ScanMode> = {
      default_scan_path: defaultPath,
      default_scan_mode: mode,
    };
    if (mbKey && !mbKey.includes("*")) {
      payload.malwarebazaar_auth_key = mbKey;
    }
    await updateSettings(payload);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  if (loading) {
    return <div className="text-muted-foreground">Loading settings...</div>;
  }

  return (
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
                onChange={(e) => setDefaultPath(e.target.value)}
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
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">MalwareBazaar Auth-Key</label>
            <Input
              type="password"
              placeholder="Get free key at auth.abuse.ch"
              value={mbKey}
              onChange={(e) => setMbKey(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Required for full filename cache and hash verification
            </p>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-muted-foreground">
              VirusTotal API Key
            </label>
            <Input disabled placeholder="Coming soon" value={vtKey} onChange={() => {}} />
          </div>
        </CardContent>
      </Card>

      <Button onClick={handleSave}>
        <Save className="h-4 w-4" />
        {saved ? "Saved!" : "Save Settings"}
      </Button>
    </div>
  );
}
