export async function copyToClipboard(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

export async function openExternalUrl(url: string): Promise<void> {
  if ("__TAURI_INTERNALS__" in window || "__TAURI__" in window) {
    const { open } = await import("@tauri-apps/plugin-shell");
    await open(url);
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

export async function openFileLocation(filePath: string): Promise<void> {
  const normalized = filePath.replace(/\//g, "\\");
  if ("__TAURI_INTERNALS__" in window || "__TAURI__" in window) {
    const { Command } = await import("@tauri-apps/plugin-shell");
    await Command.create("cmd", ["/C", "explorer", `/select,${normalized}`]).spawn();
    return;
  }
  window.open(`file:///${normalized}`, "_blank");
}
