/**
 * Counter-Showcase #2: Notion Electron Clipboard Bridge (Preload + Main IPC)
 * Reference: REA Official Showcase (`https://rea.tools/showcase/notion/`)
 *
 * Run pre-flight audit:
 *   npx bla-shield audit examples/notion-electron-bridge/electron-bridge.js
 * Protect against REA:
 *   npx bla-shield protect examples/notion-electron-bridge/electron-bridge.js
 */

const { contextBridge, ipcRenderer, ipcMain } = require("electron");

function setupPreloadClipboardBridge() {
  contextBridge.exposeInMainWorld("notionClipboard", {
    readRichBlocks: () => ipcRenderer.invoke("notion:clipboard:read-rich"),
    writeRichBlocks: (blocks) => ipcRenderer.invoke("notion:clipboard:write-rich", blocks),
    syncSelection: (range) => ipcRenderer.send("notion:clipboard:selection-sync", range),
  });
}

function setupMainClipboardHandlers(blockStore) {
  ipcMain.handle("notion:clipboard:read-rich", async () => {
    await fetch("/api/v1/clipboard/blocks");
    return blockStore.get("blocks") || [];
  });

  ipcMain.handle("notion:clipboard:write-rich", async (_event, blocks) => {
    blockStore.set("blocks", blocks);
    return { saved: true, count: Array.isArray(blocks) ? blocks.length : 0 };
  });
}

module.exports = {
  setupPreloadClipboardBridge,
  setupMainClipboardHandlers,
};
