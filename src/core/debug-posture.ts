import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

export type DebugPostureStatus = "exposed" | "not-observed" | "unknown";

export interface DebugPostureCheck {
  readonly id:
    | "node-cli-inspector-exposure"
    | "chromium-remote-debugging-exposure"
    | "macos-entitlements-debug-posture"
    | "android-manifest-debuggable-posture";
  readonly platform: "cross-platform" | "macos" | "android";
  readonly status: DebugPostureStatus;
  readonly observedConfig: string;
  readonly restrictedChannel: string;
  readonly remediation: string;
}

export interface ProductionDebugPostureReport {
  readonly targetPath: string;
  readonly overallPosture: "exposed" | "not-observed" | "unknown";
  readonly checks: readonly DebugPostureCheck[];
  readonly runtimeBoundaryContract: {
    readonly shadowObjectsClassification: "decorative-deception-signal";
    readonly absenceOfRuntimeMarkersImpliesNoDebugger: false;
    readonly blocksFridaOrGdbWithLocalPrivileges: false;
    readonly blocksRuntimeStateRecovery: false;
    readonly secretStorageGuidance: string;
  };
}

export interface InspectDebugPostureOptions {
  readonly targetDir: string;
  readonly packageJsonPath?: string;
  readonly envFilePath?: string;
  readonly macosEntitlementsPath?: string;
  readonly androidManifestPath?: string;
}

/**
 * Read-only production debug exposure inspector (Issue #19).
 *
 * Inspects authorized local build/deployment configuration files to identify
 * unnecessary debug/inspector entry points (`--inspect`, `--remote-debugging-port`,
 * `com.apple.security.get-task-allow`, `android:debuggable="true"`).
 *
 * Never probes network ports, never attaches to processes, and never claims that
 * client-side JS markers can block Frida/GDB/CDP when the observer holds OS privileges.
 */
export function inspectProductionDebugPosture(
  options: InspectDebugPostureOptions,
): ProductionDebugPostureReport {
  const rootDir = resolve(options.targetDir);
  const pkgPath = options.packageJsonPath
    ? resolve(options.packageJsonPath)
    : join(rootDir, "package.json");
  const envPath = options.envFilePath
    ? resolve(options.envFilePath)
    : join(rootDir, ".env.production");
  const entitlementsPath = options.macosEntitlementsPath
    ? resolve(options.macosEntitlementsPath)
    : join(rootDir, "entitlements.plist");
  const androidManifestPath = options.androidManifestPath
    ? resolve(options.androidManifestPath)
    : join(rootDir, "AndroidManifest.xml");

  const checks: DebugPostureCheck[] = [];

  // 1. Node CLI inspector & NODE_OPTIONS check
  {
    const sources: string[] = [];
    const exposedFlags: string[] = [];

    if (existsSync(pkgPath) && statSync(pkgPath).isFile()) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
          scripts?: Record<string, string>;
        };
        if (pkg.scripts && typeof pkg.scripts === "object") {
          for (const [name, cmd] of Object.entries(pkg.scripts)) {
            if (typeof cmd !== "string") continue;
            // Focus on production/start/serve/pack scripts or all scripts
            if (/(^|[\s"'])(--inspect(?:-brk|-port)?|ELECTRON_RUN_AS_NODE=1)\b/.test(cmd)) {
              exposedFlags.push(`package.json#scripts.${name}: "${cmd}"`);
            }
          }
          sources.push("package.json#scripts");
        }
      } catch {
        // Ignore malformed package.json here; status falls back if no valid sources
      }
    }

    if (existsSync(envPath) && statSync(envPath).isFile()) {
      const envText = readFileSync(envPath, "utf8");
      sources.push(".env.production");
      if (/(--inspect(?:-brk|-port)?|ELECTRON_RUN_AS_NODE\s*=\s*1)/.test(envText)) {
        exposedFlags.push(`.env.production contains inspector/run-as-node directive`);
      }
    }

    const status: DebugPostureStatus =
      exposedFlags.length > 0
        ? "exposed"
        : sources.length > 0
          ? "not-observed"
          : "unknown";

    checks.push({
      id: "node-cli-inspector-exposure",
      platform: "cross-platform",
      status,
      observedConfig:
        exposedFlags.length > 0
          ? exposedFlags.join("; ")
          : sources.length > 0
            ? `Inspected ${sources.join(", ")}; no --inspect or ELECTRON_RUN_AS_NODE flags found.`
            : "No package.json or .env.production found to verify Node launch flags.",
      restrictedChannel: "Node.js V8 Inspector WebSocket (--inspect / NODE_OPTIONS)",
      remediation:
        "Remove --inspect, --inspect-brk, and ELECTRON_RUN_AS_NODE=1 from production start scripts and environment files, and disable RunAsNode / EnableNodeCliInspectArguments in Electron fuses.",
    });
  }

  // 2. Chromium / WebView remote debugging port exposure
  {
    const sources: string[] = [];
    const exposedFlags: string[] = [];

    if (existsSync(pkgPath) && statSync(pkgPath).isFile()) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
          scripts?: Record<string, string>;
        };
        if (pkg.scripts && typeof pkg.scripts === "object") {
          for (const [name, cmd] of Object.entries(pkg.scripts)) {
            if (typeof cmd !== "string") continue;
            if (/--remote-debugging-(?:port|pipe|address)|--remote-allow-origins/.test(cmd)) {
              exposedFlags.push(`package.json#scripts.${name}: "${cmd}"`);
            }
          }
          sources.push("package.json#scripts");
        }
      } catch {
        // Ignore
      }
    }

    const status: DebugPostureStatus =
      exposedFlags.length > 0
        ? "exposed"
        : sources.length > 0
          ? "not-observed"
          : "unknown";

    checks.push({
      id: "chromium-remote-debugging-exposure",
      platform: "cross-platform",
      status,
      observedConfig:
        exposedFlags.length > 0
          ? exposedFlags.join("; ")
          : sources.length > 0
            ? `Inspected ${sources.join(", ")}; no --remote-debugging-port flags found.`
            : "No launch configuration found to verify Chromium remote debugging flags.",
      restrictedChannel: "Chrome DevTools Protocol (CDP) HTTP/WebSocket endpoint",
      remediation:
        "Remove --remote-debugging-port and --remote-allow-origins from production launch scripts and BrowserWindow startup switches.",
    });
  }

  // 3. macOS Entitlements / Hardened Runtime debug posture
  {
    if (existsSync(entitlementsPath) && statSync(entitlementsPath).isFile()) {
      const xml = readFileSync(entitlementsPath, "utf8");
      const riskyKeys = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-unsigned-executable-memory",
      ];
      const enabledKeys = riskyKeys.filter((key) => {
        const regex = new RegExp(
          `<key>\\s*${key.replace(/\./g, "\\.")}\\s*</key>\\s*<true\\s*/>`,
          "i",
        );
        return regex.test(xml);
      });

      checks.push({
        id: "macos-entitlements-debug-posture",
        platform: "macos",
        status: enabledKeys.length > 0 ? "exposed" : "not-observed",
        observedConfig:
          enabledKeys.length > 0
            ? `Enabled debug/injection entitlements in ${entitlementsPath}: ${enabledKeys.join(", ")}`
            : `Inspected ${entitlementsPath}; get-task-allow and dyld injection entitlements are not enabled.`,
        restrictedChannel: "macOS task_for_pid / LLDB / Frida attach & DYLD_INSERT_LIBRARIES",
        remediation:
          "Set com.apple.security.get-task-allow, allow-dyld-environment-variables, and disable-library-validation to false (or remove them) in production release entitlements with Hardened Runtime enabled.",
      });
    } else {
      checks.push({
        id: "macos-entitlements-debug-posture",
        platform: "macos",
        status: "unknown",
        observedConfig: "No macOS entitlements.plist provided or discovered in target directory.",
        restrictedChannel: "macOS task_for_pid / LLDB / Frida attach & DYLD_INSERT_LIBRARIES",
        remediation:
          "Provide macosEntitlementsPath to verify that com.apple.security.get-task-allow is omitted in release builds.",
      });
    }
  }

  // 4. Android Manifest debuggable posture
  {
    if (existsSync(androidManifestPath) && statSync(androidManifestPath).isFile()) {
      const xml = readFileSync(androidManifestPath, "utf8");
      const isDebuggable = /android:debuggable\s*=\s*["']true["']/i.test(xml);
      checks.push({
        id: "android-manifest-debuggable-posture",
        platform: "android",
        status: isDebuggable ? "exposed" : "not-observed",
        observedConfig: isDebuggable
          ? `android:debuggable="true" observed in ${androidManifestPath}`
          : `Inspected ${androidManifestPath}; android:debuggable="true" is not set.`,
        restrictedChannel: "Android JDWP / run-as / Frida gadget attach on non-rooted devices",
        remediation:
          "Ensure android:debuggable=\"false\" in release buildTypes in build.gradle / AndroidManifest.xml.",
      });
    } else {
      checks.push({
        id: "android-manifest-debuggable-posture",
        platform: "android",
        status: "unknown",
        observedConfig: "No AndroidManifest.xml provided or discovered in target directory.",
        restrictedChannel: "Android JDWP / run-as / Frida gadget attach on non-rooted devices",
        remediation:
          "Provide androidManifestPath to verify that android:debuggable is false in release builds.",
      });
    }
  }

  const overallPosture: DebugPostureStatus = checks.some((c) => c.status === "exposed")
    ? "exposed"
    : checks.some((c) => c.status === "not-observed")
      ? "not-observed"
      : "unknown";

  return {
    targetPath: rootDir,
    overallPosture,
    checks,
    runtimeBoundaryContract: {
      shadowObjectsClassification: "decorative-deception-signal",
      absenceOfRuntimeMarkersImpliesNoDebugger: false,
      blocksFridaOrGdbWithLocalPrivileges: false,
      blocksRuntimeStateRecovery: false,
      secretStorageGuidance:
        "BLA JavaScript runtime shields cannot guarantee confidentiality of plaintext or decryption keys held by a client process when the observer has OS-level debugging/instrumentation permissions (e.g., Frida, GDB, LLDB, or root/admin access). Keep authoritative access control and long-lived secrets in trusted server or hardware boundaries.",
    },
  };
}
