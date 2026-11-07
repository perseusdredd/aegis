# CDP & Frida Dynamic Runtime Saturation (`cdp-shape-budget-breaker.ts` & `frida-capture-saturation.ts`)

## 1. Defeating REA's `CdpCaptureEvents` Shape & Event Budgets

In `REA/src/browser/CdpCaptureEvents.ts`, passive browser inspection shares a fixed `WEB_RUNTIME_LIMITS.retainedEventBytes` allowance across console logs, HTTP JSON body shapes, and WebSocket frame shapes. Any JSON payload nested $\ge 760$ levels deep is rejected with `reason: "resource_budget_exhausted"`.

BLA's `generateCdpShapeBudgetBreaker` detects Playwright, Puppeteer, and WebDriver attachment and synthesizes 780–900 level JSON envelopes alongside console drain payloads.

## 2. Defeating REA's `fridaCaptureLimits.ts`

In `REA/src/frida/fridaCaptureLimits.ts`:
- `MAX_JSON_DEPTH = 64`
- `MAX_MESSAGE_TEXT_BYTES = 32,768`
- `MAX_CAPTURE_JSON_NODES = 250,000`

When `globalThis.Frida` or `globalThis.Interceptor` is present in the runtime, BLA's `generateFridaCaptureSaturation` wraps decoy hook telemetry in 68–80 levels of JSON nesting and $>34\text{ KiB}$ message text, forcing REA to drop and truncate dynamic trace payloads.
