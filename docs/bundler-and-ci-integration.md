# Bundler & CI/CD One-Click Defense Integration

## 1. Vite / Rollup / Webpack / esbuild Integration

```ts
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-agents/bundler";

export default defineConfig({
  plugins: [
    blaVitePlugin({
      intensity: "bankrupt",
      enableHoneySourceMaps: true,
    }),
  ],
});
```

## 2. GitHub Actions Post-Build Hardening

Add a single step after `npm run build` in your release workflow:

```yaml
- name: Harden release build against REA (One-Click BLA Blue Shield)
  run: npx -y bla-agents@latest defend ./dist -o ./dist-shielded --manifest
```
