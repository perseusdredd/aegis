import { aegisVitePlugin } from "../src/bundler/index.js";

export default {
  plugins: [
    aegisVitePlugin({
      intensity: "bankrupt",
      seed: "enterprise-release-2026",
      enableHoneySourceMaps: true,
    }),
  ],
};
