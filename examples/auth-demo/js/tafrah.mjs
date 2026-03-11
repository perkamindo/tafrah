import { createRequire } from "node:module";

export function runProofJson(addonPath) {
  const require = createRequire(import.meta.url);
  const binding = require(addonPath);
  return binding.runDemoJson();
}

export function runProof(addonPath) {
  return JSON.parse(runProofJson(addonPath));
}
