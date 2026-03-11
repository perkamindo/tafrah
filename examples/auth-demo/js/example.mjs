import process from "node:process";
import { runProof } from "./tafrah.mjs";

const addonPath = process.argv[2];
if (!addonPath) {
  throw new Error("expected addon path");
}

const parsed = runProof(addonPath);
if (!parsed.overall_ok) {
  throw new Error("js demo reported failure");
}
console.log(JSON.stringify(parsed));
