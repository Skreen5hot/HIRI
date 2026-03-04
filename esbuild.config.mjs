import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/demo/entry.ts"],
  bundle: true,
  outfile: "dist/demo.js",
  format: "esm",
  platform: "browser",
  target: "es2022",
  // Externalize oxigraph — loaded separately via import map in HTML
  // because its WASM needs explicit async init() before use.
  external: ["oxigraph"],
  sourcemap: true,
  minify: false, // keep readable for demo transparency
});

console.log("Built dist/demo.js");

// Copy static site files to dist/
import { readdirSync, copyFileSync } from "fs";
for (const file of readdirSync("site")) {
  copyFileSync(`site/${file}`, `dist/${file}`);
}
console.log("Copied site/ → dist/");
