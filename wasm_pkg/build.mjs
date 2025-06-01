import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/client.ts", "src/server.ts"],
  bundle: true,
  splitting: true,
  format: "esm",
  outdir: "dist",
  minify: true,
  sourcemap: false,
  target: ["es2024"],
  platform: "neutral",
  external: [],
});
