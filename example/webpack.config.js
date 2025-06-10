import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default {
  target: "node",
  entry: "./server.js",
  output: {
    path: path.resolve(__dirname, "./dist"),
    filename: "server.js",
    module: true,
    library: {
      type: "module",
    },
  },
  resolve: {
    extensions: [".js"],
  },
  module: {
    rules: [
      {
        test: /\.wasm$/,
        type: "webassembly/async",
      },
    ],
  },
  experiments: {
    asyncWebAssembly: true,
    outputModule: true,
  },
  mode: "production",
};
