/**
 * PhishGuard — Webpack Build Configuration
 * Author: Akshay | https://akshay.fruvvi.com
 */

const path = require("path");
const CopyPlugin = require("copy-webpack-plugin");

module.exports = (env, argv) => {
  const isDev = argv.mode === "development";

  return {
    entry: {
      background: "./src/background/index.ts",
      content:    "./src/content/index.ts",
      popup:      "./src/popup/popup.ts",
    },

    output: {
      path: path.resolve(__dirname, "dist"),
      filename: "[name].js",
      clean: true,
    },

    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: "ts-loader",
          exclude: /node_modules/,
        },
        {
          test: /\.css$/,
          use: ["style-loader", "css-loader"],
        },
      ],
    },

    resolve: {
      extensions: [".ts", ".tsx", ".js"],
      alias: {
        "@": path.resolve(__dirname, "src"),
      },
      fallback: {
        fs:     false,
        path:   false,
        crypto: false,
      },
    },

    plugins: [
      new CopyPlugin({
        patterns: [
          { from: "public/manifest.json",  to: "manifest.json" },
          { from: "public/popup.html",      to: "popup.html" },
          { from: "public/options.html",    to: "options.html" },
          {
            from: "public/icons",
            to:   "icons",
            noErrorOnMissing: true,
          },
          {
            from: "public/models",
            to:   "models",
            noErrorOnMissing: true,
          },
          // ONNX Runtime WASM files — required for local inference
          {
            from: "node_modules/onnxruntime-web/dist/*.wasm",
            to:   "ort-wasm/[name][ext]",
          },
          {
            from: "node_modules/onnxruntime-web/dist/ort.js",
            to:   "ort-wasm/ort.js",
          },
        ],
      }),
    ],

    devtool: isDev ? "inline-source-map" : false,

    optimization: {
      minimize: !isDev,
    },

    performance: {
      hints: false,
    },
  };
};