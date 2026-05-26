/**
 * PhishGuard — Vite Build Configuration
 *
 * Why vite-plugin-web-extension?
 * - Reads manifest.json and auto-discovers all entry points
 * - Handles service worker bundling correctly (module type)
 * - Copies static assets from public/ into dist/
 * - Hot-reload during development
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import webExtension from "vite-plugin-web-extension";
import path from "path";

export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    webExtension({
      manifest: "public/manifest.json",
      // Browser target — generates correct manifest format
      browser: "chrome",
      // Disable HMR in service worker context (not supported)
      webExtConfig: {
        startUrl: "https://example.com",
      },
    }),
  ],

  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },

  build: {
    outDir: "dist",
    sourcemap: mode === "development",
    minify: mode === "production" ? "esbuild" : false,
    // ONNX Runtime WASM files must not be inlined
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        // Deterministic chunk names for easier debugging
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },

  // Required for ONNX Runtime Web WASM threading
  optimizeDeps: {
    exclude: ["onnxruntime-web"],
  },

  // Required headers for WASM + SharedArrayBuffer
  server: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
}));
