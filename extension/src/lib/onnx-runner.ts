/**
 * PhishGuard — ONNX Runtime Web Inference Engine
 *
 * Runs the trained phishing detection model entirely in the browser
 * using WebAssembly. Zero network calls, zero privacy risk.
 *
 * Why ONNX Runtime Web?
 * - Universal model format (export from sklearn, PyTorch, etc.)
 * - WebAssembly backend = near-native speed (~2–5ms inference)
 * - No server needed
 * - Works offline
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

import * as ort from "onnxruntime-web";
import { URLFeatures, featuresToArray } from "../types";

// Singleton session — initialize once, reuse for every inference call
let session: ort.InferenceSession | null = null;
let loadingPromise: Promise<ort.InferenceSession> | null = null;

/**
 * Initialize the ONNX Runtime session.
 * Call this once on extension startup to avoid first-scan latency.
 * Uses a singleton pattern to prevent multiple model loads.
 */
export async function initModel(): Promise<void> {
  if (session) return;
  if (loadingPromise) {
    await loadingPromise;
    return;
  }

  loadingPromise = (async () => {
    // ONNX Runtime Web 1.26 dynamically loads a companion .mjs file.
    // This runner must execute in an extension page/offscreen document,
    // because import() is forbidden in MV3 service worker globals.
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.proxy = false;
    ort.env.wasm.wasmPaths = {
      mjs: chrome.runtime.getURL("ort-wasm/ort-wasm-simd-threaded.mjs"),
      wasm: chrome.runtime.getURL("ort-wasm/ort-wasm-simd-threaded.wasm"),
    };

    const modelPath = chrome.runtime.getURL("models/phishguard.onnx");
    const modelBuffer = await fetch(modelPath).then((r) => r.arrayBuffer());

    return ort.InferenceSession.create(modelBuffer, {
      executionProviders: ["wasm"],   // wasm is most compatible
      graphOptimizationLevel: "all",  // Maximize inference speed
    });
  })();

  session = await loadingPromise;
  console.info("[PhishGuard] ONNX model loaded.");
}

export interface InferenceResult {
  probability: number;    // Raw 0–1 phishing probability
  durationMs: number;     // Inference time for debugging/display
}

/**
 * Run inference on a feature vector.
 * Returns phishing probability (0 = safe, 1 = definitely phishing).
 *
 * @throws {Error} if model is not initialized or input is malformed
 */
export async function runInference(features: URLFeatures): Promise<InferenceResult> {
  if (!session) {
    await initModel();
    if (!session) throw new Error("[PhishGuard] Model failed to initialize.");
  }

  const startTime = performance.now();
  const featureArray = featuresToArray(features);

  // Create ONNX tensor — shape [1, 15] (batch=1, features=15)
  const tensor = new ort.Tensor("float32", featureArray, [1, 15]);

  // Input name must match what was used during ONNX export
  // Run skl2onnx with: initial_types=[('features', FloatTensorType([None, 15]))]
  const feeds: Record<string, ort.Tensor> = { features: tensor };
  const output = await session.run(feeds);

  // sklearn classifiers export two outputs:
  // - "label": predicted class (0=safe, 1=phish)
  // - "probabilities": [[prob_safe, prob_phish]]
  const probabilities = output["probabilities"];
  if (!probabilities) {
    throw new Error("[PhishGuard] Unexpected model output format.");
  }

  // probabilities.data = Float32Array [prob_safe, prob_phish]
  const probData = probabilities.data as Float32Array;
  const phishProbability = probData[1]; // Index 1 = phishing class

  const durationMs = performance.now() - startTime;

  return {
    probability: phishProbability,
    durationMs,
  };
}

/**
 * Check if the model is currently loaded.
 */
export function isModelLoaded(): boolean {
  return session !== null;
}
