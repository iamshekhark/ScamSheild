// ScamShield Client-Side Offline OCR & QR Engine
// Zero cloud image uploads — 100% private, local WebAssembly OCR and QR decoding.
// Analyzes images for phishing notices, payment fraud, and reverse-collect QR codes.

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ScamOCR = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {

  let tesseractWorker = null;
  let isInitializing = false;
  let initError = null;

  function getEngine() {
    if (typeof ScamEngine !== "undefined") return ScamEngine;
    if (typeof require === "function") {
      try { return require("../rules"); } catch {
        try { return require("./rules"); } catch {}
      }
    }
    return null;
  }

  function getJsQR() {
    if (typeof jsQR !== "undefined") return jsQR;
    if (typeof require === "function") {
      try { return require("jsqr"); } catch {
        try { return require("./jsQR"); } catch {}
      }
    }
    return null;
  }

  function getTesseract() {
    if (typeof Tesseract !== "undefined") return Tesseract;
    if (typeof require === "function") {
      try { return require("tesseract.js"); } catch {}
    }
    return null;
  }

  /**
   * Initialize local Tesseract worker with offline assets.
   */
  async function initWorker(config = {}) {
    if (tesseractWorker) return tesseractWorker;
    if (isInitializing) {
      while (isInitializing) {
        await new Promise((r) => setTimeout(r, 50));
      }
      if (tesseractWorker) return tesseractWorker;
    }

    isInitializing = true;
    initError = null;

    try {
      const T = getTesseract();
      if (!T || !T.createWorker) {
        throw new Error("Tesseract.js library is not loaded in this environment.");
      }

      // Default to extension directory if chrome.runtime is available
      let langPath = config.langPath;
      let workerPath = config.workerPath;
      let corePath = config.corePath;

      if (typeof chrome !== "undefined" && chrome.runtime?.getURL) {
        langPath = langPath || chrome.runtime.getURL("ocr/tessdata");
        workerPath = workerPath || chrome.runtime.getURL("ocr/worker.min.js");
        corePath = corePath || chrome.runtime.getURL("ocr/tesseract-core-lstm.wasm.js");
      }

      tesseractWorker = await T.createWorker("eng", 1, {
        workerPath,
        corePath,
        langPath,
        gzip: true,
        cacheMethod: "none",
        logger: config.logger || (() => {})
      });

      return tesseractWorker;
    } catch (err) {
      initError = err;
      console.warn("[ScamOCR] Worker initialization error:", err.message);
      throw err;
    } finally {
      isInitializing = false;
    }
  }

  /**
   * Terminate the OCR worker to free WebAssembly memory.
   */
  async function terminate() {
    if (tesseractWorker) {
      try {
        await tesseractWorker.terminate();
      } catch {}
      tesseractWorker = null;
    }
  }

  /**
   * Decode QR code from raw RGBA image data.
   */
  function decodeQR(imageData) {
    if (!imageData || !imageData.data || !imageData.width || !imageData.height) {
      return null;
    }
    const scanner = getJsQR();
    if (!scanner) return null;

    try {
      const code = scanner(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert"
      });
      return code ? code.data : null;
    } catch (e) {
      console.warn("[ScamOCR] QR decode error:", e);
      return null;
    }
  }

  /**
   * Convert image source (File, Blob, DataURL, Image, ImageData) to standard Canvas.
   */
  async function sourceToCanvas(imageSource) {
    if (typeof document === "undefined") {
      return null; // Node.js environment
    }

    if (imageSource instanceof HTMLCanvasElement) {
      return imageSource;
    }

    if (typeof ImageData !== "undefined" && imageSource instanceof ImageData) {
      const canvas = document.createElement("canvas");
      canvas.width = imageSource.width;
      canvas.height = imageSource.height;
      const ctx = canvas.getContext("2d");
      ctx.putImageData(imageSource, 0, 0);
      return canvas;
    }

    let urlToRevoke = null;
    let srcUrl = "";

    if (typeof imageSource === "string") {
      srcUrl = imageSource;
    } else if (imageSource instanceof Blob || (typeof File !== "undefined" && imageSource instanceof File)) {
      urlToRevoke = URL.createObjectURL(imageSource);
      srcUrl = urlToRevoke;
    }

    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = "anonymous";
      img.onload = () => {
        try {
          const canvas = document.createElement("canvas");
          canvas.width = img.naturalWidth || img.width;
          canvas.height = img.naturalHeight || img.height;
          const ctx = canvas.getContext("2d");
          ctx.drawImage(img, 0, 0);
          if (urlToRevoke) URL.revokeObjectURL(urlToRevoke);
          resolve(canvas);
        } catch (err) {
          if (urlToRevoke) URL.revokeObjectURL(urlToRevoke);
          reject(err);
        }
      };
      img.onerror = (err) => {
        if (urlToRevoke) URL.revokeObjectURL(urlToRevoke);
        reject(new Error("Failed to load image resource for OCR parsing."));
      };
      img.src = srcUrl;
    });
  }

  /**
   * Main scan function: Scans an image for QR codes and optical text.
   */
  async function scanImage(imageSource, options = {}) {
    const onProgress = options.onProgress || (() => {});
    const engine = getEngine();

    // 1. Guard against empty or invalid input
    if (!imageSource) {
      return {
        risk_score: 0,
        risk_level: "SAFE",
        evidence: [],
        recommendations: ["No image provided for scanning."],
        extracted_text: "",
        qr_code: null,
        ocr_confidence: 0,
        payment_status: "unverified",
        input_type: "ocr_image",
        detection_method: "ocr"
      };
    }

    // 2. Guard against oversized files (> 12MB)
    if (imageSource.size && imageSource.size > 12 * 1024 * 1024) {
      throw new Error("Image file exceeds maximum size limit (12MB). Please select a smaller screenshot.");
    }

    // 3. File type validation if File object
    if (imageSource.type && !imageSource.type.startsWith("image/")) {
      throw new Error(`Unsupported file type '${imageSource.type}'. Please upload a PNG, JPEG, or WebP image.`);
    }

    let qrContent = null;
    let extractedText = "";
    let confidence = 0;
    let canvas = null;

    // 4. Try browser-based canvas decoding
    try {
      canvas = await sourceToCanvas(imageSource);
    } catch (e) {
      console.warn("[ScamOCR] Canvas conversion skipped (running in Node or headless):", e.message);
    }

    // 5. Decode QR code if canvas is available
    if (canvas) {
      onProgress({ status: "Scanning for QR codes...", progress: 0.2 });
      const ctx = canvas.getContext("2d");
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      qrContent = decodeQR(imgData);
    }

    // 6. Run OCR text extraction
    onProgress({ status: "Extracting text locally with WebAssembly OCR...", progress: 0.4 });
    try {
      const worker = await initWorker(options);
      const recognizeTarget = canvas || imageSource;
      const ocrResult = await worker.recognize(recognizeTarget);
      if (ocrResult?.data) {
        extractedText = (ocrResult.data.text || "").trim();
        confidence = Math.round(ocrResult.data.confidence || 0);
      }
    } catch (err) {
      console.warn("[ScamOCR] Local OCR recognition failed or unreadable:", err.message);
      // Fail closed safely: if OCR fails and no QR was decoded, report UNABLE_TO_VERIFY rather than SAFE
      if (!qrContent) {
        return {
          risk_score: null,
          risk_level: "UNABLE_TO_VERIFY",
          evidence: [],
          recommendations: [
            "Unable to extract text from this image.",
            "Ensure screenshot is clear, well-lit, and contains readable typography."
          ],
          extracted_text: "",
          qr_code: null,
          ocr_confidence: 0,
          payment_status: "unverified",
          input_type: "ocr_image",
          detection_method: "ocr",
          error: "OCR text extraction failed: " + err.message
        };
      }
    }

    onProgress({ status: "Evaluating detected content...", progress: 0.8 });

    // 7. Threat Evaluation via ScamEngine
    let threatResult = null;
    let primaryType = "screenshot";

    if (qrContent) {
      // Evaluate decoded QR URI
      if (qrContent.startsWith("upi://") || qrContent.includes("upi://pay")) {
        threatResult = engine ? engine.scanPayment(qrContent, "qr_code", options) : null;
        primaryType = "qr_code";
      } else if (qrContent.startsWith("http://") || qrContent.startsWith("https://")) {
        threatResult = engine ? engine.scanUrl(qrContent, options) : null;
        primaryType = "url";
      } else {
        threatResult = engine ? engine.scanPayment(qrContent, "message", options) : null;
      }
    }

    if (extractedText) {
      // Evaluate text as payment screenshot and message
      const payRes = engine ? engine.scanPayment(extractedText, "screenshot", options) : null;
      const textRes = engine ? engine.scanText(extractedText, options) : null;

      if (!threatResult) {
        // Choose higher risk between payment and general text
        if (payRes && textRes) {
          threatResult = (payRes.risk_score >= textRes.risk_score) ? payRes : textRes;
        } else {
          threatResult = payRes || textRes;
        }
      } else {
        // Merge QR findings with text findings if both exist
        const combinedEvidence = [...(threatResult.evidence || []), ...(payRes?.evidence || []), ...(textRes?.evidence || [])];
        const uniqueEvidence = [];
        const seen = new Set();
        for (const ev of combinedEvidence) {
          const key = `${ev.category}:${ev.reason}`;
          if (!seen.has(key)) {
            seen.add(key);
            uniqueEvidence.push(ev);
          }
        }
        threatResult = engine ? engine.calculateRisk(uniqueEvidence) : threatResult;
      }
    }

    onProgress({ status: "Scan complete", progress: 1.0 });

    const baseScore = threatResult?.risk_score ?? 0;
    const baseLevel = threatResult?.risk_level ?? "SAFE";
    const baseEvidence = threatResult?.evidence || [];
    const baseRecs = threatResult?.recommendations || [];

    // Permanent Banking Disclaimer Invariant
    const DISCLAIMER = "PAYMENT UNVERIFIED: Image analysis detects deceptive text and fraud patterns only. ScamShield does NOT verify bank settlement or authenticate payment receipts.";

    const recommendations = [
      DISCLAIMER,
      ...baseRecs.filter((r) => !r.includes("PAYMENT UNVERIFIED"))
    ];

    return {
      risk_score: baseScore,
      risk_level: baseLevel,
      evidence: baseEvidence,
      recommendations,
      explanation: threatResult?.explanation || (baseScore > 0 ? "Suspicious indicators detected in image text or QR code." : "No scam or phishing signals detected in this image."),
      extracted_text: extractedText,
      qr_code: qrContent,
      ocr_confidence: confidence,
      payment_status: "unverified", // Strictly enforced invariant
      input_type: primaryType,
      detection_method: "local_ocr + rules"
    };
  }

  return {
    initWorker,
    terminate,
    decodeQR,
    scanImage
  };
});
