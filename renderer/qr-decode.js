/* Offline QR code decoder using native BarcodeDetector (Chromium/WebView2). */
(() => {
  async function toBitmap(source) {
    if (typeof ImageBitmap !== 'undefined' && source instanceof ImageBitmap) {
      return { bitmap: source, close: () => {} };
    }
    if (source instanceof HTMLImageElement || source instanceof HTMLCanvasElement) {
      return { bitmap: source, close: () => {} };
    }
    if (source instanceof Blob) {
      if (typeof createImageBitmap === 'function') {
        const bitmap = await createImageBitmap(source);
        return { bitmap, close: () => bitmap.close?.() };
      }
      const url = URL.createObjectURL(source);
      try {
        const img = new Image();
        img.decoding = 'async';
        await new Promise((resolve, reject) => {
          img.onload = resolve;
          img.onerror = () => reject(new Error('Could not load QR image'));
          img.src = url;
        });
        return { bitmap: img, close: () => URL.revokeObjectURL(url) };
      } catch (err) {
        URL.revokeObjectURL(url);
        throw err;
      }
    }
    throw new Error('Unsupported QR image source');
  }

  async function decodeQrStrings(source) {
    if (typeof window.BarcodeDetector !== 'function') {
      throw new Error('QR scanning is not supported on this platform WebView; paste the otpauth:// URI or Base32 setup key instead.');
    }
    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    const { bitmap, close } = await toBitmap(source);
    try {
      const results = await detector.detect(bitmap);
      const values = results
        .map((entry) => String(entry?.rawValue || '').trim())
        .filter(Boolean);
      if (!values.length) {
        throw new Error('No QR code detected in image');
      }
      // Prefer otpauth:// URIs when multiple QR codes exist.
      const totp = values.find((v) => v.toLowerCase().startsWith('otpauth://'));
      return totp || values[0];
    } finally {
      close();
    }
  }

  window.OpenKeyletQR = {
    supported: typeof window.BarcodeDetector === 'function',
    decode: decodeQrStrings,
  };
})();
