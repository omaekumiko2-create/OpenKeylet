/* Pure-JavaScript offline QR Code decoder (ISO/IEC 18004, Versions 1–40, EC L/M/Q/H).
   Zero dependencies, works identically in Chrome Service Workers (OffscreenCanvas) and pages
   on Windows, macOS, and Linux without requiring the native BarcodeDetector API. */
((globalScope) => {
  if (globalScope.OpenKeyletQRDecoder) return;

  // =========================================================================
  // GF(256) Arithmetic & Reed-Solomon Error Correction (poly 0x11D)
  // =========================================================================
  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
  }

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }
  function gfInv(a) {
    if (a === 0) throw new Error("GF(256) divide by zero");
    return GF_EXP[255 - GF_LOG[a]];
  }

  function polyEval(poly, x) {
    let y = poly[0];
    for (let i = 1; i < poly.length; i++) y = gfMul(y, x) ^ poly[i];
    return y;
  }

  function rsDecode(codewords, ecCount) {
    const n = codewords.length;
    const syndromes = new Uint8Array(ecCount);
    let hasError = false;
    for (let i = 0; i < ecCount; i++) {
      const val = polyEval(codewords, GF_EXP[i]);
      syndromes[i] = val;
      if (val !== 0) hasError = true;
    }
    if (!hasError) return true;

    // Berlekamp-Massey for error locator polynomial C(x)
    let C = [1];
    let B = [1];
    let L = 0;
    let m = 1;
    let b = 1;

    for (let r = 0; r < ecCount; r++) {
      let d = syndromes[r];
      for (let i = 1; i <= L; i++) {
        d ^= gfMul(C[i], syndromes[r - i]);
      }
      if (d === 0) {
        m++;
      } else {
        const T = C.slice();
        const coef = gfMul(d, gfInv(b));
        const needed = B.length + m;
        while (C.length < needed) C.push(0);
        for (let i = 0; i < B.length; i++) {
          C[i + m] ^= gfMul(coef, B[i]);
        }
        if (2 * L <= r) {
          L = r + 1 - L;
          B = T;
          b = d;
          m = 1;
        } else {
          m++;
        }
      }
    }

    if (L > Math.floor(ecCount / 2)) return false;

    // Chien search for error positions
    const errPositions = [];
    for (let i = 0; i < n; i++) {
      // Evaluate C(alpha^-i)
      const xInv = GF_EXP[(255 - i) % 255];
      let sum = 0;
      let pow = 1;
      for (let j = 0; j < C.length; j++) {
        sum ^= gfMul(C[j], pow);
        pow = gfMul(pow, xInv);
      }
      if (sum === 0) {
        const pos = n - 1 - i;
        if (pos < 0 || pos >= n) return false;
        errPositions.push({ pos, xInv, x: GF_EXP[i % 255] });
      }
    }
    if (errPositions.length !== L) return false;

    // Error evaluator polynomial Omega(x) = (S(x) * C(x)) mod x^ecCount
    const omega = new Uint8Array(ecCount);
    for (let i = 0; i < ecCount; i++) {
      let val = 0;
      for (let j = 0; j <= i && j < C.length; j++) {
        val ^= gfMul(C[j], syndromes[i - j]);
      }
      omega[i] = val;
    }

    // Forney algorithm (in GF(2^m), derivative C'(x) keeps only odd-degree terms)
    for (const { pos, xInv, x } of errPositions) {
      let num = 0;
      let pow = 1;
      for (let j = 0; j < ecCount; j++) {
        num ^= gfMul(omega[j], pow);
        pow = gfMul(pow, xInv);
      }
      let den = 0;
      pow = 1;
      for (let j = 1; j < C.length; j += 2) {
        den ^= gfMul(C[j], pow);
        pow = gfMul(pow, gfMul(xInv, xInv));
      }
      if (den === 0) return false;
      // For fcr = 0: e = x * Omega(x^-1) / C'(x^-1)
      const mag = gfMul(x, gfMul(num, gfInv(den)));
      codewords[pos] ^= mag;
    }

    // Re-verify all syndromes are zero
    for (let i = 0; i < ecCount; i++) {
      if (polyEval(codewords, GF_EXP[i]) !== 0) return false;
    }
    return true;
  }

  // =========================================================================
  // ISO/IEC 18004 Tables (Format, Version, Alignment, RS Blocks)
  // =========================================================================
  const FORMAT_LOOKUP = [
    0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
    0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976,
    0x1689, 0x13be, 0x1ce7, 0x19d0, 0x0762, 0x0255, 0x0d0c, 0x083b,
    0x355f, 0x3068, 0x3f31, 0x3a06, 0x24b4, 0x2183, 0x2eda, 0x2bed,
  ];
  // Format bits high 2 bits: 00=M, 01=L, 10=H, 11=Q -> map to table index 0=L, 1=M, 2=Q, 3=H
  const FORMAT_EC_MAP = [1, 0, 3, 2];

  const VERSION_INFO_LOOKUP = [
    0x07c94, 0x085bc, 0x09a99, 0x0a4d3, 0x0bbf6, 0x0c762, 0x0d847, 0x0e60d,
    0x0f928, 0x10b78, 0x1145d, 0x12a17, 0x13532, 0x149a6, 0x15683, 0x168c9,
    0x177ec, 0x18ec4, 0x191e1, 0x1afab, 0x1b08e, 0x1cc1a, 0x1d33f, 0x1ed75,
    0x1f250, 0x209d5, 0x216f0, 0x228ba, 0x2379f, 0x24b0b, 0x2542e, 0x26a64,
    0x27541, 0x28c69,
  ]; // versions 7..40

  const ALIGNMENT_PATTERNS = [
    [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62],
    [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90],
    [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106], [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142], [6, 34, 62, 90, 118, 146],
    [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158], [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170],
  ];

  // RS block specs indexed by (version - 1) * 4 + ecIdx (0=L, 1=M, 2=Q, 3=H)
  // Format: [ecPerBlock, count1, data1] or [ecPerBlock, count1, data1, count2, data2]
  const RS_BLOCKS = [
    // v1
    [7,1,19],[10,1,16],[13,1,13],[17,1,9],
    // v2
    [10,1,34],[16,1,28],[22,1,22],[28,1,16],
    // v3
    [15,1,55],[26,1,44],[18,2,17],[22,2,13],
    // v4
    [20,1,80],[18,2,32],[26,2,24],[16,4,9],
    // v5
    [26,1,108],[24,2,43],[18,2,15,2,16],[22,2,11,2,12],
    // v6
    [18,2,68],[16,4,27],[24,4,19],[28,4,15],
    // v7
    [20,2,78],[18,4,31],[18,2,14,4,15],[26,4,13,1,14],
    // v8
    [24,2,97],[22,2,38,2,39],[22,4,18,2,19],[26,4,14,2,15],
    // v9
    [30,2,116],[22,3,36,2,37],[20,4,16,4,17],[24,4,12,4,13],
    // v10
    [18,2,68,2,69],[26,4,43,1,44],[24,6,19,2,20],[28,6,15,2,16],
    // v11
    [20,4,81],[30,1,50,4,51],[28,4,22,4,23],[24,3,12,8,13],
    // v12
    [24,2,92,2,93],[22,6,36,2,37],[26,4,20,6,21],[28,7,14,4,15],
    // v13
    [26,4,107],[22,8,37,1,38],[24,8,20,4,21],[22,12,11,4,12],
    // v14
    [30,3,115,1,116],[24,4,40,5,41],[20,11,16,5,17],[24,11,12,5,13],
    // v15
    [22,5,87,1,88],[24,5,41,5,42],[30,5,24,7,25],[24,11,12,7,13],
    // v16
    [24,5,98,1,99],[28,7,45,3,46],[24,15,19,2,20],[30,3,15,13,16],
    // v17
    [28,1,107,5,108],[28,10,46,1,47],[28,1,22,15,23],[28,2,14,17,15],
    // v18
    [30,5,120,1,121],[26,9,43,4,44],[28,17,22,1,23],[28,2,14,19,15],
    // v19
    [28,3,113,4,114],[26,3,44,11,45],[26,17,21,4,22],[26,9,13,16,14],
    // v20
    [28,3,107,5,108],[26,3,41,13,42],[30,15,24,5,25],[28,15,15,10,16],
    // v21
    [28,4,116,4,117],[26,17,42],[28,17,22,6,23],[30,19,16,6,17],
    // v22
    [28,2,111,7,112],[28,17,46],[30,7,24,16,25],[24,34,13],
    // v23
    [30,4,121,5,122],[28,4,47,14,48],[30,11,24,14,25],[30,16,15,14,16],
    // v24
    [30,6,117,4,118],[28,6,45,14,46],[30,11,24,16,25],[30,30,16,2,17],
    // v25
    [26,8,106,4,107],[28,8,47,13,48],[30,7,24,22,25],[30,22,15,13,16],
    // v26
    [28,10,114,2,115],[28,19,46,4,47],[28,28,22,6,23],[30,33,16,4,17],
    // v27
    [30,8,122,4,123],[28,22,45,3,46],[30,8,23,26,24],[30,12,15,28,16],
    // v28
    [30,3,117,10,118],[28,3,45,23,46],[30,4,24,31,25],[30,11,15,31,16],
    // v29
    [30,7,116,7,117],[28,21,45,7,46],[30,1,23,37,24],[30,19,15,26,16],
    // v30
    [30,5,115,10,116],[28,19,47,10,48],[30,15,24,25,25],[30,23,15,25,16],
    // v31
    [30,13,115,3,116],[28,2,46,29,47],[30,42,24,1,25],[30,23,15,28,16],
    // v32
    [30,17,115],[28,10,46,23,47],[30,10,24,35,25],[30,19,15,35,16],
    // v33
    [30,17,115,1,116],[28,14,46,21,47],[30,29,24,19,25],[30,11,15,46,16],
    // v34
    [30,13,115,6,116],[28,14,46,23,47],[30,44,24,7,25],[30,59,16,1,17],
    // v35
    [30,12,121,7,122],[28,12,47,26,48],[30,39,24,14,25],[30,22,15,41,16],
    // v36
    [30,6,121,14,122],[28,6,47,34,48],[30,46,24,10,25],[30,2,15,64,16],
    // v37
    [30,17,122,4,123],[28,29,46,14,47],[30,49,24,10,25],[30,24,15,46,16],
    // v38
    [30,4,122,18,123],[28,13,46,32,47],[30,48,24,14,25],[30,42,15,32,16],
    // v39
    [30,20,117,4,118],[28,40,47,7,48],[30,43,24,22,25],[30,10,15,67,16],
    // v40
    [30,19,118,6,119],[28,18,47,31,48],[30,34,24,34,25],[30,20,15,61,16],
  ];

  const ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

  function popcount(x) {
    let c = 0;
    while (x) { x &= x - 1; c++; }
    return c;
  }

  // =========================================================================
  // Adaptive Binarizer (Hybrid 8x8 block thresholding)
  // =========================================================================
  function toGrayscale(rgba, width, height) {
    const gray = new Uint8Array(width * height);
    for (let i = 0, p = 0; i < gray.length; i++, p += 4) {
      const a = rgba[p + 3];
      if (a < 128) {
        gray[i] = 255; // Treat transparent pixels as white background
      } else {
        gray[i] = (77 * rgba[p] + 150 * rgba[p + 1] + 29 * rgba[p + 2]) >> 8;
      }
    }
    return gray;
  }

  function binarize(gray, width, height, inverted = false) {
    const blockSize = 8;
    const bxCount = Math.max(1, Math.ceil(width / blockSize));
    const byCount = Math.max(1, Math.ceil(height / blockSize));
    const blackPoints = new Uint8Array(bxCount * byCount);

    for (let by = 0; by < byCount; by++) {
      const yStart = Math.min(by * blockSize, Math.max(0, height - blockSize));
      const yEnd = Math.min(height, yStart + blockSize);
      for (let bx = 0; bx < bxCount; bx++) {
        const xStart = Math.min(bx * blockSize, Math.max(0, width - blockSize));
        const xEnd = Math.min(width, xStart + blockSize);
        let min = 255, max = 0, sum = 0, count = 0;
        for (let y = yStart; y < yEnd; y++) {
          const row = y * width;
          for (let x = xStart; x < xEnd; x++) {
            const v = gray[row + x];
            if (v < min) min = v;
            if (v > max) max = v;
            sum += v;
            count++;
          }
        }
        let avg = count ? (sum / count) : 128;
        if (max - min <= 24) {
          avg = min * 0.5;
          if (by > 0 && bx > 0) {
            const neighbor = (blackPoints[(by - 1) * bxCount + bx] +
              2 * blackPoints[by * bxCount + (bx - 1)] +
              blackPoints[(by - 1) * bxCount + (bx - 1)]) / 4;
            if (min < neighbor) avg = neighbor;
          }
        }
        blackPoints[by * bxCount + bx] = avg;
      }
    }

    const bits = new Uint8Array(width * height);
    for (let by = 0; by < byCount; by++) {
      const yStart = by * blockSize;
      const yEnd = Math.min(height, yStart + blockSize);
      const top = Math.max(0, by - 2);
      const bottom = Math.min(byCount - 1, by + 2);
      for (let bx = 0; bx < bxCount; bx++) {
        const xStart = bx * blockSize;
        const xEnd = Math.min(width, xStart + blockSize);
        const left = Math.max(0, bx - 2);
        const right = Math.min(bxCount - 1, bx + 2);
        let sum = 0, cnt = 0;
        for (let ty = top; ty <= bottom; ty++) {
          const tRow = ty * bxCount;
          for (let tx = left; tx <= right; tx++) {
            sum += blackPoints[tRow + tx];
            cnt++;
          }
        }
        const threshold = sum / cnt;
        for (let y = yStart; y < yEnd; y++) {
          const row = y * width;
          for (let x = xStart; x < xEnd; x++) {
            const dark = gray[row + x] <= threshold;
            bits[row + x] = inverted ? (dark ? 0 : 1) : (dark ? 1 : 0);
          }
        }
      }
    }
    return bits;
  }

  // =========================================================================
  // Finder Pattern & Alignment Pattern Localization
  // =========================================================================
  function isFinderRatio(counts) {
    let total = 0;
    for (let i = 0; i < 5; i++) {
      if (counts[i] === 0) return false;
      total += counts[i];
    }
    if (total < 7) return false;
    const mod = total / 7;
    const tol = mod * 0.55;
    return Math.abs(mod - counts[0]) < tol
      && Math.abs(mod - counts[1]) < tol
      && Math.abs(3 * mod - counts[2]) < 3 * tol
      && Math.abs(mod - counts[3]) < tol
      && Math.abs(mod - counts[4]) < tol;
  }

  function crossCheckVertical(bits, width, height, startY, centerX, maxCount, originalTotal) {
    const counts = [0, 0, 0, 0, 0];
    let y = startY;
    while (y >= 0 && bits[y * width + centerX]) { counts[2]++; y--; }
    if (y < 0) return NaN;
    while (y >= 0 && !bits[y * width + centerX] && counts[1] <= maxCount) { counts[1]++; y--; }
    if (y < 0 || counts[1] > maxCount) return NaN;
    while (y >= 0 && bits[y * width + centerX] && counts[0] <= maxCount) { counts[0]++; y--; }
    if (counts[0] > maxCount) return NaN;

    y = startY + 1;
    while (y < height && bits[y * width + centerX]) { counts[2]++; y++; }
    if (y === height) return NaN;
    while (y < height && !bits[y * width + centerX] && counts[3] < maxCount) { counts[3]++; y++; }
    if (y === height || counts[3] >= maxCount) return NaN;
    while (y < height && bits[y * width + centerX] && counts[4] < maxCount) { counts[4]++; y++; }
    if (counts[4] >= maxCount) return NaN;

    const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
    if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
    return isFinderRatio(counts) ? (y - counts[4] - counts[3] - counts[2] / 2) : NaN;
  }

  function crossCheckHorizontal(bits, width, height, startX, centerY, maxCount, originalTotal) {
    const row = centerY * width;
    const counts = [0, 0, 0, 0, 0];
    let x = startX;
    while (x >= 0 && bits[row + x]) { counts[2]++; x--; }
    if (x < 0) return NaN;
    while (x >= 0 && !bits[row + x] && counts[1] <= maxCount) { counts[1]++; x--; }
    if (x < 0 || counts[1] > maxCount) return NaN;
    while (x >= 0 && bits[row + x] && counts[0] <= maxCount) { counts[0]++; x--; }
    if (counts[0] > maxCount) return NaN;

    x = startX + 1;
    while (x < width && bits[row + x]) { counts[2]++; x++; }
    if (x === width) return NaN;
    while (x < width && !bits[row + x] && counts[3] < maxCount) { counts[3]++; x++; }
    if (x === width || counts[3] >= maxCount) return NaN;
    while (x < width && bits[row + x] && counts[4] < maxCount) { counts[4]++; x++; }
    if (counts[4] >= maxCount) return NaN;

    const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
    if (5 * Math.abs(total - originalTotal) >= originalTotal) return NaN;
    return isFinderRatio(counts) ? (x - counts[4] - counts[3] - counts[2] / 2) : NaN;
  }

  function crossCheckDiagonal(bits, width, height, centerY, centerX, maxCount, originalTotal) {
    const counts = [0, 0, 0, 0, 0];
    let i = 0;
    while (centerY >= i && centerX >= i && bits[(centerY - i) * width + (centerX - i)]) { counts[2]++; i++; }
    if (centerY < i || centerX < i) return false;
    while (centerY >= i && centerX >= i && !bits[(centerY - i) * width + (centerX - i)] && counts[1] <= maxCount) { counts[1]++; i++; }
    if (centerY < i || centerX < i || counts[1] > maxCount) return false;
    while (centerY >= i && centerX >= i && bits[(centerY - i) * width + (centerX - i)] && counts[0] <= maxCount) { counts[0]++; i++; }
    if (counts[0] > maxCount) return false;

    i = 1;
    while (centerY + i < height && centerX + i < width && bits[(centerY + i) * width + (centerX + i)]) { counts[2]++; i++; }
    if (centerY + i >= height || centerX + i >= width) return false;
    while (centerY + i < height && centerX + i < width && !bits[(centerY + i) * width + (centerX + i)] && counts[3] < maxCount) { counts[3]++; i++; }
    if (centerY + i >= height || centerX + i >= width || counts[3] >= maxCount) return false;
    while (centerY + i < height && centerX + i < width && bits[(centerY + i) * width + (centerX + i)] && counts[4] < maxCount) { counts[4]++; i++; }
    if (counts[4] >= maxCount) return false;

    const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
    return Math.abs(total - originalTotal) < 2 * originalTotal && isFinderRatio(counts);
  }

  function findFinderPatterns(bits, width, height) {
    const candidates = [];
    const skip = Math.max(1, Math.min(3, Math.floor(height / 140)));

    function recordCandidate(counts, y, xEnd) {
      const total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
      let cx = xEnd - counts[4] - counts[3] - counts[2] / 2;
      const cy = crossCheckVertical(bits, width, height, y, Math.floor(cx), counts[2], total);
      if (!Number.isFinite(cy)) return;
      cx = crossCheckHorizontal(bits, width, height, Math.floor(cx), Math.floor(cy), counts[2], total);
      if (!Number.isFinite(cx)) return;
      if (!crossCheckDiagonal(bits, width, height, Math.floor(cy), Math.floor(cx), counts[2], total)) return;

      const mod = total / 7;
      for (const c of candidates) {
        if (Math.abs(c.x - cx) <= mod && Math.abs(c.y - cy) <= mod && Math.abs(c.mod - mod) <= Math.max(1, c.mod)) {
          const n = c.count + 1;
          c.x = (c.x * c.count + cx) / n;
          c.y = (c.y * c.count + cy) / n;
          c.mod = (c.mod * c.count + mod) / n;
          c.count = n;
          return;
        }
      }
      candidates.push({ x: cx, y: cy, mod, count: 1 });
    }

    for (let y = skip - 1; y < height; y += skip) {
      const row = y * width;
      const counts = [0, 0, 0, 0, 0];
      let state = 0;
      for (let x = 0; x < width; x++) {
        if (bits[row + x]) {
          if ((state & 1) === 1) state++;
          counts[state]++;
        } else {
          if ((state & 1) === 0) {
            if (state === 4) {
              if (isFinderRatio(counts)) {
                recordCandidate(counts, y, x);
                state = 0;
                counts[0] = counts[1] = counts[2] = counts[3] = counts[4] = 0;
              } else {
                counts[0] = counts[2];
                counts[1] = counts[3];
                counts[2] = counts[4];
                counts[3] = 1;
                counts[4] = 0;
                state = 3;
              }
            } else {
              state++;
              counts[state]++;
            }
          } else {
            counts[state]++;
          }
        }
      }
      if (state === 4 && isFinderRatio(counts)) {
        recordCandidate(counts, y, width);
      }
    }

    // Filter out weak isolated false positives when we have plenty
    candidates.sort((a, b) => b.count - a.count);
    return candidates.slice(0, 12);
  }

  function dist(a, b) {
    return Math.hypot(a.x - b.x, a.y - b.y);
  }

  function orderThreeFinders(a, b, c) {
    const dab = dist(a, b), dbc = dist(b, c), dca = dist(c, a);
    let topLeft, p1, p2;
    if (dbc >= dab && dbc >= dca) { topLeft = a; p1 = b; p2 = c; }
    else if (dca >= dab && dca >= dbc) { topLeft = b; p1 = a; p2 = c; }
    else { topLeft = c; p1 = a; p2 = b; }
    // Cross product to distinguish topRight vs bottomLeft in screen coords (y down)
    const cross = (p1.x - topLeft.x) * (p2.y - topLeft.y) - (p1.y - topLeft.y) * (p2.x - topLeft.x);
    const topRight = cross > 0 ? p1 : p2;
    const bottomLeft = cross > 0 ? p2 : p1;
    return { topLeft, topRight, bottomLeft };
  }

  function findAlignmentPattern(bits, width, height, estX, estY, modSize, searchRadius) {
    const minX = Math.max(0, Math.floor(estX - searchRadius));
    const maxX = Math.min(width - 1, Math.ceil(estX + searchRadius));
    const minY = Math.max(0, Math.floor(estY - searchRadius));
    const maxY = Math.min(height - 1, Math.ceil(estY + searchRadius));
    const maxMod = modSize * 1.5;

    function isAlignRatio(c) {
      if (c[0] === 0 || c[1] === 0 || c[2] === 0) return false;
      const tol = modSize * 0.65;
      return Math.abs(modSize - c[0]) < tol
        && Math.abs(modSize - c[1]) < tol
        && Math.abs(modSize - c[2]) < tol;
    }

    let best = null;
    let bestDist = Infinity;

    for (let y = minY; y <= maxY; y++) {
      const row = y * width;
      const counts = [0, 0, 0];
      let state = 0;
      for (let x = minX; x <= maxX; x++) {
        if (bits[row + x]) {
          if (state === 1) {
            counts[1]++;
          } else if (state === 2) {
            if (isAlignRatio(counts)) {
              const cx = x - counts[2] - counts[1] / 2;
              // Vertical verify
              const cxInt = Math.floor(cx);
              const vc = [0, 0, 0];
              let vy = y;
              while (vy >= minY && bits[vy * width + cxInt] && vc[1] <= maxMod) { vc[1]++; vy--; }
              while (vy >= minY && !bits[vy * width + cxInt] && vc[0] <= maxMod) { vc[0]++; vy--; }
              vy = y + 1;
              while (vy <= maxY && bits[vy * width + cxInt] && vc[1] <= maxMod) { vc[1]++; vy++; }
              while (vy <= maxY && !bits[vy * width + cxInt] && vc[2] <= maxMod) { vc[2]++; vy++; }
              if (isAlignRatio(vc)) {
                const cy = vy - vc[2] - vc[1] / 2;
                const d = Math.hypot(cx - estX, cy - estY);
                if (d < bestDist) {
                  bestDist = d;
                  best = { x: cx, y: cy };
                }
              }
            }
            counts[0] = counts[2];
            counts[1] = 1;
            counts[2] = 0;
            state = 1;
          } else {
            state++;
            counts[state]++;
          }
        } else {
          if (state === 1) state++;
          counts[state]++;
        }
      }
    }
    return best;
  }

  // =========================================================================
  // Perspective Homography & Grid Sampling
  // =========================================================================
  function squareToQuad(x0, y0, x1, y1, x2, y2, x3, y3) {
    const dx3 = x0 - x1 + x2 - x3;
    const dy3 = y0 - y1 + y2 - y3;
    if (dx3 === 0 && dy3 === 0) {
      return [x1 - x0, x2 - x1, x0, y1 - y0, y2 - y1, y0, 0, 0, 1];
    }
    const dx1 = x1 - x2, dx2 = x3 - x2;
    const dy1 = y1 - y2, dy2 = y3 - y2;
    const den = dx1 * dy2 - dx2 * dy1;
    const a13 = (dx3 * dy2 - dx2 * dy3) / den;
    const a23 = (dx1 * dy3 - dx3 * dy1) / den;
    return [
      x1 - x0 + a13 * x1, x3 - x0 + a23 * x3, x0,
      y1 - y0 + a13 * y1, y3 - y0 + a23 * y3, y0,
      a13, a23, 1,
    ];
  }

  function adjoint(m) {
    return [
      m[4]*m[8] - m[5]*m[7], m[2]*m[7] - m[1]*m[8], m[1]*m[5] - m[2]*m[4],
      m[5]*m[6] - m[3]*m[8], m[0]*m[8] - m[2]*m[6], m[2]*m[3] - m[0]*m[5],
      m[3]*m[7] - m[4]*m[6], m[1]*m[6] - m[0]*m[7], m[0]*m[4] - m[1]*m[3],
    ];
  }

  function mul3x3(a, b) {
    const r = new Array(9);
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        r[i * 3 + j] = a[i * 3] * b[j] + a[i * 3 + 1] * b[j + 3] + a[i * 3 + 2] * b[j + 6];
      }
    }
    return r;
  }

  function buildTransform(dimension, tl, tr, bl, br, brGridX, brGridY) {
    const sToQ = squareToQuad(tl.x, tl.y, tr.x, tr.y, br.x, br.y, bl.x, bl.y);
    const qToS = adjoint(squareToQuad(3.5, 3.5, dimension - 3.5, 3.5, brGridX, brGridY, 3.5, dimension - 3.5));
    return mul3x3(sToQ, qToS);
  }

  function sampleGrid(bits, width, height, dimension, m) {
    const grid = new Uint8Array(dimension * dimension);
    for (let y = 0; y < dimension; y++) {
      const gy = y + 0.5;
      for (let x = 0; x < dimension; x++) {
        const gx = x + 0.5;
        const w = m[6] * gx + m[7] * gy + m[8];
        const ix = Math.floor((m[0] * gx + m[1] * gy + m[2]) / w);
        const iy = Math.floor((m[3] * gx + m[4] * gy + m[5]) / w);
        if (ix >= 0 && ix < width && iy >= 0 && iy < height) {
          grid[y * dimension + x] = bits[iy * width + ix];
        }
      }
    }
    return grid;
  }

  // =========================================================================
  // Matrix Decoding (Format, Version, Unmask, RS, Bitstream)
  // =========================================================================
  function readFormatInfo(grid, dim) {
    const get = (x, y) => grid[y * dim + x];
    let a = 0;
    for (let i = 0; i <= 5; i++) a = (a << 1) | get(i, 8);
    a = (a << 1) | get(7, 8);
    a = (a << 1) | get(8, 8);
    a = (a << 1) | get(8, 7);
    for (let i = 5; i >= 0; i--) a = (a << 1) | get(8, i);

    let b = 0;
    for (let i = dim - 1; i >= dim - 7; i--) b = (b << 1) | get(8, i);
    for (let i = dim - 8; i < dim; i++) b = (b << 1) | get(i, 8);

    let bestIdx = -1, bestDist = 4;
    for (let i = 0; i < 32; i++) {
      const code = FORMAT_LOOKUP[i];
      const da = popcount(a ^ code);
      if (da < bestDist) { bestDist = da; bestIdx = i; }
      const db = popcount(b ^ code);
      if (db < bestDist) { bestDist = db; bestIdx = i; }
    }
    if (bestIdx < 0) return null;
    return {
      ecIdx: FORMAT_EC_MAP[(bestIdx >> 3) & 3],
      mask: bestIdx & 7,
    };
  }

  function readVersionInfo(grid, dim) {
    const est = (dim - 17) >> 2;
    if (est < 7) return est;
    const get = (x, y) => grid[y * dim + x];
    let v1 = 0;
    for (let j = 5; j >= 0; j--) {
      for (let i = dim - 9; i >= dim - 11; i--) v1 = (v1 << 1) | get(i, j);
    }
    let v2 = 0;
    for (let i = 5; i >= 0; i--) {
      for (let j = dim - 9; j >= dim - 11; j--) v2 = (v2 << 1) | get(i, j);
    }
    let bestVer = est, bestDist = 4;
    for (let idx = 0; idx < VERSION_INFO_LOOKUP.length; idx++) {
      const code = VERSION_INFO_LOOKUP[idx];
      const d1 = popcount(v1 ^ code);
      if (d1 < bestDist) { bestDist = d1; bestVer = idx + 7; }
      const d2 = popcount(v2 ^ code);
      if (d2 < bestDist) { bestDist = d2; bestVer = idx + 7; }
    }
    return bestVer;
  }

  function buildFunctionMask(dim, version) {
    const mask = new Uint8Array(dim * dim);
    const fill = (x0, y0, w, h) => {
      for (let y = y0; y < y0 + h; y++) {
        for (let x = x0; x < x0 + w; x++) {
          if (x >= 0 && x < dim && y >= 0 && y < dim) mask[y * dim + x] = 1;
        }
      }
    };
    // Finders + separators + format info
    fill(0, 0, 9, 9);
    fill(dim - 8, 0, 8, 9);
    fill(0, dim - 8, 9, 8);
    // Timing patterns
    fill(6, 0, 1, dim);
    fill(0, 6, dim, 1);
    // Alignment patterns
    const centers = ALIGNMENT_PATTERNS[version] || [];
    for (const cy of centers) {
      for (const cx of centers) {
        if ((cx === 6 && cy === 6) || (cx === 6 && cy === dim - 7) || (cx === dim - 7 && cy === 6)) continue;
        fill(cx - 2, cy - 2, 5, 5);
      }
    }
    // Version info
    if (version >= 7) {
      fill(dim - 11, 0, 3, 6);
      fill(0, dim - 11, 6, 3);
    }
    return mask;
  }

  function maskBit(maskPattern, x, y) {
    switch (maskPattern) {
      case 0: return ((x + y) & 1) === 0;
      case 1: return (y & 1) === 0;
      case 2: return (x % 3) === 0;
      case 3: return ((x + y) % 3) === 0;
      case 4: return (((y >> 1) + Math.floor(x / 3)) & 1) === 0;
      case 5: return (((x * y) & 1) + ((x * y) % 3)) === 0;
      case 6: return ((((x * y) & 1) + ((x * y) % 3)) & 1) === 0;
      case 7: return ((((x + y) & 1) + ((x * y) % 3)) & 1) === 0;
      default: return false;
    }
  }

  function decodeMatrix(grid, dim) {
    const fmt = readFormatInfo(grid, dim);
    if (!fmt) return null;
    const version = readVersionInfo(grid, dim);
    if (version < 1 || version > 40 || version * 4 + 17 !== dim) return null;

    const funcMask = buildFunctionMask(dim, version);
    const spec = RS_BLOCKS[(version - 1) * 4 + fmt.ecIdx];
    if (!spec) return null;

    const ecPerBlock = spec[0];
    const blocks = [];
    for (let i = 0; i < spec[1]; i++) blocks.push({ dataLen: spec[2], totalLen: spec[2] + ecPerBlock });
    if (spec.length >= 5) {
      for (let i = 0; i < spec[3]; i++) blocks.push({ dataLen: spec[4], totalLen: spec[4] + ecPerBlock });
    }
    const totalCodewords = blocks.reduce((acc, b) => acc + b.totalLen, 0);

    // Extract raw codewords in standard zigzag order
    const raw = new Uint8Array(totalCodewords);
    let byteIdx = 0, bitCount = 0, currentByte = 0;
    let upward = true;

    for (let col = dim - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      for (let step = 0; step < dim; step++) {
        const y = upward ? (dim - 1 - step) : step;
        for (let dx = 0; dx < 2; dx++) {
          const x = col - dx;
          if (funcMask[y * dim + x]) continue;
          let bit = grid[y * dim + x];
          if (maskBit(fmt.mask, x, y)) bit ^= 1;
          currentByte = (currentByte << 1) | bit;
          bitCount++;
          if (bitCount === 8) {
            if (byteIdx < totalCodewords) raw[byteIdx++] = currentByte;
            currentByte = 0;
            bitCount = 0;
          }
        }
      }
      upward = !upward;
    }
    if (byteIdx < totalCodewords) return null;

    // De-interleave data and EC codewords into blocks
    const blockBuffers = blocks.map(b => new Uint8Array(b.totalLen));
    const maxDataLen = Math.max(...blocks.map(b => b.dataLen));
    let ptr = 0;
    for (let i = 0; i < maxDataLen; i++) {
      for (let b = 0; b < blocks.length; b++) {
        if (i < blocks[b].dataLen) blockBuffers[b][i] = raw[ptr++];
      }
    }
    for (let i = 0; i < ecPerBlock; i++) {
      for (let b = 0; b < blocks.length; b++) {
        blockBuffers[b][blocks[b].dataLen + i] = raw[ptr++];
      }
    }

    // Reed-Solomon decode every block
    const totalDataBytes = blocks.reduce((acc, b) => acc + b.dataLen, 0);
    const dataStream = new Uint8Array(totalDataBytes);
    let outPtr = 0;
    for (let b = 0; b < blocks.length; b++) {
      if (!rsDecode(blockBuffers[b], ecPerBlock)) return null;
      dataStream.set(blockBuffers[b].subarray(0, blocks[b].dataLen), outPtr);
      outPtr += blocks[b].dataLen;
    }

    return parseBitstream(dataStream, version);
  }

  function countBits(version, mode) {
    const tier = version <= 9 ? 0 : version <= 26 ? 1 : 2;
    if (mode === 1) return [10, 12, 14][tier];
    if (mode === 2) return [9, 11, 13][tier];
    if (mode === 4) return [8, 16, 16][tier];
    if (mode === 8) return [8, 10, 12][tier];
    return 0;
  }

  function parseBitstream(bytes, version) {
    let bitPos = 0;
    const totalBits = bytes.length * 8;
    const read = (n) => {
      if (bitPos + n > totalBits) return -1;
      let val = 0;
      for (let i = 0; i < n; i++) {
        const byte = bytes[bitPos >> 3];
        val = (val << 1) | ((byte >> (7 - (bitPos & 7))) & 1);
        bitPos++;
      }
      return val;
    };

    const outBytes = [];
    const pushAscii = (str) => {
      for (let i = 0; i < str.length; i++) outBytes.push(str.charCodeAt(i));
    };

    while (bitPos + 4 <= totalBits) {
      const mode = read(4);
      if (mode === 0) break; // Terminator
      if (mode === 7) {
        // ECI mode
        const first = read(8);
        if (first < 0) break;
        if ((first & 0x80) !== 0) {
          if ((first & 0xc0) === 0x80) read(8);
          else if ((first & 0xe0) === 0xc0) read(16);
        }
      } else if (mode === 3) {
        // Structured append
        if (read(16) < 0) break;
      } else if (mode === 5 || mode === 9) {
        // FNC1
        continue;
      } else if (mode === 1) {
        // Numeric
        let count = read(countBits(version, 1));
        if (count < 0) return null;
        while (count >= 3) {
          const v = read(10);
          if (v < 0 || v >= 1000) return null;
          pushAscii(String(v).padStart(3, "0"));
          count -= 3;
        }
        if (count === 2) {
          const v = read(7);
          if (v < 0 || v >= 100) return null;
          pushAscii(String(v).padStart(2, "0"));
        } else if (count === 1) {
          const v = read(4);
          if (v < 0 || v >= 10) return null;
          pushAscii(String(v));
        }
      } else if (mode === 2) {
        // Alphanumeric
        let count = read(countBits(version, 2));
        if (count < 0) return null;
        while (count >= 2) {
          const v = read(11);
          if (v < 0 || v >= 45 * 45) return null;
          pushAscii(ALPHANUMERIC[Math.floor(v / 45)] + ALPHANUMERIC[v % 45]);
          count -= 2;
        }
        if (count === 1) {
          const v = read(6);
          if (v < 0 || v >= 45) return null;
          pushAscii(ALPHANUMERIC[v]);
        }
      } else if (mode === 4) {
        // Byte mode
        const count = read(countBits(version, 4));
        if (count < 0 || bitPos + count * 8 > totalBits) return null;
        for (let i = 0; i < count; i++) {
          const b = read(8);
          if (b < 0) return null;
          outBytes.push(b);
        }
      } else if (mode === 8) {
        // Kanji mode (skip cleanly if unsupported charset)
        const count = read(countBits(version, 8));
        if (count < 0 || bitPos + count * 13 > totalBits) return null;
        for (let i = 0; i < count; i++) {
          const v = read(13);
          const assembled = (Math.floor(v / 0xc0) << 8) | (v % 0xc0);
          const sjis = assembled + (assembled < 0x1f00 ? 0x8140 : 0xc140);
          outBytes.push((sjis >> 8) & 0xff, sjis & 0xff);
        }
      } else {
        return null;
      }
    }

    if (!outBytes.length) return null;
    try {
      return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(outBytes));
    } catch {
      return String.fromCharCode(...outBytes);
    }
  }

  // =========================================================================
  // Top-level Decode Driver (tries all valid 3-finder triples + dimension +/- 4)
  // =========================================================================
  function tryDecodeBinary(bits, width, height) {
    const finders = findFinderPatterns(bits, width, height);
    if (finders.length < 3) return null;

    // Generate candidate triples ranked by finder module-size consistency & right-angle geometry
    const triples = [];
    const limit = Math.min(finders.length, 9);
    for (let i = 0; i < limit; i++) {
      for (let j = i + 1; j < limit; j++) {
        for (let k = j + 1; k < limit; k++) {
          const { topLeft, topRight, bottomLeft } = orderThreeFinders(finders[i], finders[j], finders[k]);
          const dTop = dist(topLeft, topRight);
          const dLeft = dist(topLeft, bottomLeft);
          const avgMod = (topLeft.mod + topRight.mod + bottomLeft.mod) / 3;
          if (avgMod < 1 || dTop < avgMod * 10 || dLeft < avgMod * 10) continue;
          const ratio = Math.max(dTop, dLeft) / Math.min(dTop, dLeft);
          if (ratio > 1.35) continue;
          const modSpread = Math.max(topLeft.mod, topRight.mod, bottomLeft.mod) / Math.min(topLeft.mod, topRight.mod, bottomLeft.mod);
          if (modSpread > 1.6) continue;
          const score = Math.abs(ratio - 1) + (modSpread - 1) - (topLeft.count + topRight.count + bottomLeft.count) * 0.01;
          triples.push({ topLeft, topRight, bottomLeft, avgMod, dTop, dLeft, score });
        }
      }
    }
    triples.sort((a, b) => a.score - b.score);

    for (const triple of triples.slice(0, 10)) {
      const { topLeft, topRight, bottomLeft, avgMod, dTop, dLeft } = triple;
      const rawDim = Math.round(((dTop + dLeft) / 2) / avgMod) + 7;
      let baseDim = rawDim;
      const rem = baseDim & 3;
      if (rem === 0) baseDim++;
      else if (rem === 2) baseDim--;
      else if (rem === 3) baseDim += 2;
      baseDim = Math.max(21, Math.min(177, baseDim));

      // Try baseDim first, then +/- 4 in case of slight module-size estimation drift
      const dimsToTry = [baseDim];
      if (baseDim - 4 >= 21) dimsToTry.push(baseDim - 4);
      if (baseDim + 4 <= 177) dimsToTry.push(baseDim + 4);

      for (const dim of dimsToTry) {
        // Estimated bottom-right finder/alignment point
        const brEst = {
          x: topRight.x + bottomLeft.x - topLeft.x,
          y: topRight.y + bottomLeft.y - topLeft.y,
        };

        // 1. Try with detected alignment pattern (for version >= 2)
        if (dim >= 25) {
          const factor = (dim - 10) / (dim - 7);
          const alignEstX = topLeft.x + (brEst.x - topLeft.x) * factor;
          const alignEstY = topLeft.y + (brEst.y - topLeft.y) * factor;
          const align = findAlignmentPattern(bits, width, height, alignEstX, alignEstY, avgMod, avgMod * 5);
          if (align) {
            const m = buildTransform(dim, topLeft, topRight, bottomLeft, align, dim - 6.5, dim - 6.5);
            const grid = sampleGrid(bits, width, height, dim, m);
            const decoded = decodeMatrix(grid, dim);
            if (decoded) return decoded;
          }
        }

        // 2. Fallback: parallelogram 4th corner (exact for flat digital/screenshot QR codes!)
        const m = buildTransform(dim, topLeft, topRight, bottomLeft, brEst, dim - 3.5, dim - 3.5);
        const grid = sampleGrid(bits, width, height, dim, m);
        const decoded = decodeMatrix(grid, dim);
        if (decoded) return decoded;
      }
    }
    return null;
  }

  function binarizeGlobal(gray, inverted = false) {
    // Otsu global threshold — crisp & exact for digital screens, SVG, PNG, and large modules.
    const hist = new Uint32Array(256);
    for (let i = 0; i < gray.length; i++) hist[gray[i]]++;
    const total = gray.length;
    let sum = 0;
    for (let i = 0; i < 256; i++) sum += i * hist[i];
    let sumB = 0, wB = 0, maxVar = -1, threshold = 128;
    for (let t = 0; t < 256; t++) {
      wB += hist[t];
      if (wB === 0) continue;
      const wF = total - wB;
      if (wF === 0) break;
      sumB += t * hist[t];
      const mB = sumB / wB;
      const mF = (sum - sumB) / wF;
      const between = wB * wF * (mB - mF) * (mB - mF);
      if (between > maxVar) { maxVar = between; threshold = t; }
    }
    const bits = new Uint8Array(total);
    for (let i = 0; i < total; i++) {
      const dark = gray[i] <= threshold;
      bits[i] = inverted ? (dark ? 0 : 1) : (dark ? 1 : 0);
    }
    return bits;
  }

  function decode(imageData) {
    if (!imageData || !imageData.data || !imageData.width || !imageData.height) return null;
    const { data, width, height } = imageData;
    if (width < 21 || height < 21) return null;
    const gray = toGrayscale(data, width, height);

    // 1. Global Otsu (normal & inverted) — fastest and cleanest for digital/web QR codes
    const gNormal = tryDecodeBinary(binarizeGlobal(gray, false), width, height);
    if (gNormal) return gNormal;
    const gInv = tryDecodeBinary(binarizeGlobal(gray, true), width, height);
    if (gInv) return gInv;

    // 2. Adaptive local block thresholding (normal & inverted) — handles shaded/gradient backgrounds
    const aNormal = tryDecodeBinary(binarize(gray, width, height, false), width, height);
    if (aNormal) return aNormal;
    return tryDecodeBinary(binarize(gray, width, height, true), width, height);
  }

  globalScope.OpenKeyletQRDecoder = { decode };
})(typeof self !== "undefined" ? self : window);
