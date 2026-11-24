(() => {
  if (window !== window.top || !isSecureContext || !navigator.credentials) return;
  const pending = new Map();
  function encode(value) {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      let raw = ""; for (const byte of bytes) raw += String.fromCharCode(byte);
      return btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    }
    if (Array.isArray(value)) return value.map(encode);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,encode(v)]));
    return value;
  }
  function decode(text) {
    const base64 = text.replaceAll("-", "+").replaceAll("_", "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
  }
  function credential(data, operation) {
    const r = data.response;
    const response = Object.create((operation === "create" ? AuthenticatorAttestationResponse : AuthenticatorAssertionResponse).prototype);
    const properties = { clientDataJSON: decode(r.clientDataJSON) };
    if (operation === "create") Object.assign(properties, { attestationObject: decode(r.attestationObject), getTransports: () => [...r.transports], getPublicKey: () => decode(r.publicKey), getPublicKeyAlgorithm: () => r.publicKeyAlgorithm, getAuthenticatorData: () => decode(r.authenticatorData) });
    else Object.assign(properties, { authenticatorData: decode(r.authenticatorData), signature: decode(r.signature), userHandle: r.userHandle ? decode(r.userHandle) : null });
    Object.defineProperties(response, Object.fromEntries(Object.entries(properties).map(([k,value]) => [k,{ value, enumerable: true }])));
    const result = Object.create(PublicKeyCredential.prototype);
    Object.defineProperties(result, Object.fromEntries(Object.entries({ id: data.id, rawId: decode(data.rawId), type: "public-key", response,
      authenticatorAttachment: data.authenticatorAttachment, getClientExtensionResults: () => structuredClone(data.clientExtensionResults), toJSON: () => structuredClone(data) }).map(([k,value]) => [k,{ value, enumerable: true }])));
    return result;
  }
  window.addEventListener("message", event => {
    if (event.source !== window || event.data?.type !== "openkeylet-webauthn-result") return;
    const p = pending.get(event.data.requestId); if (p) p.resolve(event.data.result);
  });
  if (typeof PublicKeyCredential === "function") {
    try {
      Object.defineProperty(PublicKeyCredential, "isUserVerifyingPlatformAuthenticatorAvailable", {
        value: () => Promise.resolve(true),
        configurable: true,
      });
    } catch {}
  }
  for (const operation of ["create", "get"]) {
    const native = navigator.credentials[operation].bind(navigator.credentials);
    navigator.credentials[operation] = async function(options) {
      // Conditional mediation remains with the browser until an explicit sign-in is requested.
      if (!options?.publicKey || options.mediation === "conditional") return native(options);
      if (options.publicKey.extensions?.largeBlob?.support === "required") return native(options);
      if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const requestId = crypto.randomUUID();
      let timer, abort;
      try {
        const result = await new Promise((resolve, reject) => {
          pending.set(requestId, { resolve });
          abort = () => { window.postMessage({ type: "openkeylet-webauthn-cancel", requestId }, location.origin); reject(new DOMException("Aborted", "AbortError")); };
          options.signal?.addEventListener("abort", abort, { once: true });
          timer = setTimeout(() => { window.postMessage({ type: "openkeylet-webauthn-cancel", requestId }, location.origin); reject(new DOMException("Request expired", "NotAllowedError")); }, Math.min(Math.max(Number(options.publicKey.timeout) || 120000, 1000), 120000));
          window.postMessage({ type: "openkeylet-webauthn-call", requestId, operation, options: encode(options.publicKey) }, location.origin);
        });
        if (options.signal?.aborted) throw new DOMException("Aborted", "AbortError");
        if (result.fallback) return native(options);
        if (result.error) throw new DOMException(result.error, result.name || "NotAllowedError");
        return credential(result.credential, operation);
      } finally { clearTimeout(timer); pending.delete(requestId); options.signal?.removeEventListener("abort", abort); }
    };
  }
})();
