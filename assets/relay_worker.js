// worker.js
const RELAY_KEY = "72263Pe1Lk/kL6XfF/5WzS546mpX0wJesOSX+Pe7Eb8="; // generate using dns-hijacker gen-relay-key

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("not found", { status: 404 });
    }
    const body = await request.arrayBuffer();
    const encryptedQuery = new Uint8Array(body);
    // decrypt using the same ChaCha20-Poly1305 scheme as your Rust client
    const dnsQuery = await decodeFromRelay(
      encryptedQuery,
      base64ToBytes(RELAY_KEY),
    );
    if (!dnsQuery) {
      return new Response("bad request", { status: 400 }); // looks like an ordinary API error
    }
    // Cloudflare Workers can call out to a DoH resolver directly
    const dohResponse = await fetch("https://cloudflare-dns.com/dns-query", {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        accept: "application/dns-message",
      },
      body: dnsQuery,
    });
    const dnsReply = new Uint8Array(await dohResponse.arrayBuffer());
    const encryptedReply = await encodeForRelay(
      dnsReply,
      base64ToBytes(RELAY_KEY),
    );
    return new Response(encryptedReply, {
      headers: { "content-type": "application/json" }, // disguised, not DoH's fingerprint
    });
  },
};
async function importKey(rawKeyBytes) {
  return crypto.subtle.importKey("raw", rawKeyBytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}
async function decodeFromRelay(packet, rawKeyBytes) {
  try {
    const key = await importKey(rawKeyBytes);
    const nonce = packet.slice(0, 12);
    const ciphertext = packet.slice(12);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  } catch {
    return null; // auth tag mismatch or malformed — treat as invalid, same as your Rust side
  }
}
async function encodeForRelay(plaintext, rawKeyBytes) {
  const key = await importKey(rawKeyBytes);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    plaintext,
  );
  const out = new Uint8Array(12 + ciphertext.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ciphertext), 12);
  return out;
}
function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
