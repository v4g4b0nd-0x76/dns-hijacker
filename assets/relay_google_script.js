// Google Apps Script relay hop.
//
// Sits in front of your Cloudflare Worker. Forwards the encrypted DNS relay
// packet unchanged, and caches responses keyed by an opaque HMAC tag the
// client computes over (relay_key, domain) — so this script never sees the
// domain itself, only a tag it can't reverse without the key.
//
// SETUP:
// 1. script.google.com > New project, paste this in as Code.gs
// 2. Project Settings > Script Properties > add CF_WORKER_URL = your worker's URL
// 3. Deploy > New deployment > type: Web app
//      Execute as: Me
//      Who has access: Anyone
// 4. Copy the resulting .../exec URL — that's what goes in your Rust config
//    as this relay instance's `relay_url`, with transport = "google_apps_script"

const CACHE_TTL_SECONDS = 300; // Apps Script CacheService max is 21600 (6h)

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents);
    const cacheKey = body.k;     // opaque HMAC tag, no domain ever visible here
    const dataB64 = body.data;   // base64 of the AES-GCM encrypted DNS packet

    if (!cacheKey || !dataB64) {
      return jsonResponse({ error: "bad request" });
    }

    const cache = CacheService.getScriptCache();
    const cached = cache.get(cacheKey);
    if (cached) {
      return jsonResponse({ data: cached });
    }

    const workerUrl = "" // worker url;
    if (!workerUrl) {
      return jsonResponse({ error: "worker url not configured" });
    }

    const bytes = Utilities.base64Decode(dataB64);
    const response = UrlFetchApp.fetch(workerUrl, {
      method: "post",
      contentType: "application/octet-stream",
      payload: bytes,
      muteHttpExceptions: true,
    });

    if (response.getResponseCode() !== 200) {
      return jsonResponse({ error: "upstream error: " + response.getResponseCode() });
    }

    const replyB64 = Utilities.base64Encode(response.getContent());
    cache.put(cacheKey, replyB64, CACHE_TTL_SECONDS);

    return jsonResponse({ data: replyB64 });
  } catch (err) {
    return jsonResponse({ error: String(err) });
  }
}

function jsonResponse(obj) {
  // Apps Script web apps can't set arbitrary HTTP status codes on
  // ContentService output — always returns 200. Treat a present "error"
  // field in the JSON body as failure on the client side, not the HTTP status.
  const output = ContentService.createTextOutput(JSON.stringify(obj));
  output.setMimeType(ContentService.MimeType.JSON);
  return output;
}
