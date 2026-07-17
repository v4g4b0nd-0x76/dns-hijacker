const RELAY_KEY = "" // genereate using gen-relay-key;

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
  "https://dns.quad9.net/dns-query",
];

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("not found", { status: 404 });
    }
    try {
      const body = await request.arrayBuffer();
      const encryptedQuery = new Uint8Array(body);
      const dnsQuery = await decodeFromRelay(encryptedQuery, base64ToBytes(RELAY_KEY));
      if (!dnsQuery) {
        return new Response("bad request", { status: 400 });
      }

      const isAQuery = getQuestionType(dnsQuery) === 1;
      const rounds = isAQuery ? 3 : 1;
      const allIps = new Set();
      let lastReply = null;

      for (let r = 0; r < rounds; r++) {
        const responses = await Promise.allSettled(
          DOH_ENDPOINTS.map((url) => queryDoh(url, dnsQuery)),
        );
        for (const res of responses) {
          if (res.status !== "fulfilled" || !res.value) continue; // skip failed resolvers
          try {
            const ips = extractARecords(res.value);
            lastReply = res.value; // any successful reply can serve as the template
            for (const ip of ips) allIps.add(ip);
          } catch (err) {
            console.error("failed to parse DoH reply", err);
          }
        }
        if (r < rounds - 1) {
          await new Promise((resolve) => setTimeout(resolve, 150));
        }
      }

      if (!lastReply) {
        return new Response("upstream failed", { status: 502 });
      }

      const finalReply = isAQuery
        ? rewriteAnswersWithIps(lastReply, Array.from(allIps))
        : lastReply;

      const encryptedReply = await encodeForRelay(finalReply, base64ToBytes(RELAY_KEY));
      return new Response(encryptedReply, {
        headers: { "content-type": "application/json" },
      });
    } catch (err) {
      console.error("worker fatal error", err);
      return new Response("internal error", { status: 500 });
    }
  },
};

async function queryDoh(url, dnsQuery) {
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/dns-message",
        accept: "application/dns-message",
      },
      body: dnsQuery,
    });
    if (!resp.ok) return null;
    return new Uint8Array(await resp.arrayBuffer());
  } catch {
    return null;
  }
}

// --- minimal DNS wire-format helpers ---

function getQuestionType(packet) {
  let offset = 12;
  offset = skipName(packet, offset);
  return (packet[offset] << 8) | packet[offset + 1];
}

function skipName(packet, offset) {
  while (true) {
    const len = packet[offset];
    if (len === 0) return offset + 1;
    if ((len & 0xc0) === 0xc0) return offset + 2;
    offset += len + 1;
  }
}

function extractARecords(packet) {
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength);
  const qdCount = view.getUint16(4);
  const anCount = view.getUint16(6);

  let offset = 12;
  for (let i = 0; i < qdCount; i++) {
    offset = skipName(packet, offset);
    offset += 4;
  }

  const ips = [];
  for (let i = 0; i < anCount; i++) {
    offset = skipName(packet, offset);
    const type = view.getUint16(offset);
    const rdlength = view.getUint16(offset + 8);
    const rdataOffset = offset + 10;
    if (type === 1 && rdlength === 4) {
      ips.push(
        `${packet[rdataOffset]}.${packet[rdataOffset + 1]}.${packet[rdataOffset + 2]}.${packet[rdataOffset + 3]}`,
      );
    }
    offset = rdataOffset + rdlength;
  }
  return ips;
}

function rewriteAnswersWithIps(templatePacket, ips) {
  const view = new DataView(templatePacket.buffer, templatePacket.byteOffset, templatePacket.byteLength);
  const qdCount = view.getUint16(4);
  const anCount = view.getUint16(6);
  const nsCount = view.getUint16(8);
  const arCount = view.getUint16(10);

  let offset = 12;
  for (let i = 0; i < qdCount; i++) {
    offset = skipName(templatePacket, offset);
    offset += 4;
  }
  const questionEnd = offset;

  for (let i = 0; i < anCount; i++) {
    offset = skipName(templatePacket, offset);
    const rdlength = view.getUint16(offset + 8);
    offset += 10 + rdlength;
  }
  const answersEnd = offset;

  const tail = templatePacket.slice(answersEnd);
  const header = templatePacket.slice(0, 12);
  const question = templatePacket.slice(12, questionEnd);
  const answers = ips.map((ip) => buildARecord(ip));
  const answersBytes = answers.reduce((s, a) => s + a.length, 0);

  const totalLen = 12 + question.length + answersBytes + tail.length;
  const out = new Uint8Array(totalLen);

  out.set(header, 0);
  const outView = new DataView(out.buffer);
  outView.setUint16(6, ips.length);
  outView.setUint16(8, nsCount);
  outView.setUint16(10, arCount);

  out.set(question, 12);
  let pos = 12 + question.length;
  for (const rec of answers) {
    out.set(rec, pos);
    pos += rec.length;
  }
  out.set(tail, pos);

  return out;
}

function buildARecord(ip) {
  const rec = new Uint8Array(16);
  rec[0] = 0xc0; rec[1] = 0x0c;
  rec[2] = 0x00; rec[3] = 0x01;
  rec[4] = 0x00; rec[5] = 0x01;
  rec[6] = 0; rec[7] = 0; rec[8] = 0; rec[9] = 60;
  rec[10] = 0x00; rec[11] = 0x04;
  const parts = ip.split(".").map(Number);
  rec.set(parts, 12);
  return rec;
}

// --- AES-256-GCM relay encryption, matching the Rust side's 12-byte-nonce-prefix layout ---

async function importKey(rawKeyBytes) {
  return crypto.subtle.importKey("raw", rawKeyBytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

async function decodeFromRelay(packet, rawKeyBytes) {
  if (packet.length < 12) return null;
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
    return null;
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
