import {
  decode as base64Decode,
  encode as base64Encode,
} from "https://deno.land/std@0.135.0/encoding/base64.ts";
import ProgressBar from "https://deno.land/x/progress@v1.2.8/mod.ts";

const { privateKey: cliPriv, publicKey: cliPub } = await crypto.subtle
  .generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
    "deriveKey",
  ]);
const cliPubJWK = await crypto.subtle.exportKey("jwk", cliPub);

let servPub: CryptoKey;
let encKey: CryptoKey;

async function encrypt(plaintext: ArrayBuffer) {
  if (!servPub) {
    const resp = await fetch("http://127.0.0.1:8080/pub");
    const servPubJWK = (await resp.json()) as JsonWebKey;
    servPub = await crypto.subtle.importKey(
      "jwk",
      servPubJWK,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      [],
    );
  }
  if (!encKey) {
    encKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: servPub },
      cliPriv,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encKey,
    plaintext,
  );
  return {
    iv,
    ciphertext,
  };
}

async function decrypt(iv: ArrayBuffer, ciphertext: ArrayBuffer) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    encKey,
    ciphertext,
  );
  return { plaintext };
}

const total = 100000;

console.log();
console.log("calling encrypted API");
let progress = new ProgressBar({
  total,
  interval: 1,
});
for (let i = 0; i < total; i++) {
  const { iv, ciphertext } = await encrypt(
    new TextEncoder().encode(JSON.stringify({ a: i, b: i })),
  );
  const body = JSON.stringify({
    p: cliPubJWK,
    i: base64Encode(iv),
    c: base64Encode(ciphertext),
  });
  const resp = await fetch("http://127.0.0.1:8080/adds", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  const data = await resp.json();
  const { plaintext } = await decrypt(
    base64Decode(data.i),
    base64Decode(data.c),
  );
  const { c } = JSON.parse(new TextDecoder().decode(plaintext));
  if (i + i != c) {
    throw new Error("result not valid");
  }
  progress.render(i + 1);
}

console.log();
console.log("calling plain API");
progress = new ProgressBar({
  total,
  interval: 1,
});
for (let i = 0; i < total; i++) {
  const resp = await fetch("http://127.0.0.1:8080/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ a: i, b: i }),
  });
  const { c } = await resp.json();
  if (i + i != c) {
    throw new Error("result not valid");
  }
  progress.render(1 + i);
}
console.log();
