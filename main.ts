import {
  decode as base64Decode,
  encode as base64Encode,
} from "https://deno.land/std@0.135.0/encoding/base64.ts";

const { privateKey: cliPriv, publicKey: cliPub } = await crypto.subtle
  .generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
const cliPubJWK = await crypto.subtle.exportKey("jwk", cliPub);

let servPub: CryptoKey;
let encKey: CryptoKey;
let signKey: CryptoKey;

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
    const secretBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: servPub },
      cliPriv,
      256,
    );
    [encKey, signKey] = await Promise.all([
      crypto.subtle.importKey(
        "raw",
        secretBits,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"],
      ),
      crypto.subtle.importKey(
        "raw",
        secretBits,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"],
      ),
    ]);
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encKey,
    plaintext,
  );
  const signature = await crypto.subtle.sign(
    { name: "HMAC" },
    signKey,
    ciphertext,
  );
  return {
    iv,
    ciphertext,
    signature,
  };
}

async function decrypt(
  iv: ArrayBuffer,
  ciphertext: ArrayBuffer,
  signature: ArrayBuffer,
) {
  const valid = await crypto.subtle.verify(
    { name: "HMAC" },
    signKey,
    signature,
    ciphertext,
  );
  if (!valid) {
    return Promise.reject("signature not match");
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    encKey,
    ciphertext,
  );
  return { plaintext };
}

const max = 1000;

let start = new Date().getTime();
for (let i = 0; i < max; i++) {
  const { iv, ciphertext, signature } = await encrypt(
    new TextEncoder().encode(JSON.stringify({ a: i, b: i })),
  );
  const body = JSON.stringify({
    p: cliPubJWK,
    i: base64Encode(iv),
    c: base64Encode(ciphertext),
    s: base64Encode(signature),
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
    base64Decode(data.s),
  );
  const { c } = JSON.parse(new TextDecoder().decode(plaintext));
  if (i + i != c) {
    throw new Error("result not valid");
  }
}
let end = new Date().getTime();
let duration = end - start;
console.log("encrypted duration", duration, "ms");

start = new Date().getTime();
for (let i = 0; i < max; i++) {
  const resp = await fetch("http://127.0.0.1:8080/add", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ a: i, b: i }),
  });
  const { c } = await resp.json();
  if (i + i != c) {
    throw new Error("result not valid");
  }
}
end = new Date().getTime();
duration = end - start;
console.log("plain duration", duration, "ms");
