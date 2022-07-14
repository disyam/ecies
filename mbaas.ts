import {
  decode as base64Decode,
  encode as base64Encode,
} from "https://deno.land/std@0.135.0/encoding/base64.ts";
import "https://deno.land/x/dotenv@v3.2.0/load.ts";

async function getServPub(endpoint: string) {
  const resp = await fetch(`${endpoint}/.encryption/jwks.json`);
  const servPubJWK = (await resp.json()).keys[0] as JsonWebKey;
  const servPub = await crypto.subtle.importKey(
    "jwk",
    servPubJWK,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
  return servPub;
}

function genCliKeyPair() {
  return crypto.subtle
    .generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
      "deriveKey",
    ]);
}

async function genSharedKey(cliPriv: CryptoKey, servPub: CryptoKey) {
  const sharedKeyOld = await crypto.subtle.deriveKey(
    { name: "ECDH", public: servPub },
    cliPriv,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const sharedKeyRaw = await crypto.subtle.exportKey("raw", sharedKeyOld);
  const sharedKeyHash = await crypto.subtle.digest(
    { name: "SHA-256" },
    sharedKeyRaw,
  );
  const sharedKeyNew = await crypto.subtle.importKey(
    "raw",
    sharedKeyHash,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  return sharedKeyNew;
}

async function encrypt(data: Record<string, unknown>, sharedKey: CryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    new TextEncoder().encode(JSON.stringify(data)),
  );
  const mergedtext = new Uint8Array(cipertext.byteLength + iv.byteLength);
  mergedtext.set(iv);
  mergedtext.set(new Uint8Array(cipertext), iv.byteLength);
  return mergedtext;
}

async function decrypt(
  mergedtext: Uint8Array,
  sharedKey: CryptoKey,
): Promise<Record<string, unknown>> {
  const iv = mergedtext.slice(0, 12);
  const ciphertext = mergedtext.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function request() {
  const endpoint = Deno.env.get("MBAAS_ENDPOINT") || "";
  const reqData = {
    provider: "local",
    data: {
      email: Deno.env.get("MBAAS_EMAIL"),
      password: Deno.env.get("MBAAS_PASSWORD"),
    },
  };
  const servPub = await getServPub(endpoint);
  const { privateKey: cliPriv, publicKey: cliPub } = await genCliKeyPair();
  const sharedKey = await genSharedKey(cliPriv, servPub);
  const mergedtext = await encrypt(reqData, sharedKey);
  const cliPubJWK = await crypto.subtle.exportKey("jwk", cliPub);
  const resp = await fetch(
    `${endpoint}/services/auth`,
    {
      method: "post",
      body: JSON.stringify({ cipherText: base64Encode(mergedtext) }),
      headers: {
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
        "x-encryption-key": base64Encode(JSON.stringify(cliPubJWK)),
      },
    },
  );
  const resData = await decrypt(
    base64Decode((await resp.json()).cipherText as string),
    sharedKey,
  );
  return resData;
}

console.log(await request());
