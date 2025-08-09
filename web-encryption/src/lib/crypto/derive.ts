export type Pbkdf2Params = {
  salt: Uint8Array;
  iterations: number;
  hash: 'SHA-256';
};

export async function deriveKeyFromPassword(password: string, params: Pbkdf2Params) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new Uint8Array(params.salt), iterations: params.iterations, hash: params.hash },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function randomSalt(length = 16) {
  const salt = new Uint8Array(length);
  crypto.getRandomValues(salt);
  return salt;
}
