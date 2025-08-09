export function randomIv(length = 12) {
  const iv = new Uint8Array(length);
  crypto.getRandomValues(iv);
  return iv;
}

export async function aesGcmEncrypt(key: CryptoKey, data: ArrayBuffer, iv?: Uint8Array) {
  const _iv = iv ?? randomIv();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: _iv as unknown as BufferSource }, key, data);
  return { iv: _iv, ciphertext: new Uint8Array(ct) };
}

export async function aesGcmDecrypt(key: CryptoKey, iv: Uint8Array, ciphertext: ArrayBuffer) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, ciphertext);
  return new Uint8Array(pt);
}
