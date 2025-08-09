import { deriveKeyFromPassword, randomSalt } from "./derive";
import { aesGcmEncrypt, aesGcmDecrypt, randomIv } from "./aes";
import { concatArrays } from "./utils";
import { encodeHeader, decodeHeader, EncHeader } from "../storage/metadata";

export class WrongPasswordError extends Error {
  constructor() {
    super('Incorrect password');
    this.name = 'WrongPasswordError';
  }
}

export type Progress = (fraction: number) => void;

export async function encryptFileChunked(
  file: File,
  password: string,
  onProgress?: Progress,
  opts?: { iterations?: number; chunkSize?: number }
) {
  const chunkSize = opts?.chunkSize ?? 1024 * 1024;
  const iterations = opts?.iterations ?? 200_000;
  const salt = randomSalt();
  const key = await deriveKeyFromPassword(password, { salt, iterations, hash: 'SHA-256' });

  const header: EncHeader = {
    v: 1,
    algo: 'AES-GCM',
    saltB64: btoa(String.fromCharCode(...salt)),
    iterations,
    chunkSize,
    fileName: file.name,
    fileSize: file.size,
  };
  const { headerBytes, headerLenPrefix } = encodeHeader(header);

  const chunks: Uint8Array[] = [headerLenPrefix, headerBytes];

  let offset = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, Math.min(offset + chunkSize, file.size));
    const buf = await slice.arrayBuffer();
    const iv = randomIv();
    const { ciphertext } = await aesGcmEncrypt(key, buf, iv);
  // Per-chunk format: [12-byte IV][4-byte LE ciphertext length][ciphertext]
  const lenBytes = new Uint8Array(4);
  new DataView(lenBytes.buffer).setUint32(0, ciphertext.byteLength, true);
  const out = new Uint8Array(iv.byteLength + lenBytes.byteLength + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(lenBytes, iv.byteLength);
  out.set(ciphertext, iv.byteLength + lenBytes.byteLength);
    chunks.push(out);

    offset += slice.size;
    onProgress?.(offset / file.size);
  }
  return concatArrays(chunks);
}

export async function decryptFileChunked(
  encrypted: Uint8Array,
  password: string,
  onProgress?: Progress
) {
  const { header, headerLen } = decodeHeader(encrypted);
  const headerStart = 4;
  const bodyStart = headerStart + headerLen;
  const salt = Uint8Array.from(atob(header.saltB64), c => c.charCodeAt(0));
  const key = await deriveKeyFromPassword(password, {
    salt, iterations: header.iterations, hash: 'SHA-256'
  });

  const ivLen = 12;
  let offset = bodyStart;
  const parts: Uint8Array[] = [];
  let processed = 0;

  while (offset < encrypted.byteLength) {
    if (offset + ivLen + 4 > encrypted.byteLength) {
      throw new Error('Corrupt or incomplete encrypted file (chunk header truncated).');
    }
    const iv = encrypted.subarray(offset, offset + ivLen);
    offset += ivLen;

    const lenView = new DataView(encrypted.buffer, encrypted.byteOffset + offset, 4);
    const ctLen = lenView.getUint32(0, true);
    offset += 4;

    if (offset + ctLen > encrypted.byteLength) {
      throw new Error('Corrupt or incomplete encrypted file (chunk payload truncated).');
    }
    const ciphertext = encrypted.subarray(offset, offset + ctLen);
    let pt: Uint8Array;
    try {
      pt = await aesGcmDecrypt(
        key,
        iv,
        ciphertext.buffer.slice(ciphertext.byteOffset, ciphertext.byteOffset + ciphertext.byteLength) as ArrayBuffer
      );
    } catch (err) {
      // Authentication failure => wrong key/password or corrupted ciphertext
      throw new WrongPasswordError();
    }
    parts.push(new Uint8Array(pt));
    offset += ctLen;

    processed += pt.byteLength;
    onProgress?.(Math.min(processed / header.fileSize, 1));
  }

  const joined = concatArrays(parts).subarray(0, header.fileSize);
  return { fileName: header.fileName, data: joined };
}
