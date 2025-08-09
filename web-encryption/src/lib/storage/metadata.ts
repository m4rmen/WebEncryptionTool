export type EncHeader = {
  v: 1;
  algo: 'AES-GCM';
  saltB64: string;
  iterations: number;
  chunkSize: number;
  fileName: string;
  fileSize: number;
};
export function encodeHeader(h: EncHeader) {
  const json = JSON.stringify(h);
  const bytes = new TextEncoder().encode(json);
  const len = new Uint8Array(new Uint32Array([bytes.byteLength]).buffer); // 4 bytes length prefix (LE)
  return { headerBytes: bytes, headerLenPrefix: len };
}
export function decodeHeader(buf: Uint8Array): { header: EncHeader; headerLen: number } {
  const headerLen = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, true);
  const start = 4;
  const end = 4 + headerLen;
  const json = new TextDecoder().decode(buf.subarray(start, end));
  return { header: JSON.parse(json), headerLen };
}
