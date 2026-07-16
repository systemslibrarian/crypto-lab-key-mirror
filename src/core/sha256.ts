/** SHA-256 via WebCrypto (SubtleCrypto). Real hash — never simulated. */

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  return new Uint8Array(buf);
}
