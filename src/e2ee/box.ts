/**
 * The E2EE layer the directory attack rides on: real X25519 (RFC 7748) ECDH,
 * HKDF-SHA-256 (RFC 5869), AES-256-GCM via WebCrypto.
 *
 * Deliberately textbook — the lab's point is that this math is FINE. The
 * attack never touches it. If the directory hands Alice the wrong public key,
 * every operation below succeeds perfectly for the attacker.
 */

import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2';
import { concatBytes, randomBytes, utf8ToBytes, bytesToUtf8 } from '../core/bytes';

export interface BoxKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateKeyPair(): BoxKeyPair {
  const secretKey = randomBytes(32);
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

export function keyPairFromSeed(seed: Uint8Array): BoxKeyPair {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return { secretKey: seed, publicKey: x25519.getPublicKey(seed) };
}

export function dh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(secretKey, publicKey);
}

/** shared secret -> AES-256-GCM key, bound to both parties' public keys. */
async function deriveAesKey(
  shared: Uint8Array,
  senderPk: Uint8Array,
  recipientPk: Uint8Array,
): Promise<CryptoKey> {
  const okm = hkdf(nobleSha256, shared, concatBytes(senderPk, recipientPk), utf8ToBytes('key-mirror/e2ee/v1'), 32);
  return crypto.subtle.importKey('raw', okm.buffer.slice(0) as ArrayBuffer, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export interface SealedMessage {
  nonce: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // includes the 16-byte GCM tag
  senderPk: Uint8Array;
  recipientPk: Uint8Array; // whatever key the sender BELIEVED was the recipient's
}

export async function seal(
  senderSk: Uint8Array,
  senderPk: Uint8Array,
  recipientPk: Uint8Array,
  plaintext: string,
): Promise<SealedMessage> {
  const shared = dh(senderSk, recipientPk);
  const key = await deriveAesKey(shared, senderPk, recipientPk);
  const nonce = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce.buffer.slice(0) as ArrayBuffer },
    key,
    utf8ToBytes(plaintext).buffer.slice(0) as ArrayBuffer,
  );
  return { nonce, ciphertext: new Uint8Array(ct), senderPk, recipientPk };
}

/** Returns the plaintext, or null if the AES-GCM tag check fails (fail-closed). */
export async function open(recipientSk: Uint8Array, msg: SealedMessage): Promise<string | null> {
  try {
    const shared = dh(recipientSk, msg.senderPk);
    const key = await deriveAesKey(shared, msg.senderPk, msg.recipientPk);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: msg.nonce.buffer.slice(0) as ArrayBuffer },
      key,
      msg.ciphertext.buffer.slice(0) as ArrayBuffer,
    );
    return bytesToUtf8(new Uint8Array(pt));
  } catch {
    return null;
  }
}
