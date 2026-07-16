/**
 * ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381, ciphersuite suite_string = 0x03.
 *
 * Hand-rolled per the RFC (prove / verify / proof_to_hash and all auxiliary
 * functions), using @noble/curves only for the edwards25519 group arithmetic
 * and @noble/hashes for SHA-512. This is the label-privacy primitive of the
 * lab: it maps a username to an unpredictable, verifiable tree label without
 * letting observers reverse the directory into a user list.
 *
 * Validated against all three RFC 9381 Appendix B.3 vectors (Examples 16-18).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { concatBytes } from '../core/bytes';

const SUITE = new Uint8Array([0x03]);
const COFACTOR = 8n;
const Q = ed25519.CURVE.n; // group order (prime subgroup)

type Point = InstanceType<typeof ed25519.ExtendedPoint>;
const Point = ed25519.ExtendedPoint;

/** RFC 8032 §5.1.5 secret-scalar derivation: SHA-512(SK)[0..31], clamped. */
export function secretScalar(sk: Uint8Array): bigint {
  const h = sha512(sk);
  const b = h.slice(0, 32);
  b[0] &= 248;
  b[31] &= 127;
  b[31] |= 64;
  return bytesToNumberLE(b);
}

export function publicKey(sk: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(sk);
}

/** string_to_point per RFC 8032 §5.1.3 — returns null for invalid encodings. */
function stringToPoint(s: Uint8Array): Point | null {
  try {
    return Point.fromHex(s, false); // strict RFC 8032 decoding
  } catch {
    return null;
  }
}

/**
 * ECVRF_encode_to_curve_try_and_increment (RFC 9381 §5.4.1.1).
 * Also returns the counter that succeeded, so the UI can show the search.
 */
export function encodeToCurveTAI(
  salt: Uint8Array,
  alpha: Uint8Array,
): { H: Point; ctr: number } {
  for (let ctr = 0; ctr < 256; ctr++) {
    const hashString = sha512(
      concatBytes(SUITE, new Uint8Array([0x01]), salt, alpha, new Uint8Array([ctr]), new Uint8Array([0x00])),
    );
    const candidate = stringToPoint(hashString.slice(0, 32));
    if (candidate === null) continue;
    const H = candidate.multiplyUnsafe(COFACTOR);
    if (H.equals(Point.ZERO)) continue;
    return { H, ctr };
  }
  // Probability ~2^-256 per the RFC; unreachable in practice.
  throw new Error('encode_to_curve failed after 256 attempts');
}

/** ECVRF_nonce_generation_RFC8032 (RFC 9381 §5.4.2.2). */
export function nonceRFC8032(sk: Uint8Array, hString: Uint8Array): bigint {
  const hashedSk = sha512(sk);
  const kString = sha512(concatBytes(hashedSk.slice(32, 64), hString));
  return bytesToNumberLE(kString) % Q;
}

/** ECVRF_challenge_generation (RFC 9381 §5.4.3): 16-byte challenge over 5 points. */
export function challenge(points: Point[]): bigint {
  const parts: Uint8Array[] = [SUITE, new Uint8Array([0x02])];
  for (const p of points) parts.push(p.toRawBytes());
  parts.push(new Uint8Array([0x00]));
  const cString = sha512(concatBytes(...parts));
  return bytesToNumberLE(cString.slice(0, 16));
}

export interface VrfProof {
  pi: Uint8Array; // 80 bytes: Gamma (32) || c (16) || s (32)
  beta: Uint8Array; // 64 bytes: the VRF output
  /** Intermediates exposed for the teaching UI. */
  intermediates: { hPoint: Uint8Array; ctr: number; k: bigint; c: bigint };
}

/** ECVRF_prove (RFC 9381 §5.1). */
export function vrfProve(sk: Uint8Array, alpha: Uint8Array): VrfProof {
  // Reduce the clamped scalar mod the subgroup order: identical point results
  // (H and B have order q), and noble requires scalars < q.
  const x = secretScalar(sk) % Q;
  const pkString = publicKey(sk);
  const { H, ctr } = encodeToCurveTAI(pkString, alpha);
  const hString = H.toRawBytes();
  const Gamma = H.multiplyUnsafe(x);
  const k = nonceRFC8032(sk, hString);
  const Y = Point.fromHex(pkString, false);
  const U = Point.BASE.multiplyUnsafe(k);
  const V = H.multiplyUnsafe(k);
  const c = challenge([Y, H, Gamma, U, V]);
  const s = (k + c * x) % Q;
  const pi = concatBytes(Gamma.toRawBytes(), numberToBytesLE(c, 16), numberToBytesLE(s, 32));
  return {
    pi,
    beta: proofToHash(pi)!,
    intermediates: { hPoint: hString, ctr, k, c },
  };
}

/** ECVRF_decode_proof (RFC 9381 §5.4.4). Null = INVALID. */
export function decodeProof(pi: Uint8Array): { Gamma: Point; c: bigint; s: bigint } | null {
  if (pi.length !== 80) return null;
  const Gamma = stringToPoint(pi.slice(0, 32));
  if (Gamma === null) return null;
  const c = bytesToNumberLE(pi.slice(32, 48));
  const s = bytesToNumberLE(pi.slice(48, 80));
  if (s >= Q) return null;
  return { Gamma, c, s };
}

/** ECVRF_proof_to_hash (RFC 9381 §5.2). Null = INVALID. */
export function proofToHash(pi: Uint8Array): Uint8Array | null {
  const d = decodeProof(pi);
  if (d === null) return null;
  const gammaCleared = d.Gamma.multiplyUnsafe(COFACTOR);
  return sha512(
    concatBytes(SUITE, new Uint8Array([0x03]), gammaCleared.toRawBytes(), new Uint8Array([0x00])),
  );
}

/**
 * ECVRF_verify (RFC 9381 §5.3), with validate_key = TRUE (full collision
 * resistance under malicious key generation — the directory server IS the
 * adversary in this lab, so key validation is not optional).
 */
export function vrfVerify(
  pkString: Uint8Array,
  alpha: Uint8Array,
  pi: Uint8Array,
): { valid: boolean; beta: Uint8Array | null } {
  const Y = stringToPoint(pkString);
  if (Y === null) return { valid: false, beta: null };
  if (Y.multiplyUnsafe(COFACTOR).equals(Point.ZERO)) return { valid: false, beta: null };
  const d = decodeProof(pi);
  if (d === null) return { valid: false, beta: null };
  const { Gamma, c, s } = d;
  const { H } = encodeToCurveTAI(pkString, alpha);
  const U = Point.BASE.multiplyUnsafe(s).subtract(Y.multiplyUnsafe(c));
  const V = H.multiplyUnsafe(s).subtract(Gamma.multiplyUnsafe(c));
  const cPrime = challenge([Y, H, Gamma, U, V]);
  if (c !== cPrime) return { valid: false, beta: null };
  return { valid: true, beta: proofToHash(pi) };
}
