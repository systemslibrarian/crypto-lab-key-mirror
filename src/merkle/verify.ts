/**
 * Independent Merkle proof verifiers (RFC 9162 §2.1.3.2 / §2.1.4.2).
 *
 * Deliberately written from the verifier's side only: these functions never
 * see the leaf list, just a claimed root, a size, and a proof. Fail-closed:
 * every malformed input returns false, never throws into the UI.
 */

import { bytesEqual } from '../core/bytes';
import { leafHash, nodeHash } from './tree';

export function isHash(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.length === 32;
}

export function validProof(proof: unknown): proof is Uint8Array[] {
  if (!Array.isArray(proof)) return false;
  for (const node of proof) if (!isHash(node)) return false;
  return true;
}

/** Avoid signed 32-bit masks and floating-point log2 rounding near 2^53. */
export function isPowerOfTwo(size: number): boolean {
  if (!Number.isSafeInteger(size) || size < 1) return false;
  while (size % 2 === 0) size /= 2;
  return size === 1;
}

/** Verify an RFC 6962 audit path for leaf (0-based leafIndex) in a tree of treeSize. */
export async function verifyInclusion(
  leaf: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize)) return false;
  if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;
  if (!(leaf instanceof Uint8Array) || !isHash(root) || !validProof(proof)) return false;

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = await leafHash(leaf);
  for (const p of proof) {
    if (p.length !== 32) return false;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        // right-hand edge of an incomplete subtree: skip missing levels
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
        if (fn === 0 && sn !== 0) {
          // consumed the whole index; remaining proof entries would be extra
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(r, root);
}

/** Verify an RFC 6962 consistency proof between (oldSize, oldRoot) and (newSize, newRoot). */
export async function verifyConsistency(
  oldSize: number,
  oldRoot: Uint8Array,
  newSize: number,
  newRoot: Uint8Array,
  proof: Uint8Array[],
): Promise<boolean> {
  if (!Number.isSafeInteger(oldSize) || !Number.isSafeInteger(newSize)) return false;
  if (oldSize < 1 || oldSize > newSize) return false;
  if (!isHash(oldRoot) || !isHash(newRoot) || !validProof(proof)) return false;
  if (oldSize === newSize) {
    return proof.length === 0 && bytesEqual(oldRoot, newRoot);
  }

  // If oldSize is an exact power of two, the old root itself is the first node.
  const path = proof.slice();
  const completeSubtree = isPowerOfTwo(oldSize);
  if (completeSubtree) {
    path.unshift(oldRoot);
  }
  if (path.length === 0) return false;

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = path[0];
  let sr = path[0];
  if (completeSubtree && !bytesEqual(fr, oldRoot)) return false;

  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (c.length !== 32) return false;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot);
}
