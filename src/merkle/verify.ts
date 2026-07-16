/**
 * Independent Merkle proof verifiers (RFC 9162 §2.1.3.2 / §2.1.4.2).
 *
 * Deliberately written from the verifier's side only: these functions never
 * see the leaf list, just a claimed root, a size, and a proof. Fail-closed:
 * every malformed input returns false, never throws into the UI.
 */

import { bytesEqual } from '../core/bytes';
import { leafHash, nodeHash } from './tree';

/** Verify an RFC 6962 audit path for leaf (0-based leafIndex) in a tree of treeSize. */
export async function verifyInclusion(
  leaf: Uint8Array,
  leafIndex: number,
  treeSize: number,
  proof: Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return false;
  if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;

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
          fn = fn >> 1;
          sn = sn >> 1;
        }
        if (fn === 0 && sn !== 0) {
          // consumed the whole index; remaining proof entries would be extra
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = fn >> 1;
    sn = sn >> 1;
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
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize)) return false;
  if (oldSize < 1 || oldSize > newSize) return false;
  if (oldSize === newSize) {
    return proof.length === 0 && bytesEqual(oldRoot, newRoot);
  }

  // If oldSize is an exact power of two, the old root itself is the first node.
  const path = proof.slice();
  if ((oldSize & (oldSize - 1)) === 0) {
    path.unshift(oldRoot);
  }
  if (path.length === 0) return false;

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = fn >> 1;
    sn = sn >> 1;
  }

  let fr = path[0];
  let sr = path[0];
  if ((oldSize & (oldSize - 1)) === 0 && !bytesEqual(fr, oldRoot)) return false;

  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (c.length !== 32) return false;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = fn >> 1;
        sn = sn >> 1;
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = fn >> 1;
    sn = sn >> 1;
  }
  return sn === 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot);
}
