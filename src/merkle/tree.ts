/**
 * RFC 6962 Merkle tree (the append-only log under Certificate Transparency
 * and the IETF KEYTRANS authenticated map's log layer).
 *
 * Hand-rolled on purpose — this IS the teaching subject. Every hash is real
 * SHA-256 via WebCrypto; nothing is simulated.
 *
 *   leaf hash:  H(0x00 || leaf)
 *   node hash:  H(0x01 || left || right)
 *   MTH of the empty list = H("")
 *
 * Proof generation follows RFC 6962 §2.1.1 (audit path) and §2.1.2
 * (consistency proof) verbatim, in the same recursive form as the spec.
 */

import { concatBytes } from '../core/bytes';
import { sha256 } from '../core/sha256';

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export async function leafHash(leaf: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(LEAF_PREFIX, leaf));
}

export async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

/** Largest power of two strictly less than n (n >= 2). */
export function splitPoint(n: number): number {
  let k = 1;
  while (2 * k < n) k *= 2;
  return k;
}

/** MTH(D[n]) — Merkle Tree Hash of a list of leaves (RFC 6962 §2.1). */
export async function merkleTreeHash(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  if (leaves.length === 1) return leafHash(leaves[0]);
  const k = splitPoint(leaves.length);
  const left = await merkleTreeHash(leaves.slice(0, k));
  const right = await merkleTreeHash(leaves.slice(k));
  return nodeHash(left, right);
}

/** PATH(m, D[n]) — audit path for leaf index m (0-based) in tree of n leaves. */
export async function inclusionProof(m: number, leaves: Uint8Array[]): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m < 0 || m >= n) throw new Error(`leaf index ${m} out of range for tree of ${n}`);
  if (n === 1) return [];
  const k = splitPoint(n);
  if (m < k) {
    const path = await inclusionProof(m, leaves.slice(0, k));
    path.push(await merkleTreeHash(leaves.slice(k)));
    return path;
  }
  const path = await inclusionProof(m - k, leaves.slice(k));
  path.push(await merkleTreeHash(leaves.slice(0, k)));
  return path;
}

/** PROOF(m, D[n]) — consistency proof between the first m leaves and all n (RFC 6962 §2.1.2). */
export async function consistencyProof(m: number, leaves: Uint8Array[]): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m <= 0 || m > n) throw new Error(`old size ${m} out of range for tree of ${n}`);
  if (m === n) return [];
  return subProof(m, leaves, true);
}

async function subProof(m: number, leaves: Uint8Array[], isCompleteSubtree: boolean): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m === n) {
    return isCompleteSubtree ? [] : [await merkleTreeHash(leaves)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    const proof = await subProof(m, leaves.slice(0, k), isCompleteSubtree);
    proof.push(await merkleTreeHash(leaves.slice(k)));
    return proof;
  }
  const proof = await subProof(m - k, leaves.slice(k), false);
  proof.push(await merkleTreeHash(leaves.slice(0, k)));
  return proof;
}

/**
 * An append-only log: leaves plus cached roots per size ("snapshots").
 * This is the server-side object; verifiers never see it — they see only
 * roots and proofs, which is the entire point of the lab.
 */
export class MerkleLog {
  private leaves: Uint8Array[] = [];

  get size(): number {
    return this.leaves.length;
  }

  async append(leaf: Uint8Array): Promise<void> {
    this.leaves.push(leaf);
  }

  leafAt(i: number): Uint8Array {
    return this.leaves[i];
  }

  allLeaves(): Uint8Array[] {
    return this.leaves.slice();
  }

  /** Root over the first `size` leaves (defaults to the current size). */
  async root(size = this.size): Promise<Uint8Array> {
    if (size < 0 || size > this.size) throw new Error('snapshot out of range');
    return merkleTreeHash(this.leaves.slice(0, size));
  }

  async proveInclusion(index: number, size = this.size): Promise<Uint8Array[]> {
    if (size < 1 || size > this.size) throw new Error('snapshot out of range');
    return inclusionProof(index, this.leaves.slice(0, size));
  }

  async proveConsistency(oldSize: number, newSize = this.size): Promise<Uint8Array[]> {
    if (newSize > this.size) throw new Error('snapshot out of range');
    return consistencyProof(oldSize, this.leaves.slice(0, newSize));
  }

  /** Fork: a new log sharing this one's history. // [extension] point — epoch-bounded forks */
  fork(): MerkleLog {
    const copy = new MerkleLog();
    copy.leaves = this.leaves.slice();
    return copy;
  }
}
