import { describe, expect, it } from 'vitest';
import { CT_FIXTURE } from './ct-fixture';
import { leafHash, nodeHash } from './tree';
import { verifyConsistency, verifyInclusion } from './verify';
import { traceConsistency } from './trace';

const decode = (value: string) => new Uint8Array(Buffer.from(value, 'base64'));
const leaf = new TextEncoder().encode('repeated leaf');

// Independent recursive RFC tree/path definition over a virtual repeated-leaf
// tree. BigInt sizes avoid the verifier's Number counters; no giant allocation.
async function virtualTree() {
  const cache = new Map<bigint, Uint8Array>();
  const split = (n: bigint) => { let k = 1n; while (2n * k < n) k *= 2n; return k; };
  const root = async (n: bigint): Promise<Uint8Array> => {
    const found = cache.get(n); if (found) return found;
    const k = split(n);
    const result = n === 1n ? await leafHash(leaf) : await nodeHash(await root(k), await root(n - k));
    cache.set(n, result); return result;
  };
  const path = async (index: bigint, size: bigint): Promise<Uint8Array[]> => {
    if (size === 1n) return [];
    const k = split(size);
    return index < k ? [...await path(index, k), await root(size - k)]
      : [...await path(index - k, size - k), await root(k)];
  };
  return { root, path };
}

describe('safe integer Merkle proof counters', () => {
  it('accepts the independently pinned historical Google CT inclusion proof above 2^31', async () => {
    const data = decode(CT_FIXTURE.leafInputB64);
    const proof = CT_FIXTURE.auditPathB64.map(decode);
    const root = decode(CT_FIXTURE.rootHashB64);
    expect(await verifyInclusion(data, CT_FIXTURE.leafIndex, CT_FIXTURE.treeSize, proof, root)).toBe(true);
    const changed = proof.map(node => node.slice()); changed[0][0] ^= 1;
    expect(await verifyInclusion(data, CT_FIXTURE.leafIndex, CT_FIXTURE.treeSize, changed, root)).toBe(false);
    expect(await verifyInclusion(data, CT_FIXTURE.leafIndex, CT_FIXTURE.treeSize, proof.slice(1), root)).toBe(false);
  });

  it('accepts recursive inclusion controls through Number.MAX_SAFE_INTEGER', async () => {
    const tree = await virtualTree();
    for (const size of [2n ** 31n, 2n ** 32n + 1n, 2n ** 40n + 7n, BigInt(Number.MAX_SAFE_INTEGER)]) {
      const index = size - 1n;
      expect(await verifyInclusion(leaf, Number(index), Number(size), await tree.path(index, size), await tree.root(size))).toBe(true);
    }
  });

  it('verifies large power-of-two consistency roots without a 32-bit mask', async () => {
    const tree = await virtualTree(); const next = await leafHash(new TextEncoder().encode('next leaf'));
    for (const size of [2n ** 31n, 2n ** 32n, 2n ** 40n, 2n ** 52n]) {
      const old = await tree.root(size); const updated = await nodeHash(old, next);
      expect(await verifyConsistency(Number(size), old, Number(size + 1n), updated, [next])).toBe(true);
      expect((await traceConsistency(Number(size), old, Number(size + 1n), updated, [next])).valid).toBe(true);
      expect(await verifyConsistency(Number(size), old, Number(size + 1n), old, [next])).toBe(false);
    }
  });

  it('handles an incomplete large subtree whose old size is not a power of two', async () => {
    const tree = await virtualTree(); const size = 2n ** 32n;
    const left = await tree.root(size); const a = await leafHash(new Uint8Array([1])); const b = await leafHash(new Uint8Array([2]));
    const old = await nodeHash(left, a); const updated = await nodeHash(left, await nodeHash(a, b));
    expect(await verifyConsistency(Number(size + 1n), old, Number(size + 2n), updated, [a, b, left])).toBe(true);
    expect((await traceConsistency(Number(size + 1n), old, Number(size + 2n), updated, [a, b, left])).valid).toBe(true);
    expect(await verifyConsistency(Number(size + 1n), old, Number(size + 2n), updated, [a, left])).toBe(false);
  });

  it('rejects unsafe, fractional and nonfinite counters, including same-size shortcuts', async () => {
    const root = await leafHash(leaf);
    for (const size of [Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, 1.5]) {
      expect(await verifyConsistency(size, root, size, root, [])).toBe(false);
      expect((await traceConsistency(size, root, size, root, [])).valid).toBe(false);
      expect(await verifyInclusion(leaf, 0, size, [], root)).toBe(false);
    }
    expect(await verifyInclusion(leaf, Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER + 2, [], root)).toBe(false);
  });

  it('rejects malformed hashes and proof containers without a false same-size success', async () => {
    const root = await leafHash(leaf);
    expect(await verifyConsistency(1, new Uint8Array(), 1, new Uint8Array(), [])).toBe(false);
    expect((await traceConsistency(1, new Uint8Array(), 1, new Uint8Array(), [])).valid).toBe(false);
    expect(await verifyConsistency(1, root, 2, root, [new Uint8Array(31)])).toBe(false);
    expect(await verifyInclusion(leaf, 0, 1, null as unknown as Uint8Array[], root)).toBe(false);
    expect(await verifyInclusion(leaf, 0, 2, [null as unknown as Uint8Array], root)).toBe(false);
    expect(await verifyInclusion(leaf, 0, 2, new Array<Uint8Array>(1), root)).toBe(false);
    expect((await traceConsistency(1, root, 2, root, new Array<Uint8Array>(1))).valid).toBe(false);
  });
});
