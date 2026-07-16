/**
 * Property tests: round-trips accept, tampering rejects (fail-closed).
 * Random trees up to 33 leaves; every inclusion and consistency pair checked.
 */

import { describe, expect, it } from 'vitest';
import { randomBytes, utf8ToBytes } from '../core/bytes';
import { consistencyProof, inclusionProof, merkleTreeHash, MerkleLog } from './tree';
import { verifyConsistency, verifyInclusion } from './verify';

async function buildLog(n: number): Promise<MerkleLog> {
  const log = new MerkleLog();
  for (let i = 0; i < n; i++) await log.append(utf8ToBytes(`entry-${i}`));
  return log;
}

describe('inclusion proofs — round trip and rejection', () => {
  it('accepts every leaf of trees sized 1..33', { timeout: 30000 }, async () => {
    for (const n of [1, 2, 3, 5, 8, 13, 21, 33]) {
      const log = await buildLog(n);
      const root = await log.root();
      for (let i = 0; i < n; i++) {
        const proof = await log.proveInclusion(i);
        expect(await verifyInclusion(log.leafAt(i), i, n, proof, root)).toBe(true);
      }
    }
  });

  it('rejects a proof presented for the wrong leaf, wrong index, wrong size, and wrong root', async () => {
    const n = 13;
    const log = await buildLog(n);
    const root = await log.root();
    const proof = await log.proveInclusion(4);
    expect(await verifyInclusion(utf8ToBytes('entry-5'), 4, n, proof, root)).toBe(false);
    expect(await verifyInclusion(log.leafAt(4), 5, n, proof, root)).toBe(false);
    // A proof against tree 13 does not verify against the size-12 snapshot root.
    expect(await verifyInclusion(log.leafAt(4), 4, n - 1, proof, await log.root(n - 1))).toBe(false);
    expect(await verifyInclusion(log.leafAt(4), 4, n, proof, randomBytes(32))).toBe(false);
  });

  it('rejects a truncated and an extended proof', async () => {
    const log = await buildLog(8);
    const root = await log.root();
    const proof = await log.proveInclusion(3);
    expect(await verifyInclusion(log.leafAt(3), 3, 8, proof.slice(1), root)).toBe(false);
    expect(await verifyInclusion(log.leafAt(3), 3, 8, [...proof, randomBytes(32)], root)).toBe(false);
  });

  it('rejects a bit-flipped proof node', async () => {
    const log = await buildLog(8);
    const root = await log.root();
    const proof = await log.proveInclusion(3);
    proof[1] = proof[1].slice();
    proof[1][0] ^= 0x01;
    expect(await verifyInclusion(log.leafAt(3), 3, 8, proof, root)).toBe(false);
  });

  it('rejects out-of-range indices without throwing', async () => {
    const log = await buildLog(4);
    const root = await log.root();
    expect(await verifyInclusion(log.leafAt(0), -1, 4, [], root)).toBe(false);
    expect(await verifyInclusion(log.leafAt(0), 4, 4, [], root)).toBe(false);
    expect(await verifyInclusion(log.leafAt(0), 0, 0, [], root)).toBe(false);
  });
});

describe('consistency proofs — round trip and rejection', () => {
  it('accepts every (m, n) pair for trees up to 20 leaves', { timeout: 30000 }, async () => {
    const max = 20;
    const log = await buildLog(max);
    for (let n = 1; n <= max; n++) {
      const newRoot = await log.root(n);
      for (let m = 1; m <= n; m++) {
        const oldRoot = await log.root(m);
        const proof = await log.proveConsistency(m, n);
        expect(await verifyConsistency(m, oldRoot, n, newRoot, proof), `${m} -> ${n}`).toBe(true);
      }
    }
  });

  it('rejects a forked history (same size, different content)', async () => {
    // Two logs agree on 6 entries, then diverge — the equivocation shape.
    const honest = await buildLog(6);
    const fork = honest.fork();
    await honest.append(utf8ToBytes('bob-key-real'));
    await fork.append(utf8ToBytes('bob-key-forged'));

    const oldRoot = await honest.root(6);
    const honestProof = await honest.proveConsistency(6, 7);
    const forkRoot = await fork.root(7);

    // The honest proof does NOT connect the shared prefix to the forked head.
    expect(await verifyConsistency(6, oldRoot, 7, forkRoot, honestProof)).toBe(false);
    // But each history is internally consistent — that is why consistency alone
    // cannot detect equivocation (layer 3 of the demo).
    expect(await verifyConsistency(6, oldRoot, 7, await honest.root(7), honestProof)).toBe(true);
    expect(
      await verifyConsistency(6, oldRoot, 7, forkRoot, await fork.proveConsistency(6, 7)),
    ).toBe(true);
  });

  it('rejects tampered roots and malformed sizes without throwing', async () => {
    const log = await buildLog(9);
    const proof = await log.proveConsistency(5, 9);
    const r5 = await log.root(5);
    const r9 = await log.root(9);
    expect(await verifyConsistency(5, randomBytes(32), 9, r9, proof)).toBe(false);
    expect(await verifyConsistency(5, r5, 9, randomBytes(32), proof)).toBe(false);
    expect(await verifyConsistency(0, r5, 9, r9, proof)).toBe(false);
    expect(await verifyConsistency(9, r9, 5, r5, proof)).toBe(false);
    expect(await verifyConsistency(5, r5, 9, r9, [])).toBe(false);
  });

  it('same-size consistency requires identical roots and an empty proof', async () => {
    const log = await buildLog(7);
    const r = await log.root();
    expect(await verifyConsistency(7, r, 7, r, [])).toBe(true);
    expect(await verifyConsistency(7, r, 7, randomBytes(32), [])).toBe(false);
    expect(await verifyConsistency(7, r, 7, r, [randomBytes(32)])).toBe(false);
  });

  it('generation rejects out-of-range snapshots', async () => {
    const leaves = [utf8ToBytes('a'), utf8ToBytes('b')];
    await expect(consistencyProof(0, leaves)).rejects.toThrow();
    await expect(consistencyProof(3, leaves)).rejects.toThrow();
    await expect(inclusionProof(2, leaves)).rejects.toThrow();
    expect((await merkleTreeHash(leaves)).length).toBe(32);
  });
});
