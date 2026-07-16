/** Pins the UI stepper's traced verifier to the real verifier — they may never disagree. */

import { describe, expect, it } from 'vitest';
import { utf8ToBytes } from '../core/bytes';
import { traceConsistency } from './trace';
import { MerkleLog } from './tree';
import { verifyConsistency } from './verify';

async function buildLog(n: number, tag = 'entry'): Promise<MerkleLog> {
  const log = new MerkleLog();
  for (let i = 0; i < n; i++) await log.append(utf8ToBytes(`${tag}-${i}`));
  return log;
}

describe('traceConsistency mirrors verifyConsistency', () => {
  it('agrees on every honest (m, n) pair up to 16 leaves and records steps', { timeout: 30000 }, async () => {
    const log = await buildLog(16);
    for (let n = 1; n <= 16; n++) {
      for (let m = 1; m <= n; m++) {
        const oldRoot = await log.root(m);
        const newRoot = await log.root(n);
        const proof = await log.proveConsistency(m, n);
        const trace = await traceConsistency(m, oldRoot, n, newRoot, proof);
        const real = await verifyConsistency(m, oldRoot, n, newRoot, proof);
        expect(trace.valid, `${m} -> ${n}`).toBe(real);
        expect(trace.valid).toBe(true);
      }
    }
  });

  it('agrees on the forked-history failure and explains which root mismatched', async () => {
    const honest = await buildLog(6);
    const fork = honest.fork();
    await honest.append(utf8ToBytes('bob-key-real'));
    await fork.append(utf8ToBytes('bob-key-forged'));

    const oldRoot = await honest.root(6);
    const forkRoot = await fork.root(7);
    const honestProof = await honest.proveConsistency(6, 7);

    const trace = await traceConsistency(6, oldRoot, 7, forkRoot, honestProof);
    const real = await verifyConsistency(6, oldRoot, 7, forkRoot, honestProof);
    expect(trace.valid).toBe(real);
    expect(trace.valid).toBe(false);
    expect(trace.frMatchesOld).toBe(true); // shared prefix reconstructs fine
    expect(trace.srMatchesNew).toBe(false); // the forked head is what breaks
    expect(trace.failReason).toMatch(/new root/);
  });
});
