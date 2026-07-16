/**
 * Instrumented consistency verification for the byte-level stepper (Exhibit 3).
 * Runs the SAME RFC 9162 algorithm as verify.ts and records every hash step;
 * a test pins its verdict to verifyConsistency so the UI can never drift from
 * the real verifier.
 */

import { bytesEqual } from '../core/bytes';
import { nodeHash } from './tree';

export interface TraceStep {
  kind: 'seed' | 'combine-left' | 'combine-right' | 'skip';
  description: string;
  fn: number;
  sn: number;
  /** node consumed from the proof (combine steps). */
  node?: Uint8Array;
  /** running hashes after this step. */
  fr: Uint8Array;
  sr: Uint8Array;
}

export interface ConsistencyTrace {
  steps: TraceStep[];
  prepended: boolean;
  finalFr: Uint8Array;
  finalSr: Uint8Array;
  frMatchesOld: boolean;
  srMatchesNew: boolean;
  structureOk: boolean;
  valid: boolean;
  failReason: string | null;
}

export async function traceConsistency(
  oldSize: number,
  oldRoot: Uint8Array,
  newSize: number,
  newRoot: Uint8Array,
  proof: Uint8Array[],
): Promise<ConsistencyTrace> {
  const empty = new Uint8Array(0);
  const fail = (reason: string, steps: TraceStep[] = []): ConsistencyTrace => ({
    steps,
    prepended: false,
    finalFr: empty,
    finalSr: empty,
    frMatchesOld: false,
    srMatchesNew: false,
    structureOk: false,
    valid: false,
    failReason: reason,
  });

  if (oldSize < 1 || oldSize > newSize) return fail('sizes out of range');
  if (oldSize === newSize) {
    const ok = proof.length === 0 && bytesEqual(oldRoot, newRoot);
    return {
      steps: [],
      prepended: false,
      finalFr: oldRoot,
      finalSr: newRoot,
      frMatchesOld: ok,
      srMatchesNew: ok,
      structureOk: proof.length === 0,
      valid: ok,
      failReason: ok ? null : 'equal sizes require identical roots and an empty proof',
    };
  }

  const path = proof.slice();
  const prepended = (oldSize & (oldSize - 1)) === 0;
  if (prepended) path.unshift(oldRoot);
  if (path.length === 0) return fail('empty proof');

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn >>= 1;
    sn >>= 1;
  }

  let fr = path[0];
  let sr = path[0];
  const steps: TraceStep[] = [
    {
      kind: 'seed',
      description: prepended
        ? `old size ${oldSize} is a power of two — seed both running hashes with the OLD ROOT itself`
        : `seed both running hashes with proof node 0 (the node that anchors the old tree's right edge)`,
      fn,
      sn,
      node: path[0],
      fr,
      sr,
    },
  ];

  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return { ...fail('proof longer than the tree allows', steps) };
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      steps.push({
        kind: 'combine-left',
        description: `node ${i} sits LEFT of both trees' running hashes: fr = H(0x01‖node‖fr), sr = H(0x01‖node‖sr)`,
        fn,
        sn,
        node: c,
        fr,
        sr,
      });
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = await nodeHash(sr, c);
      steps.push({
        kind: 'combine-right',
        description: `node ${i} exists only in the NEW tree: sr = H(0x01‖sr‖node); fr unchanged`,
        fn,
        sn,
        node: c,
        fr,
        sr,
      });
    }
    fn >>= 1;
    sn >>= 1;
  }

  const structureOk = sn === 0;
  const frMatchesOld = bytesEqual(fr, oldRoot);
  const srMatchesNew = bytesEqual(sr, newRoot);
  const valid = structureOk && frMatchesOld && srMatchesNew;
  return {
    steps,
    prepended,
    finalFr: fr,
    finalSr: sr,
    frMatchesOld,
    srMatchesNew,
    structureOk,
    valid,
    failReason: valid
      ? null
      : !structureOk
        ? 'proof shape does not match the claimed sizes'
        : !frMatchesOld
          ? 'reconstructed old root does not match the root the client already holds'
          : 'reconstructed new root does not match the tree head the server just signed',
  };
}
