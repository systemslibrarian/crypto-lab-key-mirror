/**
 * The verifying client: everything a user's app can check WITHOUT talking to
 * another user. Layers 0-3 all run here — and all of them pass against a
 * well-executed equivocation, which is the lesson.
 *
 * Every check verifies real crypto (ed25519 / SHA-256 Merkle) and reports its
 * own result independently. The client never collapses "the math checked out"
 * into "you are safe" — that verdict belongs to the caller (and to gossip).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { bytesEqual, bytesToHex } from '../core/bytes';
import { verifyConsistency, verifyInclusion } from '../merkle/verify';
import { bindingLeaf, bindingMessage, sthMessage } from './server';
import type { CheckResult, DefenseLayer, LookupResponse, SignedTreeHead } from './types';

export class DirectoryClient {
  /** Last tree head this client accepted — the anchor for consistency checks. */
  lastSTH: SignedTreeHead | null = null;

  constructor(
    readonly name: string,
    private readonly directoryPk: Uint8Array,
  ) {}

  /**
   * Run every check the given layer enforces. Returns one CheckResult per
   * check, each independently pass/fail. Does NOT return a verdict — a
   * response can pass every layer-3 check and still be a lie.
   */
  async verify(res: LookupResponse, layer: DefenseLayer): Promise<CheckResult[]> {
    const out: CheckResult[] = [];

    if (layer >= 1) {
      const ok = ed25519.verify(res.bindingSignature, bindingMessage(res.binding), this.directoryPk);
      out.push({
        label: 'ed25519 signature over binding',
        ok,
        detail: ok
          ? `directory signed “${res.binding.user} → ${res.binding.keyHex.slice(0, 16)}…” — authentic, straight from the server`
          : 'signature does not verify under the directory key',
      });
    }

    if (layer >= 2) {
      const sthOk = ed25519.verify(
        res.sth.signature,
        sthMessage(res.sth.epoch, res.sth.size, res.sth.root),
        this.directoryPk,
      );
      out.push({
        label: 'ed25519 signature over tree head',
        ok: sthOk,
        detail: sthOk
          ? `STH(epoch ${res.sth.epoch}, size ${res.sth.size}, root ${bytesToHex(res.sth.root).slice(0, 16)}…) is authentic`
          : 'tree head signature does not verify',
      });
      const leafOk = bytesEqual(res.leaf, bindingLeaf(res.binding));
      const incOk =
        leafOk &&
        (await verifyInclusion(res.leaf, res.leafIndex, res.sth.size, res.inclusionProof, res.sth.root));
      out.push({
        label: 'Merkle inclusion proof',
        ok: incOk,
        detail: incOk
          ? `leaf ${res.leafIndex} provably in the tree behind root ${bytesToHex(res.sth.root).slice(0, 16)}…`
          : 'inclusion proof does not reach the signed root',
      });
    }

    if (layer >= 3) {
      if (this.lastSTH === null) {
        out.push({
          label: 'Merkle consistency proof',
          ok: true,
          detail: 'first contact — nothing to be consistent with yet (trust on first use)',
        });
      } else if (res.consistency === null || res.consistency.fromSize !== this.lastSTH.size) {
        out.push({
          label: 'Merkle consistency proof',
          ok: false,
          detail: 'server did not prove consistency with the tree head I already hold',
        });
      } else {
        const ok = await verifyConsistency(
          this.lastSTH.size,
          this.lastSTH.root,
          res.sth.size,
          res.sth.root,
          res.consistency.proof,
        );
        out.push({
          label: 'Merkle consistency proof',
          ok,
          detail: ok
            ? `my old root (size ${this.lastSTH.size}) is provably a prefix of the new tree (size ${res.sth.size}) — nothing I saw was retracted`
            : 'the new tree is NOT an extension of the tree I already accepted',
        });
      }
    }

    // Accept the new head as this client's anchor if everything enforced passed.
    if (out.every((c) => c.ok)) this.lastSTH = res.sth;
    return out;
  }
}

/**
 * Layer 4 — gossip. Two clients compare the signed tree heads their views of
 * the directory gave them for the same epoch. Honest directory: identical.
 * Equivocating directory: two different roots, both signed — which is not
 * just detection but transferable cryptographic evidence.
 */
export interface GossipResult {
  sameEpoch: boolean;
  rootsMatch: boolean;
  bothSigned: boolean;
  /** true = equivocation proven: two validly signed heads, same epoch, different roots. */
  equivocationProven: boolean;
}

export function gossip(a: SignedTreeHead, b: SignedTreeHead, directoryPk: Uint8Array): GossipResult {
  const sameEpoch = a.epoch === b.epoch && a.size === b.size;
  const rootsMatch = bytesEqual(a.root, b.root);
  const bothSigned =
    ed25519.verify(a.signature, sthMessage(a.epoch, a.size, a.root), directoryPk) &&
    ed25519.verify(b.signature, sthMessage(b.epoch, b.size, b.root), directoryPk);
  return {
    sameEpoch,
    rootsMatch,
    bothSigned,
    equivocationProven: sameEpoch && bothSigned && !rootsMatch,
  };
}

/**
 * Self-monitoring — Bob audits every binding published under HIS name in a
 * view of the log. A key he never generated is an intrusion, and its
 * inclusion proof turns the attack into evidence.
 */
export interface MonitorFinding {
  index: number;
  keyHex: string;
  epoch: number;
  recognized: boolean;
}

export function monitorOwnBindings(
  user: string,
  bindings: { user: string; keyHex: string; epoch: number }[],
  ownKeysHex: string[],
): MonitorFinding[] {
  const own = new Set(ownKeysHex);
  const findings: MonitorFinding[] = [];
  bindings.forEach((b, index) => {
    if (b.user === user) {
      findings.push({ index, keyHex: b.keyHex, epoch: b.epoch, recognized: own.has(b.keyHex) });
    }
  });
  return findings;
}
