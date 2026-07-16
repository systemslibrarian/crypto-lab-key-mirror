/**
 * The key directory server — honest by default, and when switched, an
 * EQUIVOCATING directory that maintains two internally consistent Merkle
 * logs: the `shadow` view served to the victim (Alice) and the `main` view
 * served to everyone else.
 *
 * Everything the server hands out is real: real SHA-256 Merkle proofs over
 * real logs, real ed25519 signatures. That is the point — every layer of
 * client-side verification below gossip passes *because* the server's lie is
 * cryptographically well-formed.
 *
 * The deliberately-malicious mode is never the default and is isolated here.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '../core/bytes';
import { MerkleLog } from '../merkle/tree';
import type { Binding, LookupResponse, SignedTreeHead, ViewName } from './types';

const STH_DOMAIN = utf8ToBytes('key-mirror/sth/v1');
const BINDING_DOMAIN = utf8ToBytes('key-mirror/binding/v1');

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

/** Canonical leaf bytes for a (user, key, epoch) binding. */
export function bindingLeaf(b: Binding): Uint8Array {
  return concatBytes(utf8ToBytes(b.user), new Uint8Array([0x00]), hexToBytes(b.keyHex), u64le(b.epoch));
}

export function sthMessage(epoch: number, size: number, root: Uint8Array): Uint8Array {
  return concatBytes(STH_DOMAIN, u64le(epoch), u64le(size), root);
}

export function bindingMessage(b: Binding): Uint8Array {
  return concatBytes(BINDING_DOMAIN, bindingLeaf(b));
}

interface View {
  log: MerkleLog;
  bindings: Binding[]; // parallel to log leaves
}

export class KeyDirectory {
  readonly signingPk: Uint8Array;
  private readonly signingSk: Uint8Array;
  private epoch = 0;
  private malicious = false;
  private views: Record<ViewName, View>;

  constructor() {
    this.signingSk = randomBytes(32);
    this.signingPk = ed25519.getPublicKey(this.signingSk);
    const main: View = { log: new MerkleLog(), bindings: [] };
    // While honest, `shadow` IS `main` (same object): one log, one truth.
    this.views = { main, shadow: main };
  }

  get isMalicious(): boolean {
    return this.malicious;
  }

  get currentEpoch(): number {
    return this.epoch;
  }

  /** Append a binding to every active view (an honest registration/update). */
  async register(user: string, keyHex: string): Promise<Binding> {
    this.epoch++;
    const b: Binding = { user, keyHex, epoch: this.epoch };
    await this.views.main.log.append(bindingLeaf(b));
    this.views.main.bindings.push(b);
    if (this.views.shadow !== this.views.main) {
      await this.views.shadow.log.append(bindingLeaf(b));
      this.views.shadow.bindings.push(b);
    }
    return b;
  }

  /**
   * Flip to equivocation: fork the log. From this epoch on, the shadow view
   * (served to the victim) records `attackerKeyHex` as `victimUser`'s key,
   * while the main view records the genuine key. Both histories share every
   * leaf up to the fork and remain append-only afterwards.
   */
  async equivocate(victimUser: string, realKeyHex: string, attackerKeyHex: string): Promise<void> {
    if (this.malicious) return;
    this.malicious = true;
    this.epoch++;
    const shadow: View = { log: this.views.main.log.fork(), bindings: this.views.main.bindings.slice() };
    this.views.shadow = shadow;

    const lie: Binding = { user: victimUser, keyHex: attackerKeyHex, epoch: this.epoch };
    await shadow.log.append(bindingLeaf(lie));
    shadow.bindings.push(lie);

    const truth: Binding = { user: victimUser, keyHex: realKeyHex, epoch: this.epoch };
    await this.views.main.log.append(bindingLeaf(truth));
    this.views.main.bindings.push(truth);
  }

  /** Back to honesty: the shadow view is abandoned; one log again. */
  repent(): void {
    this.malicious = false;
    this.views.shadow = this.views.main;
  }

  async signedTreeHead(view: ViewName): Promise<SignedTreeHead> {
    const v = this.views[view];
    const size = v.log.size;
    const root = await v.log.root();
    const signature = ed25519.sign(sthMessage(this.epoch, size, root), this.signingSk);
    return { epoch: this.epoch, size, root, signature };
  }

  /**
   * Answer a lookup from one view, with every artifact any defense layer
   * could ask for. The server is maximally cooperative — its proofs are all
   * genuine. `clientLastSize` drives the consistency proof (layer 3).
   */
  async lookup(user: string, view: ViewName, clientLastSize: number | null): Promise<LookupResponse | null> {
    const v = this.views[view];
    let index = -1;
    for (let i = v.bindings.length - 1; i >= 0; i--) {
      if (v.bindings[i].user === user) {
        index = i;
        break;
      }
    }
    if (index === -1) return null;
    const binding = v.bindings[index];
    const leaf = v.log.leafAt(index);
    const sth = await this.signedTreeHead(view);
    return {
      binding,
      bindingSignature: ed25519.sign(bindingMessage(binding), this.signingSk),
      sth,
      leafIndex: index,
      leaf,
      inclusionProof: await v.log.proveInclusion(index),
      consistency:
        clientLastSize !== null && clientLastSize >= 1 && clientLastSize <= v.log.size
          ? { fromSize: clientLastSize, proof: await v.log.proveConsistency(clientLastSize) }
          : null,
    };
  }

  /** The full binding list of a view — what a monitor walks. */
  viewBindings(view: ViewName): Binding[] {
    return this.views[view].bindings.slice();
  }

  async inclusionProofFor(view: ViewName, index: number): Promise<Uint8Array[]> {
    return this.views[view].log.proveInclusion(index);
  }
}
