/** Shared types for the key directory, its clients, and the gossip layer. */

export type ViewName = 'main' | 'shadow';

/** Which defenses the querying client enforces. Cumulative: each layer includes the ones below. */
export type DefenseLayer = 0 | 1 | 2 | 3 | 4;

export const LAYER_NAMES: Record<DefenseLayer, string> = {
  0: 'Bare lookup — trust the server',
  1: 'Signed directory responses',
  2: 'Merkle tree + inclusion proof',
  3: 'Append-only + consistency proof',
  4: 'Gossip — compare roots across users',
};

export interface SignedTreeHead {
  epoch: number;
  size: number;
  root: Uint8Array;
  signature: Uint8Array; // ed25519 by the directory over (epoch, size, root)
}

export interface Binding {
  user: string;
  keyHex: string;
  epoch: number; // epoch at which this binding was appended
}

export interface LookupResponse {
  binding: Binding;
  /** Layer 1+: server's signature over the binding itself. */
  bindingSignature: Uint8Array;
  /** Layer 2+: STH and inclusion proof for the binding's leaf. */
  sth: SignedTreeHead;
  leafIndex: number;
  leaf: Uint8Array;
  inclusionProof: Uint8Array[];
  /** Layer 3+: consistency proof from the client's previously seen STH (if any). */
  consistency: { fromSize: number; proof: Uint8Array[] } | null;
}

export interface CheckResult {
  label: string;
  ok: boolean;
  detail: string;
}
