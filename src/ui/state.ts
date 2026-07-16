/**
 * Shared session state: one directory, four actors, one VRF key.
 * All key material is generated per page load and lives only in memory.
 */

import { bytesToHex } from '../core/bytes';
import { KeyDirectory } from '../directory/server';
import { generateKeyPair, type BoxKeyPair } from '../e2ee/box';

export interface Actor {
  name: string;
  keys: BoxKeyPair;
}

export interface LabState {
  dir: KeyDirectory;
  alice: Actor;
  bob: Actor;
  carol: Actor;
  mallory: Actor;
  vrfSk: Uint8Array;
  /** Panels that need re-rendering when the malicious toggle flips. */
  onModeChange: Array<() => void>;
}

let state: LabState | null = null;

export async function initState(): Promise<LabState> {
  const dir = new KeyDirectory();
  const alice: Actor = { name: 'alice', keys: generateKeyPair() };
  const bob: Actor = { name: 'bob', keys: generateKeyPair() };
  const carol: Actor = { name: 'carol', keys: generateKeyPair() };
  const mallory: Actor = { name: 'mallory', keys: generateKeyPair() };
  await dir.register('alice', bytesToHex(alice.keys.publicKey));
  await dir.register('bob', bytesToHex(bob.keys.publicKey));
  await dir.register('carol', bytesToHex(carol.keys.publicKey));
  state = {
    dir,
    alice,
    bob,
    carol,
    mallory,
    vrfSk: crypto.getRandomValues(new Uint8Array(32)),
    onModeChange: [],
  };
  return state;
}

export function getState(): LabState {
  if (!state) throw new Error('state not initialized');
  return state;
}

export async function setMalicious(on: boolean): Promise<void> {
  const s = getState();
  if (on && !s.dir.isMalicious) {
    await s.dir.equivocate('bob', bytesToHex(s.bob.keys.publicKey), bytesToHex(s.mallory.keys.publicKey));
  } else if (!on && s.dir.isMalicious) {
    s.dir.repent();
  }
  for (const cb of s.onModeChange) cb();
}
