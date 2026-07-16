/**
 * The lab's system-level tests: an equivocating directory defeats layers 0-3
 * (every client-side check passes while the two views disagree), gossip
 * proves the lie, and self-monitoring finds the planted key.
 */

import { describe, expect, it } from 'vitest';
import { bytesToHex } from '../core/bytes';
import { generateKeyPair, open, seal } from '../e2ee/box';
import { verifyInclusion } from '../merkle/verify';
import { DirectoryClient, gossip, monitorOwnBindings } from './client';
import { KeyDirectory } from './server';
import type { DefenseLayer } from './types';

async function setup() {
  const dir = new KeyDirectory();
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const carol = generateKeyPair();
  const mallory = generateKeyPair();
  await dir.register('alice', bytesToHex(alice.publicKey));
  await dir.register('bob', bytesToHex(bob.publicKey));
  await dir.register('carol', bytesToHex(carol.publicKey));
  return { dir, alice, bob, carol, mallory };
}

describe('honest directory', () => {
  it('all layers pass and both views return the same key', async () => {
    const { dir, bob } = await setup();
    const aliceClient = new DirectoryClient('alice', dir.signingPk);
    const carolClient = new DirectoryClient('carol', dir.signingPk);

    for (const layer of [0, 1, 2, 3] as DefenseLayer[]) {
      const resA = await dir.lookup('bob', 'shadow', aliceClient.lastSTH?.size ?? null);
      const resC = await dir.lookup('bob', 'main', carolClient.lastSTH?.size ?? null);
      expect(resA!.binding.keyHex).toBe(bytesToHex(bob.publicKey));
      expect(resA!.binding.keyHex).toBe(resC!.binding.keyHex);
      expect((await aliceClient.verify(resA!, layer)).every((c) => c.ok)).toBe(true);
      expect((await carolClient.verify(resC!, layer)).every((c) => c.ok)).toBe(true);
    }

    const g = gossip(await dir.signedTreeHead('shadow'), await dir.signedTreeHead('main'), dir.signingPk);
    expect(g.rootsMatch).toBe(true);
    expect(g.equivocationProven).toBe(false);
  });

  it('consistency check keeps passing across honest appends', async () => {
    const { dir } = await setup();
    const client = new DirectoryClient('alice', dir.signingPk);
    let res = await dir.lookup('bob', 'shadow', null);
    expect((await client.verify(res!, 3)).every((c) => c.ok)).toBe(true);
    await dir.register('dave', bytesToHex(generateKeyPair().publicKey));
    res = await dir.lookup('bob', 'shadow', client.lastSTH!.size);
    expect((await client.verify(res!, 3)).every((c) => c.ok)).toBe(true);
  });
});

describe('equivocating directory — the attack', () => {
  it('layers 0-3: every client-side check passes, yet Alice and Carol hold different keys for bob', async () => {
    const { dir, bob, mallory } = await setup();
    await dir.equivocate('bob', bytesToHex(bob.publicKey), bytesToHex(mallory.publicKey));

    const aliceClient = new DirectoryClient('alice', dir.signingPk);
    const carolClient = new DirectoryClient('carol', dir.signingPk);

    for (const layer of [0, 1, 2, 3] as DefenseLayer[]) {
      const resA = await dir.lookup('bob', 'shadow', aliceClient.lastSTH?.size ?? null);
      const resC = await dir.lookup('bob', 'main', carolClient.lastSTH?.size ?? null);

      // THE FLAW, EXHIBITED: all real crypto checks pass on both sides...
      expect(
        (await aliceClient.verify(resA!, layer)).every((c) => c.ok),
        `alice checks at layer ${layer}`,
      ).toBe(true);
      expect(
        (await carolClient.verify(resC!, layer)).every((c) => c.ok),
        `carol checks at layer ${layer}`,
      ).toBe(true);

      // ...while the directory told the two users different things.
      expect(resA!.binding.keyHex).toBe(bytesToHex(mallory.publicKey));
      expect(resC!.binding.keyHex).toBe(bytesToHex(bob.publicKey));
    }
  });

  it('consistency proofs keep passing per-view even as the fork grows', async () => {
    const { dir, bob, mallory } = await setup();
    const aliceClient = new DirectoryClient('alice', dir.signingPk);
    // Alice anchors BEFORE the fork.
    let resA = await dir.lookup('bob', 'shadow', null);
    await aliceClient.verify(resA!, 3);

    await dir.equivocate('bob', bytesToHex(bob.publicKey), bytesToHex(mallory.publicKey));
    await dir.register('erin', bytesToHex(generateKeyPair().publicKey));

    resA = await dir.lookup('bob', 'shadow', aliceClient.lastSTH!.size);
    const checks = await aliceClient.verify(resA!, 3);
    expect(checks.every((c) => c.ok)).toBe(true); // her forked history is self-consistent
    expect(resA!.binding.keyHex).toBe(bytesToHex(mallory.publicKey)); // and still a lie
  });

  it('the E2EE math cooperates fully with the lie (attack end-to-end)', async () => {
    const { dir, alice, bob, mallory } = await setup();
    await dir.equivocate('bob', bytesToHex(bob.publicKey), bytesToHex(mallory.publicKey));
    const res = await dir.lookup('bob', 'shadow', null);
    const keyAliceGot = res!.binding.keyHex;

    const msg = await seal(
      alice.secretKey,
      alice.publicKey,
      Uint8Array.from(Buffer.from(keyAliceGot, 'hex')),
      'my location: 41.5, -81.6',
    );
    expect(await open(mallory.secretKey, msg)).toBe('my location: 41.5, -81.6');
    expect(await open(bob.secretKey, msg)).toBe(null);
  });

  it('layer 4 gossip: two signed heads, same epoch, different roots — equivocation PROVEN', async () => {
    const { dir, bob, mallory } = await setup();
    await dir.equivocate('bob', bytesToHex(bob.publicKey), bytesToHex(mallory.publicKey));

    const sthAlice = await dir.signedTreeHead('shadow');
    const sthCarol = await dir.signedTreeHead('main');
    const g = gossip(sthAlice, sthCarol, dir.signingPk);

    expect(g.sameEpoch).toBe(true);
    expect(g.bothSigned).toBe(true); // the server authenticated BOTH stories
    expect(g.rootsMatch).toBe(false);
    expect(g.equivocationProven).toBe(true);
  });

  it('gossip does not false-positive across different epochs', async () => {
    const { dir } = await setup();
    const before = await dir.signedTreeHead('main');
    await dir.register('erin', bytesToHex(generateKeyPair().publicKey));
    const after = await dir.signedTreeHead('main');
    const g = gossip(before, after, dir.signingPk);
    expect(g.equivocationProven).toBe(false);
  });
});

describe('self-monitoring (the payoff: detection requires participation)', () => {
  it('Bob finds a key under his name that he never generated, with a valid inclusion proof', async () => {
    const { dir, bob, mallory } = await setup();
    await dir.equivocate('bob', bytesToHex(bob.publicKey), bytesToHex(mallory.publicKey));

    // Bob audits the view that was served to Alice.
    const bindings = dir.viewBindings('shadow');
    const findings = monitorOwnBindings('bob', bindings, [bytesToHex(bob.publicKey)]);
    const planted = findings.filter((f) => !f.recognized);
    expect(planted.length).toBe(1);
    expect(planted[0].keyHex).toBe(bytesToHex(mallory.publicKey));

    // The planted key is provably IN the log — the attack left evidence.
    const res = await dir.lookup('bob', 'shadow', null);
    expect(
      await verifyInclusion(res!.leaf, res!.leafIndex, res!.sth.size, res!.inclusionProof, res!.sth.root),
    ).toBe(true);
  });

  it('an honest history shows only keys Bob recognizes', async () => {
    const { dir, bob } = await setup();
    const findings = monitorOwnBindings('bob', dir.viewBindings('main'), [bytesToHex(bob.publicKey)]);
    expect(findings.length).toBe(1);
    expect(findings.every((f) => f.recognized)).toBe(true);
  });
});
