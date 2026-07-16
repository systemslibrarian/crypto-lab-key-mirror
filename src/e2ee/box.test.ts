/**
 * E2EE box tests: RFC 7748 §6.1 X25519 Diffie-Hellman KAT, round trips,
 * tamper rejection, and the key-substitution property the whole lab teaches.
 */

import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../core/bytes';
import { dh, generateKeyPair, keyPairFromSeed, open, seal } from './box';

// RFC 7748 §6.1 test vector
const ALICE_SK = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
const ALICE_PK = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
const BOB_SK = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
const BOB_PK = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
const SHARED = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

describe('X25519 — RFC 7748 §6.1 vector', () => {
  it('derives the spec public keys from the spec secret keys', () => {
    expect(bytesToHex(keyPairFromSeed(hexToBytes(ALICE_SK)).publicKey)).toBe(ALICE_PK);
    expect(bytesToHex(keyPairFromSeed(hexToBytes(BOB_SK)).publicKey)).toBe(BOB_PK);
  });

  it('both sides derive the spec shared secret', () => {
    expect(bytesToHex(dh(hexToBytes(ALICE_SK), hexToBytes(BOB_PK)))).toBe(SHARED);
    expect(bytesToHex(dh(hexToBytes(BOB_SK), hexToBytes(ALICE_PK)))).toBe(SHARED);
  });
});

describe('seal/open', () => {
  it('round-trips a message to the intended recipient', async () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const msg = await seal(alice.secretKey, alice.publicKey, bob.publicKey, 'hi Bob — it’s Alice');
    expect(await open(bob.secretKey, msg)).toBe('hi Bob — it’s Alice');
  });

  it('rejects a tampered ciphertext and a tampered nonce (GCM tag)', async () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const msg = await seal(alice.secretKey, alice.publicKey, bob.publicKey, 'attack at dawn');
    const tampered = { ...msg, ciphertext: msg.ciphertext.slice() };
    tampered.ciphertext[0] ^= 0x01;
    expect(await open(bob.secretKey, tampered)).toBe(null);
    const badNonce = { ...msg, nonce: msg.nonce.slice() };
    badNonce.nonce[0] ^= 0x01;
    expect(await open(bob.secretKey, badNonce)).toBe(null);
  });

  it('a third party without either secret key cannot open', async () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const eve = generateKeyPair();
    const msg = await seal(alice.secretKey, alice.publicKey, bob.publicKey, 'secret');
    expect(await open(eve.secretKey, msg)).toBe(null);
  });

  it('KEY SUBSTITUTION: if the directory lies, the attacker opens the message and Bob cannot', async () => {
    // This is the flaw the lab exists to teach: the crypto is not broken,
    // the binding between "Bob" and a key is.
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const mallory = generateKeyPair();
    // Alice asked the directory for Bob's key and got Mallory's instead.
    const msg = await seal(alice.secretKey, alice.publicKey, mallory.publicKey, 'for Bob only');
    expect(await open(mallory.secretKey, msg)).toBe('for Bob only'); // attack succeeds
    expect(await open(bob.secretKey, msg)).toBe(null); // Bob never sees it
  });
});
