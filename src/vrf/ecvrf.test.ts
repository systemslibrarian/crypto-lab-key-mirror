/**
 * ECVRF-EDWARDS25519-SHA512-TAI known-answer tests.
 * Vectors: RFC 9381 Appendix B.3, Examples 16, 17, 18 (all of them).
 */

import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../core/bytes';
import { publicKey, proofToHash, vrfProve, vrfVerify } from './ecvrf';

interface Vector {
  name: string;
  sk: string;
  pk: string;
  alpha: string;
  ctr: number;
  h: string;
  pi: string;
  beta: string;
}

const VECTORS: Vector[] = [
  {
    name: 'Example 16 (empty alpha)',
    sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    alpha: '',
    ctr: 0,
    h: '91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318',
    pi: '8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805',
    beta: '90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae',
  },
  {
    name: 'Example 17 (alpha = 0x72)',
    sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    alpha: '72',
    ctr: 1,
    h: '5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551',
    pi: 'f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02',
    beta: 'eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031',
  },
  {
    name: 'Example 18 (alpha = 0xaf82)',
    sk: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    alpha: 'af82',
    ctr: 0,
    h: 'bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a',
    pi: '9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e',
    beta: '645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f',
  },
];

describe('ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381 B.3 vectors', () => {
  for (const v of VECTORS) {
    it(`${v.name}: prove matches pi, beta, H, and ctr`, () => {
      const sk = hexToBytes(v.sk);
      expect(bytesToHex(publicKey(sk))).toBe(v.pk);
      const proof = vrfProve(sk, hexToBytes(v.alpha));
      expect(bytesToHex(proof.intermediates.hPoint)).toBe(v.h);
      expect(proof.intermediates.ctr).toBe(v.ctr);
      expect(bytesToHex(proof.pi)).toBe(v.pi);
      expect(bytesToHex(proof.beta)).toBe(v.beta);
    });

    it(`${v.name}: verify accepts and returns beta`, () => {
      const res = vrfVerify(hexToBytes(v.pk), hexToBytes(v.alpha), hexToBytes(v.pi));
      expect(res.valid).toBe(true);
      expect(bytesToHex(res.beta!)).toBe(v.beta);
    });
  }

  it('proof_to_hash recomputes beta from pi alone', () => {
    for (const v of VECTORS) {
      expect(bytesToHex(proofToHash(hexToBytes(v.pi))!)).toBe(v.beta);
    }
  });

  it('rejects a proof presented for a different alpha', () => {
    const v = VECTORS[0];
    expect(vrfVerify(hexToBytes(v.pk), hexToBytes('42'), hexToBytes(v.pi)).valid).toBe(false);
  });

  it('rejects a proof presented under a different public key', () => {
    const [a, b] = VECTORS;
    expect(vrfVerify(hexToBytes(b.pk), hexToBytes(a.alpha), hexToBytes(a.pi)).valid).toBe(false);
  });

  it('rejects a bit-flipped proof and malformed encodings (fail-closed)', () => {
    const v = VECTORS[2];
    const pk = hexToBytes(v.pk);
    const alpha = hexToBytes(v.alpha);
    const flipped = hexToBytes(v.pi);
    flipped[40] ^= 0x01; // inside the challenge c
    expect(vrfVerify(pk, alpha, flipped).valid).toBe(false);
    expect(vrfVerify(pk, alpha, hexToBytes(v.pi).slice(0, 79)).valid).toBe(false);
    // An all-zero pi decodes (Gamma = a small-order point) but verify rejects it.
    expect(vrfVerify(pk, alpha, new Uint8Array(80)).valid).toBe(false);
    // s >= q must be rejected at decode
    const badS = hexToBytes(v.pi);
    badS.fill(0xff, 48, 80);
    expect(vrfVerify(pk, alpha, badS).valid).toBe(false);
  });

  it('rejects a small-order public key (validate_key)', () => {
    const v = VECTORS[0];
    const identity = new Uint8Array(32);
    identity[0] = 0x01; // ed25519 encoding of the identity element (y = 1)
    expect(vrfVerify(identity, hexToBytes(v.alpha), hexToBytes(v.pi)).valid).toBe(false);
  });

  it('is deterministic: same input, same beta; different input, different beta', () => {
    const sk = hexToBytes(VECTORS[0].sk);
    const a = vrfProve(sk, new TextEncoder().encode('bob'));
    const b = vrfProve(sk, new TextEncoder().encode('bob'));
    const c = vrfProve(sk, new TextEncoder().encode('boc'));
    expect(bytesToHex(a.beta)).toBe(bytesToHex(b.beta));
    expect(bytesToHex(a.beta)).not.toBe(bytesToHex(c.beta));
  });
});
