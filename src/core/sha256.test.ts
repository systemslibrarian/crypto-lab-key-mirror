/** FIPS 180-4 SHA-256 known-answer tests (NIST CAVP short-message vectors). */

import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8ToBytes } from './bytes';
import { sha256 } from './sha256';

describe('SHA-256 — FIPS 180-4 vectors', () => {
  it('empty string', async () => {
    expect(bytesToHex(await sha256(new Uint8Array(0)))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('"abc"', async () => {
    expect(bytesToHex(await sha256(utf8ToBytes('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('two-block message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', async () => {
    expect(
      bytesToHex(await sha256(utf8ToBytes('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    ).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });
});

describe('hex helpers', () => {
  it('round-trips and rejects malformed hex', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
    expect(() => hexToBytes('0f0')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
  });
});
