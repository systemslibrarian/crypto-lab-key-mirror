/**
 * RFC 6962 Merkle tree known-answer tests.
 *
 * Vectors are the canonical Certificate Transparency reference-tree vectors
 * (google/certificate-transparency merkle_tree_test.cc), the same 8-leaf tree
 * every production CT/KT implementation tests against.
 */

import { describe, expect, it } from 'vitest';
import { hexToBytes, bytesToHex } from '../core/bytes';
import { consistencyProof, inclusionProof, merkleTreeHash, MerkleLog } from './tree';
import { verifyConsistency, verifyInclusion } from './verify';

const INPUTS = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
].map(hexToBytes);

const EMPTY_ROOT = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

// { leafIndex (0-based), treeSize, path }
const PATHS: Array<{ leaf: number; size: number; path: string[] }> = [
  { leaf: 0, size: 1, path: [] },
  {
    leaf: 0,
    size: 8,
    path: [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  },
  {
    leaf: 5,
    size: 8,
    path: [
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  },
  {
    leaf: 2,
    size: 3,
    path: ['fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125'],
  },
  {
    leaf: 1,
    size: 5,
    path: [
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  },
];

// { oldSize, newSize, proof }
const CONSISTENCY: Array<{ s1: number; s2: number; proof: string[] }> = [
  { s1: 1, s2: 1, proof: [] },
  {
    s1: 1,
    s2: 8,
    proof: [
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ],
  },
  {
    s1: 6,
    s2: 8,
    proof: [
      '0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a',
      'ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0',
      'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    ],
  },
  {
    s1: 2,
    s2: 5,
    proof: [
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      'bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b',
    ],
  },
];

describe('RFC 6962 Merkle tree — CT reference vectors', () => {
  it('empty tree root is SHA-256 of the empty string', async () => {
    expect(bytesToHex(await merkleTreeHash([]))).toBe(EMPTY_ROOT);
  });

  it('incremental roots match all 8 CT vectors', async () => {
    for (let i = 0; i < 8; i++) {
      const root = await merkleTreeHash(INPUTS.slice(0, i + 1));
      expect(bytesToHex(root), `root at size ${i + 1}`).toBe(ROOTS[i]);
    }
  });

  it('audit paths match the CT path vectors', async () => {
    for (const v of PATHS) {
      const path = await inclusionProof(v.leaf, INPUTS.slice(0, v.size));
      expect(path.map(bytesToHex), `path(leaf ${v.leaf}, size ${v.size})`).toEqual(v.path);
    }
  });

  it('every CT path vector verifies against its snapshot root', async () => {
    for (const v of PATHS) {
      const ok = await verifyInclusion(
        INPUTS[v.leaf],
        v.leaf,
        v.size,
        v.path.map(hexToBytes),
        hexToBytes(ROOTS[v.size - 1]),
      );
      expect(ok, `verify(leaf ${v.leaf}, size ${v.size})`).toBe(true);
    }
  });

  it('consistency proofs match the CT proof vectors', async () => {
    for (const v of CONSISTENCY) {
      const proof = await consistencyProof(v.s1, INPUTS.slice(0, v.s2));
      expect(proof.map(bytesToHex), `proof(${v.s1} -> ${v.s2})`).toEqual(v.proof);
    }
  });

  it('every CT consistency vector verifies against its two roots', async () => {
    for (const v of CONSISTENCY) {
      const ok = await verifyConsistency(
        v.s1,
        hexToBytes(ROOTS[v.s1 - 1]),
        v.s2,
        hexToBytes(ROOTS[v.s2 - 1]),
        v.proof.map(hexToBytes),
      );
      expect(ok, `verifyConsistency(${v.s1} -> ${v.s2})`).toBe(true);
    }
  });

  it('MerkleLog snapshots reproduce the same roots', async () => {
    const log = new MerkleLog();
    for (const leaf of INPUTS) await log.append(leaf);
    for (let i = 0; i < 8; i++) {
      expect(bytesToHex(await log.root(i + 1))).toBe(ROOTS[i]);
    }
  });
});
