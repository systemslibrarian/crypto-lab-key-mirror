/** Sibling labs this demo links out to instead of rebuilding (scope guard). */
const gh = (repo: string) => `https://systemslibrarian.github.io/${repo}/`;

export const LABS = {
  catalog: 'https://crypto-lab.systemslibrarian.dev/',
  vrfGate: gh('crypto-lab-vrf-gate'),
  mlsGroup: gh('crypto-lab-mls-group'),
  x3dhWire: gh('crypto-lab-x3dh-wire'),
  ratchetWire: gh('crypto-lab-ratchet-wire'),
  pkiChain: gh('crypto-lab-pki-chain'),
  merkleProofs: gh('crypto-lab-merkle-proofs'),
  merkleVault: gh('crypto-lab-merkle-vault'),
} as const;
