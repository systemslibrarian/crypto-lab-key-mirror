/** Honest scoping card — what this lab is, isn't, and does not prove (§0.2, §1 SCOPE). */

import { el } from './dom';
import { LABS } from './links';

export function mountScope(container: HTMLElement): void {
  const a = (href: string, text: string) => el('a', { href, target: '_blank', rel: 'noopener' }, text);

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'scope-h' },
      el('h2', { id: 'scope-h' }, 'Honest scoping — what this lab is not'),
      el(
        'p',
        { className: 'honesty' },
        'Transparency is DETECTION, not prevention. In every attack run above, Mallory read Alice’s messages — and detection did not undo that. What transparency changes is the cost: the attack leaves permanent, signed, third-party-verifiable evidence, and an attacker who must leave receipts usually declines to attack.',
      ),
      el(
        'ul',
        { className: 'checklist' },
        el(
          'li',
          {},
          el('span', { className: 'check-label' }, 'Not a messaging-protocol rebuild.'),
          el(
            'div',
            { className: 'check-detail' },
            'The E2EE here is a single sealed box, deliberately minimal. Group keys, session setup, and self-healing ratchets are their own labs: ',
            a(LABS.mlsGroup, 'mls-group'),
            ', ',
            a(LABS.x3dhWire, 'x3dh-wire'),
            ', ',
            a(LABS.ratchetWire, 'ratchet-wire'),
            '.',
          ),
        ),
        el(
          'li',
          {},
          el('span', { className: 'check-label' }, 'Not a Certificate Transparency rebuild.'),
          el(
            'div',
            { className: 'check-detail' },
            'CT logs certificates for domain names; KT logs public keys for user identities — same Merkle machinery, different directory. For CT itself see ',
            a(LABS.pkiChain, 'pki-chain'),
            ', ',
            a(LABS.merkleProofs, 'merkle-proofs'),
            ', ',
            a(LABS.merkleVault, 'merkle-vault'),
            '.',
          ),
        ),
        el(
          'li',
          {},
          el('span', { className: 'check-label' }, 'No real network gossip.'),
          el(
            'div',
            { className: 'check-detail' },
            '“Gossip” here is two in-page clients comparing signed tree heads. Deployed systems route heads through auditors, other providers, or anonymized channels — the comparison logic is the same, the transport is not built here.',
          ),
        ),
        el(
          'li',
          {},
          el('span', { className: 'check-label' }, 'Not the CONIKS or KEYTRANS wire format.'),
          el(
            'div',
            { className: 'check-detail' },
            'Real KEYTRANS uses a VRF-addressed prefix tree (an authenticated map) with a log of its roots; this lab uses a flat RFC 6962 log of bindings plus a stand-alone VRF exhibit so each mechanism is visible on its own. The trust conclusions carry over; the byte formats do not.',
          ),
        ),
      ),
      el(
        'p',
        { className: 'note' },
        'What is real here: SHA-256 Merkle trees with RFC 6962 proofs (pinned to the CT reference vectors), RFC 6962/9162 verification, ed25519 signatures, X25519+HKDF+AES-GCM encryption, and RFC 9381 ECVRF (pinned to Appendix B.3). What is simulated: the network, the passage of epochs, and the actors. What this does not prove: that any real deployment is secure — key material here is per-session and this page is a teaching demo, not production crypto.',
      ),
    ),
  );
}
