/** Plain-language on-ramp — zero math, before any hex (§2 pedagogy standard). */

import { el } from './dom';

export function mountIntro(container: HTMLElement): void {
  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'intro-h' },
      el('h2', { id: 'intro-h' }, 'What is key transparency?'),
      el(
        'p',
        { className: 'panel-lede' },
        'When you message someone on an end-to-end-encrypted app, your phone first asks the app\'s server: ',
        el('em', {}, '“what is this person\'s public key?”'),
        ' Encryption then guarantees that only the holder of that key can read your message. But it cannot tell you whether the key actually belongs to your friend — or to an attacker the server decided to show you instead.',
      ),
      el(
        'p',
        { className: 'panel-lede' },
        'Key transparency forces the server to publish every key it ever hands out in one append-only, cryptographically verifiable log — the same Merkle-tree machinery behind Certificate Transparency. The server can still lie. But it can no longer lie ',
        el('em', {}, 'quietly'),
        ': a lie told to one user and not another becomes a permanent, provable artifact that the users — or anyone auditing — can catch.',
      ),
      el(
        'p',
        { className: 'note' },
        'This lab runs the attack first, then rebuilds the defense one layer at a time — every proof below is a real SHA-256 Merkle computation checked by a real verifier, and every signature is real ed25519. Not production crypto: a teaching demo.',
      ),
    ),
  );
}
