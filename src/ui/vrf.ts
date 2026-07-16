/**
 * Exhibit 4 — VRF LABEL PRIVACY. Real ECVRF-EDWARDS25519-SHA512-TAI
 * (RFC 9381, KAT-tested against Appendix B.3) maps a username to its tree
 * label: unpredictable to observers, verifiable by the user who holds the
 * proof. Deep dive lives in the sibling vrf-gate lab.
 */

import { bytesToHex, utf8ToBytes } from '../core/bytes';
import { publicKey, vrfProve, vrfVerify } from '../vrf/ecvrf';
import { clear, el, liveRegion, resultChip, short, verdictChip } from './dom';
import { LABS } from './links';
import { getState } from './state';

export function mountVrf(container: HTMLElement): void {
  const state = getState();
  const vrfPk = publicKey(state.vrfSk);

  const out = liveRegion();
  const observer = el('div', {});
  const nameInput = el('input', { type: 'text', id: 'vrf-name', value: 'bob' }) as HTMLInputElement;
  const deriveBtn = el('button', { className: 'btn btn-primary', id: 'vrf-derive', type: 'button' }, 'Derive private label') as HTMLButtonElement;
  const tamperBtn = el('button', { className: 'btn btn-danger', id: 'vrf-tamper', type: 'button', disabled: true }, 'Flip a byte in the proof') as HTMLButtonElement;

  let lastPi: Uint8Array | null = null;
  let lastName = '';

  function treeIndex(beta: Uint8Array): number {
    // Teaching projection: first 3 bytes of beta → an index into 2^24 slots.
    return (beta[0] << 16) | (beta[1] << 8) | beta[2];
  }

  // A realistic-sized directory so the anonymity is visceral, not a toy of three.
  const DIRECTORY_USERS = [
    'alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi',
    'ivan', 'judy', 'mallory', 'niaj', 'olivia', 'peggy', 'rupert',
    'sybil', 'trent', 'victor', 'walter', 'wendy', 'craig', 'chuck',
  ];

  function renderObserver(highlight: string | null): void {
    clear(observer);
    // Every account's real VRF label, sorted by label — i.e. tree order, which
    // is exactly what an observer walking the published tree would see.
    const searchSet = highlight && !DIRECTORY_USERS.includes(highlight) ? [...DIRECTORY_USERS, highlight] : DIRECTORY_USERS;
    const labels = searchSet
      .map((u) => ({ u, beta: vrfProve(state.vrfSk, utf8ToBytes(u)).beta }))
      .sort((a, b) => bytesToHex(a.beta).localeCompare(bytesToHex(b.beta)));
    const ul = el('ul', { className: 'label-list', role: 'list' });
    for (const { u, beta } of labels) {
      const mine = highlight === u;
      ul.append(
        el(
          'li',
          { className: mine ? 'label-mine' : '', role: 'listitem' },
          el('code', {}, `slot ${treeIndex(beta).toString().padStart(8, '0')} · label ${short(bytesToHex(beta), 24)}`),
          mine ? ' ← the label you just derived (only YOU can prove it maps to your name)' : '',
        ),
      );
    }
    observer.append(
      el('h3', {}, `What an observer sees: ${labels.length} opaque labels`),
      el(
        'p',
        { className: 'note' },
        highlight
          ? `Your name’s label is highlighted — but that link is only visible to you, because only you can produce the proof. To everyone else it is one indistinguishable row among ${labels.length}.`
          : `Derive a label above and watch it drop into this list — invisibly, unless you hold the proof.`,
      ),
      el('div', { className: 'label-scroll', tabindex: '0', role: 'region', 'aria-label': 'Published directory labels' }, ul),
      el(
        'p',
        { className: 'note' },
        'The rows are sorted by label (tree order), so position leaks nothing about who registered when. Without the VRF proof for a specific username, no observer can tell which label is whose — or even test whether a given name has an account. The directory stays auditable without becoming a public membership list.',
      ),
    );
  }

  function derive(): void {
    clear(out);
    const name = nameInput.value.trim() || 'bob';
    lastName = name;
    const proof = vrfProve(state.vrfSk, utf8ToBytes(name));
    lastPi = proof.pi;
    tamperBtn.disabled = false;

    const ver = vrfVerify(vrfPk, utf8ToBytes(name), proof.pi);
    out.append(
      el(
        'dl',
        { className: 'kv' },
        el('dt', {}, 'username (VRF input α)'),
        el('dd', {}, el('code', {}, name)),
        el('dt', {}, 'tree slot'),
        el('dd', {}, el('code', {}, String(treeIndex(proof.beta)))),
        el('dt', {}, 'label β = VRF(sk, α) — 64 bytes'),
        el('dd', {}, el('code', {}, bytesToHex(proof.beta))),
        el('dt', {}, 'proof π — 80 bytes (Γ ‖ c ‖ s)'),
        el('dd', {}, el('code', {}, bytesToHex(proof.pi))),
        el('dt', {}, 'try-and-increment counter'),
        el('dd', {}, `hashed to the curve on ctr = ${proof.intermediates.ctr}`),
      ),
      resultChip('ECVRF_verify(pk, α, π) — run as the user', ver.valid),
      el(
        'p',
        { className: 'note' },
        'The user holding π can verify the directory put them in the right slot. Everyone else sees β as pseudorandom bytes.',
      ),
    );
    renderObserver(name);
  }

  function tamper(): void {
    if (!lastPi) return;
    const flipped = lastPi.slice();
    flipped[40] ^= 0x01; // one bit, inside the challenge scalar c
    const ver = vrfVerify(vrfPk, utf8ToBytes(lastName), flipped);
    out.append(
      el(
        'div',
        { className: 'verdict-row' },
        el(
          'div',
          { className: 'verdict-slot' },
          el('p', { className: 'slot-title' }, 'You flipped bit 0 of byte 40 (inside c)'),
          resultChip('ECVRF_verify on the tampered proof', ver.valid),
          verdictChip('safe', 'REJECTED — the directory cannot forge or reassign a label'),
          el(
            'p',
            { className: 'note' },
            'Uniqueness is the property doing the work: for a fixed public key and username there is exactly one β any valid proof can open to, so the server cannot map one user to two slots.',
          ),
        ),
      ),
    );
    tamperBtn.disabled = true;
  }

  deriveBtn.addEventListener('click', derive);
  tamperBtn.addEventListener('click', tamper);

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'vrf-h' },
      el('h2', { id: 'vrf-h' }, '4 · Label privacy — the directory that doesn’t leak its users'),
      el(
        'p',
        { className: 'panel-lede' },
        'A transparent directory has a side effect: publishing every username would hand the world a membership list. KEYTRANS-style systems fix this by addressing the tree with a verifiable random function of the username — real ECVRF (RFC 9381) below, the same construction our tests pin to the spec’s vectors.',
      ),
      el(
        'div',
        { className: 'controls' },
        el('span', { className: 'ctl' }, el('label', { className: 'ctl-label', for: 'vrf-name' }, 'Username'), nameInput),
        deriveBtn,
        tamperBtn,
      ),
      out,
      observer,
      el(
        'p',
        { className: 'note' },
        'This panel shows only the label mapping — the full VRF construction (hash-to-curve, nonce, challenge) gets its own lab: ',
        el('a', { href: LABS.vrfGate, target: '_blank', rel: 'noopener' }, 'vrf-gate'),
        '.',
      ),
    ),
  );

  renderObserver(null);
}
