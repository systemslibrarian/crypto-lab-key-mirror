/**
 * Exhibit 2 — THE DEFENSE, LAYER BY LAYER. The learner runs the same attack
 * against each defense layer. Layers 0-3 pass every real check while the lie
 * stands; layer 4 (gossip) is where the two histories collide.
 *
 * Verdict separation is the whole design here: the left column shows raw
 * crypto results (neutral ✓/✗), the right column shows the system verdict.
 */

import { bytesToHex } from '../core/bytes';
import { DirectoryClient, gossip } from '../directory/client';
import { LAYER_NAMES, type CheckResult, type DefenseLayer } from '../directory/types';
import { clear, el, hexDiff, liveRegion, verdictChip } from './dom';
import { getState } from './state';

const LAYER_LESSON: Record<DefenseLayer, string> = {
  0: 'Alice checked nothing, so there was nothing to fail. Pure trust.',
  1: 'Authentication ≠ consistency. The signature proves the answer came from the directory — and the directory happily signs its lie. Alice now has a *signed* wrong key.',
  2: 'An inclusion proof proves membership in *a* tree. The malicious directory simply keeps two trees and proves Alice’s lie into hers. Every hash checks out.',
  3: 'A consistency proof shows *her own* view was never rewritten — append-only per victim. The directory maintains two append-only histories in parallel, one per audience, and never needs to retract anything.',
  4: 'Alice and Carol finally compare notes: two tree heads for the same epoch and size, both validly signed, different roots. There is no innocent explanation — the signed pair is transferable proof of equivocation.',
};

export function mountLadder(container: HTMLElement): void {
  const state = getState();
  const results = liveRegion();
  const anchorNote = liveRegion('note');
  const runBtn = el('button', { className: 'btn btn-primary', id: 'ladder-run', type: 'button' }, 'Run the lookups at this layer') as HTMLButtonElement;
  const forgetBtn = el('button', { className: 'btn', id: 'ladder-forget', type: 'button' }, 'New devices (forget anchors)') as HTMLButtonElement;

  // PERSISTENT clients — they keep the last tree head they accepted across
  // runs, exactly like a real phone. This is what makes layer 3 honest: an
  // Alice who anchored a head BEFORE the attack can later run a consistency
  // check that PASSES against the forked history — her own view was never
  // rewritten — and is lied to anyway.
  let alice = new DirectoryClient('alice', state.dir.signingPk);
  let carol = new DirectoryClient('carol', state.dir.signingPk);

  function anchorState(): void {
    const a = alice.lastSTH ? `size ${alice.lastSTH.size} (epoch ${alice.lastSTH.epoch})` : 'nothing yet';
    const c = carol.lastSTH ? `size ${carol.lastSTH.size} (epoch ${carol.lastSTH.epoch})` : 'nothing yet';
    anchorNote.textContent = `Anchored tree heads — Alice: ${a} · Carol: ${c}. Run once while the directory is honest, then turn on the attack and run layer 3 again to watch consistency pass across the fork.`;
  }

  const radios: HTMLInputElement[] = [];
  const fields = el('fieldset', { className: 'layers' }, el('legend', {}, 'Defense layer the clients enforce'));
  ([0, 1, 2, 3, 4] as DefenseLayer[]).forEach((n) => {
    const input = el('input', {
      type: 'radio',
      name: 'layer',
      id: `layer-${n}`,
      value: String(n),
      ...(n === 0 ? { checked: true } : {}),
    }) as HTMLInputElement;
    radios.push(input);
    fields.append(el('span', { className: 'layer-opt' }, input, el('label', { for: `layer-${n}` }, `${n} — ${LAYER_NAMES[n]}`)));
  });

  function chosenLayer(): DefenseLayer {
    return Number(radios.find((r) => r.checked)?.value ?? 0) as DefenseLayer;
  }

  function checksList(title: string, checks: CheckResult[]): HTMLElement {
    const ul = el('ul', { className: 'checklist' });
    if (checks.length === 0) {
      ul.append(el('li', {}, el('span', { className: 'check-label' }, 'no checks at this layer'), el('div', { className: 'check-detail' }, 'the client accepts whatever the server says')));
    }
    for (const c of checks) {
      ul.append(
        el(
          'li',
          { className: c.ok ? '' : 'check-fail' },
          el('span', { className: 'check-label' }, `${c.ok ? '✓' : '✗'} ${c.label}`),
          el('div', { className: 'check-detail' }, c.detail),
        ),
      );
    }
    return el('div', { className: 'verdict-slot' }, el('p', { className: 'slot-title' }, title), ul);
  }

  async function run(): Promise<void> {
    clear(results);
    const layer = chosenLayer();
    const malicious = state.dir.isMalicious;

    // Pass each client's anchored size so the server must produce a real
    // consistency proof from the head that client already holds (layer 3).
    const anchoredBefore = alice.lastSTH !== null;
    const resA = (await state.dir.lookup('bob', 'shadow', alice.lastSTH?.size ?? null))!;
    const resC = (await state.dir.lookup('bob', 'main', carol.lastSTH?.size ?? null))!;
    const checksA = await alice.verify(resA, layer);
    const checksC = await carol.verify(resC, layer);
    anchorState();

    const row1 = el('div', { className: 'verdict-row' });
    row1.append(checksList('Alice’s checks (client-side, real crypto)', checksA));
    row1.append(checksList('Carol’s checks (client-side, real crypto)', checksC));
    results.append(row1);

    // The omniscient lab view — what no single client can see.
    const keyA = resA.binding.keyHex;
    const keyC = resC.binding.keyHex;
    const diff = hexDiff(keyA, keyC);
    const truthSlot = el(
      'div',
      { className: 'verdict-slot' },
      el('p', { className: 'slot-title' }, 'Lab’s omniscient view (no client sees this)'),
      el('span', { className: 'hexlabel' }, 'key handed to Alice'),
      diff.aNode,
      el('span', { className: 'hexlabel' }, 'key handed to Carol'),
      diff.bNode,
    );

    // The verdict — SEPARATE from the checks, per the visual-semantics rule.
    const verdictSlot = el('div', { className: 'verdict-slot' }, el('p', { className: 'slot-title' }, 'Security verdict'));
    const allChecksPassed = [...checksA, ...checksC].every((c) => c.ok);
    const checksSummary = el(
      'p',
      { className: 'chip chip-neutral' },
      el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, allChecksPassed ? '✓' : '✗'),
      `${[...checksA, ...checksC].filter((c) => c.ok).length}/${checksA.length + checksC.length} crypto checks passed`,
    );

    if (layer === 4) {
      const sthA = resA.sth;
      const sthC = resC.sth;
      const g = gossip(sthA, sthC, state.dir.signingPk);
      const rootDiff = hexDiff(bytesToHex(sthA.root), bytesToHex(sthC.root));
      const gossipSlot = el(
        'div',
        { className: 'verdict-slot' },
        el('p', { className: 'slot-title' }, 'Gossip: Alice and Carol swap signed tree heads'),
        el('span', { className: 'hexlabel' }, `Alice’s head (epoch ${sthA.epoch}, size ${sthA.size}) — signature ${g.bothSigned ? 'valid ✓' : 'invalid ✗'}`),
        rootDiff.aNode,
        el('span', { className: 'hexlabel' }, `Carol’s head (epoch ${sthC.epoch}, size ${sthC.size}) — signature ${g.bothSigned ? 'valid ✓' : 'invalid ✗'}`),
        rootDiff.bNode,
      );
      results.append(el('div', { className: 'verdict-row' }, truthSlot, gossipSlot));

      verdictSlot.append(checksSummary);
      if (g.equivocationProven) {
        verdictSlot.append(
          verdictChip('safe', 'EQUIVOCATION PROVEN — two signed heads, same epoch, different roots'),
          verdictChip('warn', 'Detection, not prevention — messages Alice already sent were already read'),
        );
      } else {
        verdictSlot.append(verdictChip('safe', 'Roots match — one history, no equivocation this epoch'));
      }
    } else {
      results.append(el('div', { className: 'verdict-row' }, truthSlot));
      verdictSlot.append(checksSummary);
      if (malicious) {
        verdictSlot.append(
          verdictChip('alarm', `LIE UNDETECTED at layer ${layer} — Alice is encrypting to the attacker`),
        );
        if (layer === 3 && anchoredBefore) {
          const consistencyCheck = checksA.find((c) => c.label.includes('consistency'));
          if (consistencyCheck?.ok) {
            verdictSlot.append(
              verdictChip('warn', 'Consistency PASSED across the fork — and still missed the lie'),
              el(
                'p',
                { className: 'note' },
                'Alice already held an earlier tree head. The server proved her new (forked) head extends that anchor — genuinely, because it never rewrote her view; it just grew a second history beside it. Append-only is not single-history.',
              ),
            );
          }
        }
      } else {
        verdictSlot.append(verdictChip('safe', 'CONSISTENT — both users got the same key'));
      }
    }
    verdictSlot.append(el('p', { className: 'note' }, LAYER_LESSON[layer]));
    results.append(el('div', { className: 'verdict-row' }, verdictSlot));
  }

  runBtn.addEventListener('click', () => void run());
  forgetBtn.addEventListener('click', () => {
    alice = new DirectoryClient('alice', state.dir.signingPk);
    carol = new DirectoryClient('carol', state.dir.signingPk);
    clear(results);
    anchorState();
  });
  // Flipping the attack does NOT reset the clients — keeping their anchors is
  // the point. Just clear stale results.
  state.onModeChange.push(() => clear(results));

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'ladder-h' },
      el('h2', { id: 'ladder-h' }, '2 · The defense — each layer earned by the attack it fails to stop'),
      el(
        'p',
        { className: 'panel-lede' },
        'Pick how much verification Alice’s and Carol’s clients do, then run their lookups against the directory as it currently stands (use the toggle in Exhibit 1 to make it malicious). Every proof the server produces is genuine — watch how far genuine proofs carry a lie.',
      ),
      fields,
      el('div', { className: 'controls' }, runBtn, forgetBtn),
      anchorNote,
      results,
      el(
        'details',
        { className: 'expert' },
        el('summary', {}, 'Expert view: what each artifact actually is'),
        el(
          'p',
          { className: 'note' },
          'Layer 1 signs the binding (ed25519 over a domain-separated encoding). Layer 2 adds an RFC 6962 signed tree head and an audit path to the binding’s leaf. Layer 3 adds an RFC 6962 consistency proof from the client’s previously accepted head. Layer 4 is out-of-band: the clients compare heads directly, which deployed systems approximate with gossip protocols, third-party auditors, or anonymized head checks. In IETF KEYTRANS the map is a prefix tree over VRF labels with an inclusion proof per epoch; the log-of-roots plays the role the plain log plays here.',
        ),
      ),
    ),
  );

  anchorState();
}
