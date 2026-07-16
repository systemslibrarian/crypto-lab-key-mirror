/**
 * Exhibit 5 — SELF-MONITORING, the payoff. An attacker who wants Alice to
 * accept a fake key for Bob must publish that key in a log Bob can read.
 * Bob audits his own history and finds it — with an inclusion proof that
 * turns the intrusion into evidence.
 */

import { bytesToHex } from '../core/bytes';
import { monitorOwnBindings } from '../directory/client';
import { bindingLeaf } from '../directory/server';
import { verifyInclusion } from '../merkle/verify';
import { clear, el, liveRegion, short, verdictChip } from './dom';
import { getState } from './state';

export function mountMonitor(container: HTMLElement): void {
  const state = getState();
  const out = liveRegion();
  const auditBtn = el('button', { className: 'btn btn-primary', id: 'monitor-run', type: 'button' }, 'Bob: audit my own key history') as HTMLButtonElement;

  async function audit(): Promise<void> {
    clear(out);
    const malicious = state.dir.isMalicious;
    // Bob audits the victim-facing view: with gossip forcing a single log,
    // this is the log any successful attack must have written into.
    const view = 'shadow';
    const bindings = state.dir.viewBindings(view);
    const findings = monitorOwnBindings('bob', bindings, [bytesToHex(state.bob.keys.publicKey)]);
    const sth = await state.dir.signedTreeHead(view);

    const ul = el('ul', { className: 'checklist' });
    for (const f of findings) {
      const leafProof = await state.dir.inclusionProofFor(view, f.index);
      const included = await verifyInclusion(
        bindingLeaf(bindings[f.index]),
        f.index,
        sth.size,
        leafProof,
        sth.root,
      );
      ul.append(
        el(
          'li',
          { className: f.recognized ? '' : 'check-fail' },
          el(
            'span',
            { className: 'check-label' },
            f.recognized
              ? `✓ epoch ${f.epoch}: ${short(f.keyHex, 18)} — my key, I registered it`
              : `⚠ epoch ${f.epoch}: ${short(f.keyHex, 18)} — I NEVER generated this key`,
          ),
          el(
            'div',
            { className: 'check-detail' },
            `leaf ${f.index} · inclusion proof against the signed root: ${included ? 'verifies ✓' : 'FAILS ✗'} — ${
              f.recognized ? 'normal history' : 'this entry is now cryptographic evidence of the attack'
            }`,
          ),
        ),
      );
    }

    const verdictSlot = el('div', { className: 'verdict-slot' }, el('p', { className: 'slot-title' }, 'Security verdict'));
    const planted = findings.filter((f) => !f.recognized);
    if (planted.length > 0) {
      verdictSlot.append(
        verdictChip('alarm', `INTRUSION FOUND — ${planted.length} key under Bob’s name that Bob never made`),
        verdictChip('warn', 'Detection, not prevention — whatever Alice sent to that key was already read'),
        el(
          'p',
          { className: 'note' },
          'This only worked because Bob looked. Monitoring is a duty, not a default: in deployed systems it is done by the user’s own devices in the background (WhatsApp, iMessage Contact Key Verification) or delegated to third-party monitors.',
        ),
      );
    } else {
      verdictSlot.append(
        verdictChip('safe', 'CLEAN — every key in Bob’s history is one Bob registered'),
        malicious
          ? el('p', { className: 'note' }, 'The attack is on but the planted key sits in the view served to Alice — run Exhibit 1 first, then audit again.')
          : el('p', { className: 'note' }, 'Turn on the attack in Exhibit 1 and audit again to see what an intrusion looks like.'),
      );
    }

    out.append(
      el('h3', {}, `Bob’s history in the published log (${findings.length} entr${findings.length === 1 ? 'y' : 'ies'})`),
      ul,
      el('div', { className: 'verdict-row' }, verdictSlot),
    );
  }

  auditBtn.addEventListener('click', () => void audit());
  state.onModeChange.push(() => clear(out));

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'monitor-h' },
      el('h2', { id: 'monitor-h' }, '5 · Monitoring — the attacker must leave a receipt'),
      el(
        'p',
        { className: 'panel-lede' },
        'Once gossip forces the directory down to a single history, an attacker who wants Alice to trust a fake key for Bob has exactly one move left: publish that key, in the log, under Bob’s name, forever. Bob can read that log.',
      ),
      el('div', { className: 'controls' }, auditBtn),
      out,
    ),
  );
}
