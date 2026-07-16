/**
 * Exhibit 3 — CONSISTENCY PROOF STEPPER, byte level. Walks the real RFC 9162
 * verification algorithm (via the traced verifier pinned to verify.ts by
 * test) over two scenarios:
 *   A) an honest append: old root → new root, the proof checks;
 *   B) a forked history: after gossip reveals the main history, no proof can
 *      connect the head Alice accepted to it — the reconstruction mismatches,
 *      byte for byte.
 */

import { bytesToHex, utf8ToBytes } from '../core/bytes';
import { traceConsistency, type ConsistencyTrace } from '../merkle/trace';
import { MerkleLog } from '../merkle/tree';
import { clear, el, hexDiff, liveRegion, short, verdictChip } from './dom';

type Scenario = 'append' | 'fork';

interface Prepared {
  oldSize: number;
  oldRoot: Uint8Array;
  newSize: number;
  newRoot: Uint8Array;
  proof: Uint8Array[];
  trace: ConsistencyTrace;
  oldLabel: string;
  newLabel: string;
}

async function buildScenario(which: Scenario): Promise<Prepared> {
  // Six pre-fork registrations shared by every history.
  const main = new MerkleLog();
  for (const u of ['alice:key1', 'bob:key1', 'carol:key1', 'dave:key1', 'erin:key1', 'frank:key1']) {
    await main.append(utf8ToBytes(u));
  }

  if (which === 'append') {
    const oldRoot = await main.root(6);
    await main.append(utf8ToBytes('grace:key1'));
    return {
      oldSize: 6,
      oldRoot,
      newSize: 7,
      newRoot: await main.root(7),
      proof: await main.proveConsistency(6, 7),
      trace: await traceConsistency(6, oldRoot, 7, await main.root(7), await main.proveConsistency(6, 7)),
      oldLabel: 'root Alice already holds (size 6)',
      newLabel: 'new signed root (size 7) — an honest append',
    };
  }

  // Fork: shadow history got the forged bob key; main got the real one and
  // then grew. Alice holds the SHADOW head; the server must now connect it to
  // the main history it shows everyone else. It cannot.
  const shadow = main.fork();
  await main.append(utf8ToBytes('bob:key1-rotation-REAL'));
  await shadow.append(utf8ToBytes('bob:key1-rotation-FORGED'));
  await main.append(utf8ToBytes('grace:key1'));

  const aliceHead = await shadow.root(7);
  const mainHead = await main.root(8);
  const proof = await main.proveConsistency(7, 8); // the best proof the server can produce
  return {
    oldSize: 7,
    oldRoot: aliceHead,
    newSize: 8,
    newRoot: mainHead,
    proof,
    trace: await traceConsistency(7, aliceHead, 8, mainHead, proof),
    oldLabel: 'head Alice accepted (size 7 — contains the forged key)',
    newLabel: 'main history’s head (size 8 — the one everyone else sees)',
  };
}

export function mountStepper(container: HTMLElement): void {
  const tableRegion = el('div', { className: 'tracewrap', tabindex: '0', role: 'region', 'aria-label': 'Consistency verification steps' });
  const finalRegion = liveRegion();
  const statusLine = liveRegion('note');

  const nextBtn = el('button', { className: 'btn btn-primary', id: 'stepper-next', type: 'button' }, 'Next hash step') as HTMLButtonElement;
  const allBtn = el('button', { className: 'btn', id: 'stepper-all', type: 'button' }, 'Run all steps') as HTMLButtonElement;

  const radioAppend = el('input', { type: 'radio', name: 'scenario', id: 'scn-append', value: 'append', checked: true }) as HTMLInputElement;
  const radioFork = el('input', { type: 'radio', name: 'scenario', id: 'scn-fork', value: 'fork' }) as HTMLInputElement;

  let prepared: Prepared | null = null;
  let shown = 0;
  let rows: HTMLTableRowElement[] = [];

  function renderTable(): void {
    clear(tableRegion);
    rows = [];
    if (!prepared) return;
    const tbody = el('tbody', {});
    prepared.trace.steps.forEach((s, i) => {
      const tr = el(
        'tr',
        { className: 'trace-future', 'data-row': String(i) },
        el('td', {}, String(i)),
        el('td', {}, s.description),
        el('td', {}, el('code', {}, s.node ? short(bytesToHex(s.node), 16) : '—')),
        el('td', {}, el('code', {}, short(bytesToHex(s.fr), 16))),
        el('td', {}, el('code', {}, short(bytesToHex(s.sr), 16))),
      ) as HTMLTableRowElement;
      rows.push(tr);
      tbody.append(tr);
    });
    tableRegion.append(
      el(
        'table',
        { className: 'trace-table' },
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', {}, 'step'),
            el('th', {}, 'operation (real SHA-256, H(0x01‖left‖right))'),
            el('th', {}, 'proof node'),
            el('th', {}, 'fr — rebuilt OLD root'),
            el('th', {}, 'sr — rebuilt NEW root'),
          ),
        ),
        tbody,
      ),
    );
  }

  function renderFinal(): void {
    clear(finalRegion);
    if (!prepared) return;
    const t = prepared.trace;
    const oldCmp = hexDiff(bytesToHex(t.finalFr), bytesToHex(prepared.oldRoot));
    const newCmp = hexDiff(bytesToHex(t.finalSr), bytesToHex(prepared.newRoot));

    finalRegion.append(
      el(
        'div',
        { className: 'verdict-row' },
        el(
          'div',
          { className: 'verdict-slot' },
          el('p', { className: 'slot-title' }, 'rebuilt old root  vs  ' + prepared.oldLabel),
          oldCmp.aNode,
          oldCmp.bNode,
          el(
            'p',
            { className: 'chip chip-neutral' },
            el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, t.frMatchesOld ? '✓' : '✗'),
            t.frMatchesOld ? 'old root reconstructed exactly' : 'MISMATCH — this proof does not contain Alice’s history',
          ),
        ),
        el(
          'div',
          { className: 'verdict-slot' },
          el('p', { className: 'slot-title' }, 'rebuilt new root  vs  ' + prepared.newLabel),
          newCmp.aNode,
          newCmp.bNode,
          el(
            'p',
            { className: 'chip chip-neutral' },
            el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, t.srMatchesNew ? '✓' : '✗'),
            t.srMatchesNew ? 'new root reconstructed exactly' : 'MISMATCH',
          ),
        ),
      ),
    );

    const verdictSlot = el('div', { className: 'verdict-slot' }, el('p', { className: 'slot-title' }, 'What this proves'));
    if (t.valid) {
      verdictSlot.append(
        verdictChip('safe', 'APPEND PROVEN — the new tree contains the old tree unchanged'),
        el('p', { className: 'note' }, 'Every leaf Alice ever saw is still there, in the same positions. The server extended the log; it retracted nothing.'),
      );
    } else {
      verdictSlot.append(
        verdictChip('safe', 'FORK EXPOSED — no consistency proof can connect two histories'),
        el(
          'p',
          { className: 'note' },
          `The verifier fails closed: ${t.failReason}. This is the “append-only” promise doing its job — once Alice holds a signed head of the forked history, the server is mathematically stuck with its lie.`,
        ),
      );
    }
    finalRegion.append(el('div', { className: 'verdict-row' }, verdictSlot));
  }

  async function reset(): Promise<void> {
    const which: Scenario = radioFork.checked ? 'fork' : 'append';
    statusLine.textContent = 'building logs and proof…';
    prepared = await buildScenario(which);
    shown = 0;
    renderTable();
    clear(finalRegion);
    nextBtn.disabled = false;
    allBtn.disabled = false;
    statusLine.textContent =
      which === 'append'
        ? `verifying: does root(${prepared.oldSize}) extend into root(${prepared.newSize})? Proof has ${prepared.proof.length} nodes.`
        : `verifying: can the server connect the head it gave Alice to the history it shows everyone else? Proof has ${prepared.proof.length} nodes.`;
  }

  function next(): void {
    if (!prepared || shown >= rows.length) return;
    rows.forEach((r) => r.classList.remove('trace-now'));
    rows[shown].classList.remove('trace-future');
    rows[shown].classList.add('trace-now');
    shown++;
    if (shown >= rows.length) {
      renderFinal();
      nextBtn.disabled = true;
      allBtn.disabled = true;
      statusLine.textContent = 'verification complete — compare the reconstructed roots below.';
    }
  }

  nextBtn.addEventListener('click', next);
  allBtn.addEventListener('click', () => {
    while (prepared && shown < rows.length) next();
  });
  radioAppend.addEventListener('change', () => void reset());
  radioFork.addEventListener('change', () => void reset());

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'stepper-h' },
      el('h2', { id: 'stepper-h' }, '3 · Consistency proofs, byte by byte'),
      el(
        'p',
        { className: 'panel-lede' },
        'A consistency proof lets a client verify that a new tree head extends the old one it already trusts — append-only, nothing retracted. Walk the real verifier: it rebuilds both roots from a handful of internal nodes and compares them byte-for-byte.',
      ),
      el(
        'fieldset',
        { className: 'layers' },
        el('legend', {}, 'Scenario'),
        el('span', { className: 'layer-opt' }, radioAppend, el('label', { for: 'scn-append' }, 'Honest append — proof verifies')),
        el('span', { className: 'layer-opt' }, radioFork, el('label', { for: 'scn-fork' }, 'Forked history — proof fails')),
      ),
      el('div', { className: 'controls' }, nextBtn, allBtn),
      statusLine,
      tableRegion,
      finalRegion,
      el(
        'details',
        { className: 'expert' },
        el('summary', {}, 'Expert view: the algorithm being stepped'),
        el(
          'p',
          { className: 'note' },
          'This is RFC 9162 §2.1.4.2 (the RFC 6962 consistency check): seed two running hashes from the proof, fold in each node — left of both, or right of the new tree only, chosen by the bit pattern of the sizes — then require the first to equal the old root and the second the new root. The stepper calls the same code path the unit tests pin against the CT reference vectors; nothing is re-narrated.',
        ),
      ),
    ),
  );

  void reset();
}
