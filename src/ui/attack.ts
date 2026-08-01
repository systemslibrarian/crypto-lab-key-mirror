/**
 * Exhibit 1 — THE LIE. The headline mechanism, shown not told: the same
 * directory answers the same question two different ways, and two perfectly
 * working E2EE conversations result. Real X25519 + HKDF + AES-GCM throughout.
 */

import { bytesToHex, hexToBytes } from '../core/bytes';
import { open, seal, type SealedMessage } from '../e2ee/box';
import { clear, el, liveRegion, short, verdictChip } from './dom';
import { getState, setMalicious } from './state';

interface StepDef {
  title: string;
  run: () => Promise<{ detail: string; alarm?: boolean }>;
}

export function mountAttack(container: HTMLElement): void {
  const state = getState();

  const ledgerRegion = el('div', {});
  const flowRegion = el('div', { className: 'flow-wrap', role: 'img' });
  const stepsList = el('ol', { className: 'steps' });
  const verdictRegion = liveRegion('verdict-row');
  const statusLine = liveRegion('note');

  const actorLogs: Record<string, HTMLElement> = {
    alice: el('ul', { className: 'msg-log', 'aria-label': 'Alice’s view' }),
    bob: el('ul', { className: 'msg-log', 'aria-label': 'Bob’s view' }),
    carol: el('ul', { className: 'msg-log', 'aria-label': 'Carol’s view' }),
    mallory: el('ul', { className: 'msg-log', 'aria-label': 'Mallory’s view' }),
  };

  const msgInput = el('input', {
    type: 'text',
    id: 'attack-msg',
    value: 'Bob — meet at the old bridge, 9pm. —A',
  }) as HTMLInputElement;

  const evilBox = el('input', { type: 'checkbox', id: 'evil-toggle' }) as HTMLInputElement;

  const tamperBox = el('input', { type: 'checkbox', id: 'tamper-toggle' }) as HTMLInputElement;

  // --- Real record of what the AEAD actually did this run.
  // The "cryptographic results" chip below is derived from this and nothing else.
  // It exists so the chip can go WRONG: flip the tamper toggle and a tag really
  // fails, and the chip has to say so. That contrast is the exhibit — AES-GCM
  // catches a flipped bit every time, and cannot catch a substituted key even once.
  interface OpenAttempt {
    who: string;
    ok: boolean;
  }
  let openAttempts: OpenAttempt[] = [];
  let agreements = 0;

  /** seal(), with the X25519 agreement counted. */
  async function sealCounted(
    senderSk: Uint8Array,
    senderPk: Uint8Array,
    recipientPk: Uint8Array,
    plaintext: string,
  ): Promise<SealedMessage> {
    agreements++;
    return seal(senderSk, senderPk, recipientPk, plaintext);
  }

  /** open(), with the tag-verification outcome recorded. Returns null on tag failure. */
  async function openCounted(recipientSk: Uint8Array, msg: SealedMessage, who: string): Promise<string | null> {
    agreements++;
    const pt = await open(recipientSk, msg);
    openAttempts.push({ who, ok: pt !== null });
    return pt;
  }

  /** Mallory flips one bit of the ciphertext in transit, if the toggle is on. */
  function maybeTamper(msg: SealedMessage): boolean {
    if (!tamperBox.checked) return false;
    msg.ciphertext[0] ^= 0x01;
    return true;
  }

  const stepBtn = el('button', { className: 'btn btn-primary', id: 'attack-step', type: 'button' }, 'Next step') as HTMLButtonElement;
  const runAllBtn = el('button', { className: 'btn', id: 'attack-run', type: 'button' }, 'Run all steps') as HTMLButtonElement;
  const resetBtn = el('button', { className: 'btn', id: 'attack-reset', type: 'button' }, 'Reset') as HTMLButtonElement;

  let steps: StepDef[] = [];
  let stepIdx = 0;
  let busy = false;

  function actorCard(name: string, role: string, extraClass = ''): HTMLElement {
    return el(
      'div',
      { className: `actor-card ${extraClass}` },
      el('div', { className: 'actor-title' }, el('h3', {}, name), el('span', { className: 'actor-role' }, role)),
      actorLogs[name.toLowerCase()],
    );
  }

  function log(actor: string, text: string, meta?: string, alarm = false): void {
    actorLogs[actor].append(
      el(
        'li',
        { className: alarm ? 'msg-alarm' : '' },
        text,
        meta ? el('div', { className: 'msg-meta' }, meta) : null,
      ),
    );
  }

  async function renderLedgers(): Promise<void> {
    clear(ledgerRegion);
    const malicious = state.dir.isMalicious;
    const views: Array<{ view: 'main' | 'shadow'; title: string; cls: string }> = malicious
      ? [
          { view: 'shadow', title: 'Ledger shown to Alice', cls: 'ledger ledger-shadow' },
          { view: 'main', title: 'Ledger shown to everyone else', cls: 'ledger' },
        ]
      : [{ view: 'main', title: 'The directory’s ledger (one for everyone)', cls: 'ledger' }];

    const grid = el('div', { className: 'ledgers' });
    for (const v of views) {
      const sth = await state.dir.signedTreeHead(v.view);
      const tbody = el('tbody', {});
      state.dir.viewBindings(v.view).forEach((b) => {
        const isLie = malicious && v.view === 'shadow' && b.user === 'bob' && b.keyHex === bytesToHex(state.mallory.keys.publicKey);
        tbody.append(
          el(
            'tr',
            { className: isLie ? 'row-lie' : '' },
            el('td', {}, b.user),
            el('td', {}, el('code', {}, short(b.keyHex, 18)), isLie ? ' ⚠ Mallory’s key' : ''),
            el('td', {}, String(b.epoch)),
          ),
        );
      });
      grid.append(
        el(
          'div',
          { className: v.cls },
          el('h3', {}, v.title),
          el(
            'table',
            {},
            el('thead', {}, el('tr', {}, el('th', {}, 'user'), el('th', {}, 'public key'), el('th', {}, 'epoch'))),
            tbody,
          ),
          el('p', { className: 'ledger-root mono' }, `Merkle root: ${short(bytesToHex(sth.root), 24)}`),
        ),
      );
    }
    ledgerRegion.append(grid);
  }

  // --- The message-journey diagram: the headline mechanism, shown spatially.
  // Each part lights up as the step that produces it completes; motion is tied
  // to the action, never idle. All information is also present as text so the
  // diagram conveys nothing by colour or motion alone (WCAG 1.4.1).
  interface FlowPart {
    type: 'node' | 'edge';
    lane: 'top' | 'bottom';
    title: string;
    sub: string;
    icon?: string;
    alarm?: boolean;
    activeAtStep: number;
  }

  function buildFlow(): FlowPart[] {
    const malicious = state.dir.isMalicious;
    const malloryKey = short(bytesToHex(state.mallory.keys.publicKey), 12);
    const bobKey = short(bytesToHex(state.bob.keys.publicKey), 12);

    if (malicious) {
      return [
        { type: 'node', lane: 'top', icon: '📤', title: 'Alice', sub: 'sender', activeAtStep: 1 },
        { type: 'edge', lane: 'top', icon: '🔒', title: `sealed to ${malloryKey}`, sub: 'the substituted key — Mallory’s', alarm: true, activeAtStep: 2 },
        { type: 'node', lane: 'top', icon: '👁', title: 'Mallory', sub: 'decrypts & reads', alarm: true, activeAtStep: 3 },
        { type: 'edge', lane: 'top', icon: '🔒', title: `re-sealed to ${bobKey}`, sub: 'Bob’s real key', alarm: true, activeAtStep: 4 },
        { type: 'node', lane: 'top', icon: '📥', title: 'Bob', sub: 'reads, notices nothing', activeAtStep: 5 },
        { type: 'node', lane: 'bottom', icon: '📤', title: 'Carol', sub: 'another sender', activeAtStep: 6 },
        { type: 'edge', lane: 'bottom', icon: '🔒', title: `sealed to ${bobKey}`, sub: 'Bob’s real key — no detour', activeAtStep: 6 },
        { type: 'node', lane: 'bottom', icon: '📥', title: 'Bob', sub: 'reads', activeAtStep: 7 },
      ];
    }
    return [
      { type: 'node', lane: 'top', icon: '📤', title: 'Alice', sub: 'sender', activeAtStep: 1 },
      { type: 'edge', lane: 'top', icon: '🔒', title: `sealed to ${bobKey}`, sub: 'Bob’s real key', activeAtStep: 2 },
      { type: 'node', lane: 'top', icon: '📥', title: 'Bob', sub: 'reads', activeAtStep: 3 },
      { type: 'node', lane: 'bottom', icon: '📤', title: 'Carol', sub: 'another sender', activeAtStep: 4 },
      { type: 'edge', lane: 'bottom', icon: '🔒', title: `sealed to ${bobKey}`, sub: 'Bob’s real key', activeAtStep: 4 },
      { type: 'node', lane: 'bottom', icon: '📥', title: 'Bob', sub: 'reads', activeAtStep: 5 },
    ];
  }

  function renderFlow(completed: number): void {
    clear(flowRegion);
    const parts = buildFlow();
    const malicious = state.dir.isMalicious;
    flowRegion.setAttribute(
      'aria-label',
      malicious
        ? 'Message journey: Alice sends to the substituted key, Mallory decrypts and re-encrypts to Bob; Carol sends straight to Bob.'
        : 'Message journey: Alice sends straight to Bob; Carol sends straight to Bob.',
    );

    const laneLabel: Record<'top' | 'bottom', string> = {
      top: malicious ? 'Alice’s message' : 'Alice’s message',
      bottom: 'Carol’s message',
    };
    for (const lane of ['top', 'bottom'] as const) {
      const laneParts = parts.filter((p) => p.lane === lane);
      const row = el('div', { className: 'flow-lane' }, el('span', { className: 'flow-lane-label' }, laneLabel[lane]));
      const track = el('div', { className: 'flow-track' });
      laneParts.forEach((p) => {
        const reached = completed >= p.activeAtStep;
        const justNow = completed === p.activeAtStep && reached;
        const cls = [
          p.type === 'edge' ? 'flow-edge' : 'flow-node',
          reached ? (p.alarm ? 'flow-alarm' : 'flow-done') : 'flow-idle',
          justNow ? 'flow-now' : '',
        ]
          .filter(Boolean)
          .join(' ');
        track.append(
          el(
            'div',
            { className: cls },
            el('span', { className: 'flow-icon', 'aria-hidden': 'true' }, reached ? p.icon ?? '' : '·'),
            el('span', { className: 'flow-title' }, p.title),
            el('span', { className: 'flow-sub' }, reached ? p.sub : 'waiting'),
          ),
        );
      });
      row.append(track);
      flowRegion.append(row);
    }
  }

  function buildSteps(): StepDef[] {
    const malicious = state.dir.isMalicious;
    let aliceKeyForBob = '';
    let aliceMsg: SealedMessage | null = null;
    let forwarded: SealedMessage | null = null;
    let carolMsg: SealedMessage | null = null;
    let malloryPlaintext: string | null = null;

    const defs: StepDef[] = [
      {
        title: 'Alice asks the directory: “what is bob’s key?”',
        run: async () => {
          const res = await state.dir.lookup('bob', 'shadow', null);
          aliceKeyForBob = res!.binding.keyHex;
          log('alice', `directory says bob’s key is ${short(aliceKeyForBob, 18)}`, `epoch ${res!.binding.epoch}`);
          return {
            detail: malicious
              ? `the directory answers from the ledger it keeps FOR ALICE: ${short(aliceKeyForBob, 18)} — Alice has no way to tell whose key this is`
              : `the directory answers ${short(aliceKeyForBob, 18)} — bob’s genuine key`,
            alarm: malicious,
          };
        },
      },
      {
        title: 'Alice encrypts to that key — real X25519 → HKDF → AES-256-GCM',
        run: async () => {
          aliceMsg = await sealCounted(
            state.alice.keys.secretKey,
            state.alice.keys.publicKey,
            hexToBytes(aliceKeyForBob),
            msgInput.value || '(empty message)',
          );
          const flipped = maybeTamper(aliceMsg);
          log('alice', 'sealed and sent', `ciphertext ${short(bytesToHex(aliceMsg.ciphertext), 24)}`);
          if (flipped) {
            log('mallory', 'flipped one bit of the ciphertext in transit', 'byte 0, low bit', true);
          }
          return {
            detail: flipped
              ? `ciphertext ${short(bytesToHex(aliceMsg.ciphertext), 32)} (nonce ${bytesToHex(aliceMsg.nonce)}) — then one bit of byte 0 was flipped on the wire. Watch what the tag does about it.`
              : `ciphertext ${short(bytesToHex(aliceMsg.ciphertext), 32)} (nonce ${bytesToHex(aliceMsg.nonce)}) — the encryption is flawless either way`,
            alarm: flipped,
          };
        },
      },
    ];

    if (malicious) {
      defs.push(
        {
          title: 'The ciphertext reaches… Mallory, who holds the substituted key',
          run: async () => {
            const pt = await openCounted(state.mallory.keys.secretKey, aliceMsg!, 'Mallory');
            if (pt === null) {
              log('mallory', 'decryption REJECTED', 'AES-GCM tag: INVALID ✗', true);
              return {
                detail:
                  'the AES-GCM tag check FAILED — Mallory holds the right key but the ciphertext was modified in flight, so the tag rejects it and she gets nothing. This is the tamper AEAD does catch.',
                alarm: true,
              };
            }
            malloryPlaintext = pt;
            log('mallory', `decrypted Alice’s message: “${pt}”`, 'AES-GCM tag: valid ✓', true);
            return {
              detail: `Mallory decrypts with her own secret key: “${pt}” — the AES-GCM tag verifies, because the message really was encrypted to her`,
              alarm: true,
            };
          },
        },
        {
          title: 'Mallory re-encrypts to bob’s REAL key and forwards it',
          run: async () => {
            if (malloryPlaintext === null) {
              return {
                detail:
                  'nothing to forward — Mallory never recovered the plaintext, so the relay stalls here. Bob simply never receives the message.',
                alarm: true,
              };
            }
            forwarded = await sealCounted(
              state.mallory.keys.secretKey,
              state.mallory.keys.publicKey,
              state.bob.keys.publicKey,
              malloryPlaintext,
            );
            return {
              detail: `a fresh, valid ciphertext ${short(bytesToHex(forwarded.ciphertext), 24)} heads to bob — the conversation will look completely normal`,
              alarm: true,
            };
          },
        },
        {
          title: 'Bob decrypts the forwarded copy — nothing looks wrong',
          run: async () => {
            if (forwarded === null) {
              return {
                detail: 'nothing arrived. The flipped bit broke the relay before it reached Bob.',
                alarm: true,
              };
            }
            const pt = await openCounted(state.bob.keys.secretKey, forwarded, 'Bob');
            if (pt === null) {
              log('bob', 'decryption REJECTED', 'AES-GCM tag: INVALID ✗', true);
              return { detail: 'the AES-GCM tag check FAILED for Bob — the message did not survive the wire.', alarm: true };
            }
            log('bob', `received: “${pt}”`, 'AES-GCM tag: valid ✓');
            return {
              detail: 'Bob reads the message Alice wrote. Two working E2EE hops, one silent reader in the middle.',
            };
          },
        },
      );
    } else {
      defs.push({
        title: 'Bob decrypts it',
        run: async () => {
          const pt = await openCounted(state.bob.keys.secretKey, aliceMsg!, 'Bob');
          if (pt === null) {
            log('bob', 'decryption REJECTED', 'AES-GCM tag: INVALID ✗', true);
            return {
              detail:
                'the AES-GCM tag check FAILED — one flipped bit and the message is refused outright. AEAD catches this every time.',
              alarm: true,
            };
          }
          log('bob', `received: “${pt}”`, 'AES-GCM tag: valid ✓');
          return { detail: 'straight from Alice to Bob — one key, one reader' };
        },
      });
    }

    defs.push(
      {
        title: 'Carol asks the same question — and gets bob’s real key',
        run: async () => {
          const res = await state.dir.lookup('bob', 'main', null);
          log('carol', `directory says bob’s key is ${short(res!.binding.keyHex, 18)}`, `epoch ${res!.binding.epoch}`);
          carolMsg = await sealCounted(
            state.carol.keys.secretKey,
            state.carol.keys.publicKey,
            hexToBytes(res!.binding.keyHex),
            'Bob, confirming Thursday. — C',
          );
          return {
            detail: malicious
              ? `the SAME directory, the SAME question, a DIFFERENT answer: ${short(res!.binding.keyHex, 18)}. That is equivocation.`
              : `${short(res!.binding.keyHex, 18)} — the same answer Alice got`,
            alarm: malicious,
          };
        },
      },
      {
        title: 'Bob decrypts Carol’s message too',
        run: async () => {
          const pt = await openCounted(state.bob.keys.secretKey, carolMsg!, 'Bob (from Carol)');
          if (pt === null) {
            log('bob', 'decryption REJECTED', 'AES-GCM tag: INVALID ✗', true);
            renderVerdict();
            return { detail: 'Carol’s message was rejected by the tag check. Now look at the verdict.', alarm: true };
          }
          log('bob', `received: “${pt}”`, 'AES-GCM tag: valid ✓');
          renderVerdict();
          return { detail: 'both conversations work. Now look at the verdict.' };
        },
      },
    );

    return defs;
  }

  function renderVerdict(): void {
    clear(verdictRegion);
    const malicious = state.dir.isMalicious;
    // Derived from what the AEAD actually returned this run — never asserted.
    const failed = openAttempts.filter((a) => !a.ok);
    const total = openAttempts.length;
    const allOk = total > 0 && failed.length === 0;
    const cryptoSlot = el(
      'div',
      { className: 'verdict-slot' },
      el('p', { className: 'slot-title' }, 'Cryptographic results'),
      total === 0
        ? el(
            'p',
            { className: 'chip chip-neutral' },
            el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, '·'),
            'No decryption attempted yet — nothing to report',
          )
        : allOk
          ? el(
              'p',
              { className: 'chip chip-neutral' },
              el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, '✓'),
              `All ${total} AES-GCM tag${total === 1 ? '' : 's'} verified · ${agreements} X25519 agreement${agreements === 1 ? '' : 's'} completed`,
            )
          : el(
              'p',
              { className: 'chip chip-alarm' },
              el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, '✗'),
              `${failed.length} of ${total} AES-GCM tag check${total === 1 ? '' : 's'} FAILED (${failed.map((a) => a.who).join(', ')}) — the ciphertext was modified in flight and the tag refused it`,
            ),
    );
    const verdictSlot = el('div', { className: 'verdict-slot' }, el('p', { className: 'slot-title' }, 'Security verdict'));
    if (failed.length > 0) {
      // The bit-flip path: this is the contrast case, and it is the ONE thing the
      // AEAD can see. Say so, and do not claim the run was clean.
      verdictSlot.append(
        verdictChip('warn', 'TAMPER DETECTED — the flipped bit was caught and the message refused'),
        el(
          'p',
          { className: 'note' },
          malicious
            ? 'Note what did and did not happen. The key substitution went by in total silence; the flipped bit was caught instantly. AES-GCM defends the bytes, not the name→key binding. Untick the bit-flip and run it again to see the substitution alone.'
            : 'One flipped bit and the tag refuses the whole message — AEAD catches this every time, with no directory, no ledger, no transparency log required. That is the check that works. The next run shows the one it cannot make.',
        ),
      );
    } else if (malicious) {
      verdictSlot.append(
        verdictChip('alarm', 'INTERCEPTED, UNDETECTED — Alice encrypted to the attacker'),
        el(
          'p',
          { className: 'note' },
          'Sit with that: the encryption did everything it promised, to the wrong key. No cryptographic check Alice can run on her own — not one — has failed. The rest of this lab builds the machinery that changes that.',
        ),
      );
    } else {
      verdictSlot.append(
        verdictChip('safe', 'CONSISTENT — one ledger, one truth, both users encrypted to Bob'),
        el('p', { className: 'note' }, 'Flip the directory to malicious and run it again.'),
      );
    }
    verdictRegion.append(cryptoSlot, verdictSlot);
  }

  function renderStepList(): void {
    clear(stepsList);
    steps.forEach((s, i) => {
      const cls = i < stepIdx ? '' : 'step-pending';
      stepsList.append(el('li', { className: cls, 'data-step': String(i) }, s.title));
    });
  }

  async function reset(): Promise<void> {
    steps = buildSteps();
    stepIdx = 0;
    openAttempts = [];
    agreements = 0;
    for (const l of Object.values(actorLogs)) clear(l);
    clear(verdictRegion);
    renderStepList();
    await renderLedgers();
    renderFlow(0);
    stepBtn.disabled = false;
    runAllBtn.disabled = false;
    statusLine.textContent = state.dir.isMalicious
      ? 'Directory is MALICIOUS: it now keeps two ledgers. Step through the lookup.'
      : 'Directory is honest. Step through the lookup.';
  }

  async function nextStep(): Promise<void> {
    if (busy || stepIdx >= steps.length) return;
    busy = true;
    const li = stepsList.querySelector<HTMLElement>(`[data-step="${stepIdx}"]`)!;
    li.classList.remove('step-pending');
    li.classList.add('step-active');
    const result = await steps[stepIdx].run();
    li.classList.remove('step-active');
    if (result.alarm) li.classList.add('step-alarm');
    li.append(el('div', { className: 'step-detail' }, result.detail));
    stepIdx++;
    renderFlow(stepIdx);
    if (stepIdx >= steps.length) {
      stepBtn.disabled = true;
      runAllBtn.disabled = true;
      statusLine.textContent = 'Sequence complete.';
    }
    busy = false;
  }

  async function runAll(): Promise<void> {
    while (stepIdx < steps.length) await nextStep();
  }

  stepBtn.addEventListener('click', () => void nextStep());
  runAllBtn.addEventListener('click', () => void runAll());
  resetBtn.addEventListener('click', () => void reset());
  evilBox.addEventListener('change', () => void setMalicious(evilBox.checked));
  tamperBox.addEventListener('change', () => void reset());

  state.onModeChange.push(() => {
    evilBox.checked = state.dir.isMalicious;
    void reset();
  });

  container.append(
    el(
      'section',
      { className: 'panel', 'aria-labelledby': 'attack-h' },
      el('h2', { id: 'attack-h' }, '1 · The lie — one directory, two truths'),
      el(
        'p',
        { className: 'panel-lede' },
        'Alice and Carol both ask the directory for Bob’s public key. An honest directory gives one answer. A malicious one gives Alice the attacker’s key and Carol the real one — and both of their encrypted conversations work perfectly.',
      ),
      el(
        'div',
        { className: 'controls' },
        el(
          'span',
          { className: 'evil-toggle' },
          evilBox,
          el('label', { for: 'evil-toggle' }, 'Directory turns malicious (attack mode)'),
        ),
        el(
          'span',
          { className: 'evil-toggle' },
          tamperBox,
          el('label', { for: 'tamper-toggle' }, 'Flip one bit of the ciphertext in transit'),
        ),
        el(
          'span',
          { className: 'ctl' },
          el('label', { className: 'ctl-label', for: 'attack-msg' }, 'Message Alice sends'),
          msgInput,
        ),
        stepBtn,
        runAllBtn,
        resetBtn,
      ),
      statusLine,
      el('h3', { className: 'flow-heading' }, 'Where Alice’s message actually goes'),
      flowRegion,
      ledgerRegion,
      stepsList,
      el(
        'div',
        { className: 'actors' },
        actorCard('Alice', 'sender — sees only her own view'),
        actorCard('Bob', 'recipient — sees only what arrives'),
        actorCard('Carol', 'another user — her own view'),
        actorCard('Mallory', 'attacker — controls the directory’s answers to Alice', 'actor-mallory'),
      ),
      verdictRegion,
      el(
        'details',
        { className: 'expert' },
        el('summary', {}, 'Expert view: why the E2EE math cannot notice'),
        el(
          'p',
          { className: 'note' },
          'The sealed box here is X25519 ECDH → HKDF-SHA-256 → AES-256-GCM (the same shape as a Signal session setup’s first hop). Its security theorem is conditional: “only the holder of the recipient private key can decrypt.” The theorem binds ciphertexts to a ',
          el('em', {}, 'key'),
          ', never to a ',
          el('em', {}, 'name'),
          '. The name→key binding is exactly the part the directory controls — and exactly the part transparency audits. Substituting the key changes nothing the algorithms can observe: every DH, KDF, and tag check is distributionally identical.',
        ),
      ),
    ),
  );

  void reset();
}
