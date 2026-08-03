/**
 * Claims spec — asserts the load-bearing states this page CLAIMS, against the
 * page's own computed output rather than hardcoded expectations wherever a
 * cross-check is possible:
 *
 *  - Exhibit 1: the equivocation is real (the key Alice is handed differs from
 *    Carol's, and matches the flagged Mallory row), the two ledgers carry
 *    different Merkle roots, the verdict tracks the run, and the crypto
 *    counters are internally consistent (agreements = seals + opens, tags
 *    verified = logged tag-valid lines).
 *  - Exhibit 2: at layers 0-3 every crypto check passes AND the lie stands —
 *    the checks summary "N/M passed" is checked against the rendered checklist,
 *    not asserted. At layer 4 gossip proves equivocation.
 *  - Exhibit 3: the trace row count equals the proof-node count the page
 *    reported; the honest append reconstructs both roots byte-identically
 *    (zero diff spans) and the fork does not, with the reason stated.
 *  - Exhibit 4: the displayed tree slot is recomputed here from the displayed
 *    beta; proof/label lengths match RFC 9381 sizes; tamper is rejected.
 *  - Exhibit 5: the entry-count heading matches the rendered rows, and the
 *    "N planted" verdict matches the number of unrecognised rows.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';

/** Number rendered inside the first element matching `sel`, via a regex group. */
async function num(root: Page | Locator, sel: string, re: RegExp): Promise<number> {
  const text = (await root.locator(sel).first().innerText()).replace(/\s+/g, ' ');
  const m = text.match(re);
  expect(m, `no match for ${re} in: ${text}`).not.toBeNull();
  return Number(m![1]);
}

async function setToggles(page: Page, opts: { malicious: boolean; tamper: boolean }): Promise<void> {
  const evil = page.locator('#evil-toggle');
  const tamper = page.locator('#tamper-toggle');
  if ((await evil.isChecked()) !== opts.malicious) await evil.setChecked(opts.malicious);
  await expect(page.locator('.ledger-shadow')).toHaveCount(opts.malicious ? 1 : 0);
  if ((await tamper.isChecked()) !== opts.tamper) await tamper.setChecked(opts.tamper);
  // reset() rebuilds the step list; malicious runs have 7 steps, honest 5.
  await expect(page.locator('.steps li')).toHaveCount(opts.malicious ? 7 : 5);
}

async function runAttack(page: Page, opts: { malicious: boolean; tamper: boolean }): Promise<void> {
  await setToggles(page, opts);
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-step')).toBeDisabled();
  await expect(page.locator('.verdict-row .chip').first()).toBeVisible();
}

/** The short-form key hex the page prints in an actor's log line. */
async function keyFromLog(page: Page, actor: string): Promise<string> {
  const line = await page.locator(`ul[aria-label="${actor}"] li`).first().innerText();
  const m = line.match(/bob’s key is ([0-9a-f]+…?)/);
  expect(m, `no key in ${actor} log line: ${line}`).not.toBeNull();
  return m![1];
}

// ---------------------------------------------------------------- Exhibit 1

test('exhibit 1 — honest directory: one ledger, one key, CONSISTENT verdict', async ({ page }) => {
  await page.goto('.');
  await runAttack(page, { malicious: false, tamper: false });

  // One ledger only, and the page says so.
  await expect(page.locator('.ledger')).toHaveCount(1);
  await expect(page.locator('.ledger h3')).toHaveText('The directory’s ledger (one for everyone)');
  await expect(page.locator('.row-lie')).toHaveCount(0);

  // The two lookups returned the SAME key — compared, not assumed.
  expect(await keyFromLog(page, 'Alice’s view')).toBe(await keyFromLog(page, 'Carol’s view'));

  await expect(page.locator('.chip-ok')).toContainText(
    'CONSISTENT — one ledger, one truth, both users encrypted to Bob',
  );
  await expect(page.locator('.verdict-row')).not.toContainText('INTERCEPTED');
});

test('exhibit 1 — malicious directory: two ledgers, two roots, two answers, INTERCEPTED verdict', async ({
  page,
}) => {
  await page.goto('.');
  await runAttack(page, { malicious: true, tamper: false });

  // Two ledgers, and their Merkle roots are genuinely different (the fork).
  await expect(page.locator('.ledger')).toHaveCount(2);
  const roots = await page.locator('.ledger-root').allInnerTexts();
  expect(roots).toHaveLength(2);
  expect(roots[0]).not.toBe(roots[1]);

  // The lie is flagged in the shadow ledger, and the key Alice was handed is
  // exactly that flagged key — and NOT the key Carol was handed.
  const lieRow = page.locator('.ledger-shadow .row-lie');
  await expect(lieRow).toHaveCount(1);
  await expect(lieRow).toContainText('Mallory’s key');
  const lieKey = (await lieRow.locator('code').innerText()).trim();

  const aliceKey = await keyFromLog(page, 'Alice’s view');
  const carolKey = await keyFromLog(page, 'Carol’s view');
  expect(aliceKey).toBe(lieKey);
  expect(aliceKey).not.toBe(carolKey);

  // Carol's key is the one in the honest ledger for bob.
  const honestBobKey = (
    await page.locator('.ledger:not(.ledger-shadow) tbody tr', { hasText: 'bob' }).last().locator('code').innerText()
  ).trim();
  expect(carolKey).toBe(honestBobKey);

  await expect(page.locator('.chip-alarm')).toContainText(
    'INTERCEPTED, UNDETECTED — Alice encrypted to the attacker',
  );
  // Mallory really read the plaintext Alice typed.
  await expect(page.locator('ul[aria-label="Mallory’s view"]')).toContainText(
    'decrypted Alice’s message: “Bob — meet at the old bridge, 9pm. —A”',
  );
  // ...and Bob received that same plaintext, none the wiser.
  await expect(page.locator('ul[aria-label="Bob’s view"]')).toContainText(
    'received: “Bob — meet at the old bridge, 9pm. —A”',
  );
});

for (const malicious of [false, true]) {
  test(`exhibit 1 — crypto counters are internally consistent (${malicious ? 'malicious' : 'honest'})`, async ({
    page,
  }) => {
    await page.goto('.');
    await runAttack(page, { malicious, tamper: false });

    const chip = page.locator('.verdict-slot', { hasText: 'Cryptographic results' }).locator('.chip');
    const chipText = await chip.innerText();
    const m = chipText.match(/All (\d+) AES-GCM tags? verified · (\d+) X25519 agreements? completed/);
    expect(m, `unexpected crypto chip: ${chipText}`).not.toBeNull();
    const tags = Number(m![1]);
    const agreements = Number(m![2]);

    // Every verified tag left a "tag: valid" line in some actor's log.
    const validLines = await page.locator('.msg-meta', { hasText: 'AES-GCM tag: valid' }).count();
    expect(tags).toBe(validLines);

    // Every X25519 agreement is either a seal (one per encrypted hop drawn in
    // the flow diagram) or an open (one per tag verified). Parts sum to whole.
    const seals = await page.locator('.flow-edge').count();
    expect(seals).toBe(malicious ? 3 : 2);
    expect(agreements).toBe(seals + tags);
  });
}

for (const malicious of [false, true]) {
  test(`exhibit 1 — bit-flip in transit is caught by the tag (${malicious ? 'malicious' : 'honest'})`, async ({
    page,
  }) => {
    await page.goto('.');
    await runAttack(page, { malicious, tamper: true });

    const cryptoChip = page.locator('.verdict-slot', { hasText: 'Cryptographic results' }).locator('.chip');
    const text = await cryptoChip.innerText();
    const m = text.match(/(\d+) of (\d+) AES-GCM tag checks? FAILED \(([^)]+)\)/);
    expect(m, `expected a failure chip, got: ${text}`).not.toBeNull();
    const failed = Number(m![1]);
    const total = Number(m![2]);
    const who = m![3];
    expect(failed).toBe(1);
    expect(failed).toBeLessThan(total);
    // The victim of the flipped bit is whoever held the key Alice sealed to.
    expect(who).toBe(malicious ? 'Mallory' : 'Bob');
    expect(text).toContain('the ciphertext was modified in flight and the tag refused it');

    // And the verdict says tamper, not "all clear".
    await expect(page.locator('.chip-warn').first()).toContainText(
      'TAMPER DETECTED — the flipped bit was caught and the message refused',
    );
    await expect(page.locator('.verdict-row')).not.toContainText('INTERCEPTED, UNDETECTED');

    // A rejection was logged with the reason.
    await expect(page.locator('.actors')).toContainText('decryption REJECTED');
    await expect(page.locator('.msg-meta', { hasText: 'AES-GCM tag: INVALID' }).first()).toBeVisible();
  });
}

// ---------------------------------------------------------------- Exhibit 2

/** Reconcile the ladder's "N/M crypto checks passed" chip against the checklist it rendered. */
async function assertChecksSummaryConsistent(page: Page): Promise<{ passed: number; total: number }> {
  const chipText = await page.locator('.chip-neutral', { hasText: 'crypto checks passed' }).innerText();
  const m = chipText.match(/(\d+)\/(\d+) crypto checks passed/);
  expect(m, `unexpected summary chip: ${chipText}`).not.toBeNull();
  const passed = Number(m![1]);
  const total = Number(m![2]);

  const labels = await page.locator('.checklist .check-label').allInnerTexts();
  const real = labels.filter((t) => t.startsWith('✓') || t.startsWith('✗'));
  const ok = real.filter((t) => t.startsWith('✓'));
  expect(total).toBe(real.length);
  expect(passed).toBe(ok.length);
  return { passed, total };
}

test('exhibit 2 — layers 0-3: every crypto check passes and the lie survives all of them', async ({ page }) => {
  await page.goto('.');
  await setToggles(page, { malicious: true, tamper: false });

  for (const layer of [0, 1, 2, 3]) {
    await page.locator(`#layer-${layer}`).check();
    await page.locator('#ladder-run').click();
    await expect(page.locator('.chip-alarm')).toContainText(
      `LIE UNDETECTED at layer ${layer} — Alice is encrypting to the attacker`,
    );

    const { passed, total } = await assertChecksSummaryConsistent(page);
    // The thesis: nothing failed, and the lie stood anyway.
    expect(passed).toBe(total);
    // 2 clients x {0, 1, 3, 4} checks enforced at layers 0..3.
    expect(total).toBe([0, 1, 3, 4][layer] * 2);

    // The omniscient view shows the two keys really differ at every layer.
    const omni = page.locator('.verdict-slot', { hasText: 'omniscient view' });
    expect(await omni.locator('.hex-diff').count()).toBeGreaterThan(0);
  }
});

test('exhibit 2 — layer 4 gossip proves equivocation from two validly signed heads', async ({ page }) => {
  await page.goto('.');
  await setToggles(page, { malicious: true, tamper: false });
  await page.locator('#layer-4').check();
  await page.locator('#ladder-run').click();

  const gossipSlot = page.locator('.verdict-slot', { hasText: 'Gossip: Alice and Carol swap signed tree heads' });
  const heads = await gossipSlot.locator('.hexlabel').allInnerTexts();
  expect(heads).toHaveLength(2);
  // Both heads are validly signed — the directory cannot disown either.
  for (const h of heads) expect(h).toContain('signature valid ✓');
  // Same epoch and size...
  const epochs = heads.map((h) => h.match(/epoch (\d+), size (\d+)/)!.slice(1).join('/'));
  expect(epochs[0]).toBe(epochs[1]);
  // ...different roots.
  expect(await gossipSlot.locator('.hex-diff').count()).toBeGreaterThan(0);

  await expect(page.locator('.chip-ok')).toContainText(
    'EQUIVOCATION PROVEN — two signed heads, same epoch, different roots',
  );
  await expect(page.locator('.chip-warn')).toContainText(
    'Detection, not prevention — messages Alice already sent were already read',
  );
  // Every client-side check still passed; gossip is what caught it.
  const { passed, total } = await assertChecksSummaryConsistent(page);
  expect(passed).toBe(total);
});

test('exhibit 2 — honest directory: no equivocation at any layer', async ({ page }) => {
  await page.goto('.');
  await setToggles(page, { malicious: false, tamper: false });
  for (const layer of [0, 2, 4]) {
    await page.locator(`#layer-${layer}`).check();
    await page.locator('#ladder-run').click();
    if (layer === 4) {
      await expect(page.locator('.chip-ok')).toContainText('Roots match — one history, no equivocation this epoch');
    } else {
      await expect(page.locator('.chip-ok')).toContainText('CONSISTENT — both users got the same key');
    }
    await expect(page.locator('#ladder-run').locator('..').locator('..')).not.toContainText('LIE UNDETECTED');
    // Both users got byte-identical keys.
    const omni = page.locator('.verdict-slot', { hasText: 'omniscient view' });
    expect(await omni.locator('.hex-diff').count()).toBe(0);
  }
});

test('exhibit 2 — an anchored client sees consistency PASS across the fork', async ({ page }) => {
  await page.goto('.');
  // Anchor Alice on an honest head first.
  await setToggles(page, { malicious: false, tamper: false });
  await page.locator('#layer-3').check();
  await page.locator('#ladder-run').click();
  await expect(page.locator('.note', { hasText: 'Anchored tree heads' })).toContainText('Alice: size');

  // Now turn the directory malicious and re-run at the same layer.
  await setToggles(page, { malicious: true, tamper: false });
  await page.locator('#ladder-run').click();

  await expect(page.locator('.chip-warn')).toContainText('Consistency PASSED across the fork — and still missed the lie');
  await expect(
    page.locator('.verdict-slot', { hasText: 'Alice’s checks' }).locator('.checklist'),
  ).toContainText('✓ Merkle consistency proof');
  const { passed, total } = await assertChecksSummaryConsistent(page);
  expect(passed).toBe(total);
  await expect(page.locator('.chip-alarm')).toContainText('LIE UNDETECTED at layer 3');
});

// ---------------------------------------------------------------- Exhibit 3

test('exhibit 3 — honest append reconstructs both roots byte-for-byte', async ({ page }) => {
  await page.goto('.');
  await page.locator('#scn-append').check();
  await expect(page.locator('#stepper-all')).toBeEnabled();

  // The page states the proof size; the trace must have exactly that many steps.
  const nodes = await num(page, '.panel:has(#stepper-all) .note', /Proof has (\d+) nodes/);
  await page.locator('#stepper-all').click();
  await expect(page.locator('.trace-table tbody tr')).toHaveCount(nodes);

  await expect(page.locator('.chip-ok')).toContainText('APPEND PROVEN — the new tree contains the old tree unchanged');
  await expect(page.locator('.chip-neutral', { hasText: 'old root reconstructed exactly' })).toBeVisible();
  await expect(page.locator('.chip-neutral', { hasText: 'new root reconstructed exactly' })).toBeVisible();
  // Byte-level honesty: nothing differs.
  expect(await page.locator('.verdict-slot:has-text("rebuilt old root") .hex-diff').count()).toBe(0);
  expect(await page.locator('.verdict-slot:has-text("rebuilt new root") .hex-diff').count()).toBe(0);
});

test('exhibit 3 — forked history fails closed, and says which root did not match', async ({ page }) => {
  await page.goto('.');
  await page.locator('#scn-fork').check();
  await expect(page.locator('#stepper-all')).toBeEnabled();

  const nodes = await num(page, '.panel:has(#stepper-all) .note', /Proof has (\d+) nodes/);
  await page.locator('#stepper-all').click();
  await expect(page.locator('.trace-table tbody tr')).toHaveCount(nodes);

  await expect(page.locator('.chip-ok')).toContainText('FORK EXPOSED — no consistency proof can connect two histories');
  await expect(page.locator('.chip-neutral', { hasText: 'MISMATCH — this proof does not contain Alice’s history' })).toBeVisible();
  // The stated reason is the real failReason from the verifier.
  await expect(page.locator('.note', { hasText: 'The verifier fails closed' })).toContainText(
    'reconstructed old root does not match the root the client already holds',
  );
  // The rebuilt OLD root really differs from the head Alice holds.
  expect(await page.locator('.verdict-slot:has-text("rebuilt old root") .hex-diff').count()).toBeGreaterThan(0);
});

test('exhibit 3 — stepping one row at a time reaches the same verdict', async ({ page }) => {
  await page.goto('.');
  await page.locator('#scn-append').check();
  await expect(page.locator('#stepper-next')).toBeEnabled();
  const rows = await page.locator('.trace-table tbody tr').count();
  expect(rows).toBeGreaterThan(0);
  for (let i = 0; i < rows; i++) await page.locator('#stepper-next').click();
  await expect(page.locator('#stepper-next')).toBeDisabled();
  await expect(page.locator('.chip-ok')).toContainText('APPEND PROVEN');
});

// ---------------------------------------------------------------- Exhibit 4

test('exhibit 4 — the tree slot the page shows is the one its own beta implies', async ({ page }) => {
  await page.goto('.');
  await page.locator('#vrf-derive').click();

  const dd = page.locator('.kv dd code');
  const slot = Number(await dd.nth(1).innerText());
  const beta = (await dd.nth(2).innerText()).trim();
  const pi = (await dd.nth(3).innerText()).trim();

  // RFC 9381 sizes, as the page labels them.
  expect(beta).toMatch(/^[0-9a-f]{128}$/);
  expect(pi).toMatch(/^[0-9a-f]{160}$/);

  // Recompute the projection the page documents: first 3 bytes of beta.
  const expected =
    (parseInt(beta.slice(0, 2), 16) << 16) | (parseInt(beta.slice(2, 4), 16) << 8) | parseInt(beta.slice(4, 6), 16);
  expect(slot).toBe(expected);

  await expect(page.locator('.chip-neutral', { hasText: 'ECVRF_verify(pk, α, π)' })).toContainText('valid');
  await expect(page.locator('.chip-neutral', { hasText: 'ECVRF_verify(pk, α, π)' })).not.toContainText('INVALID');
});

test('exhibit 4 — the observer list counts and sorts what it claims', async ({ page }) => {
  await page.goto('.');
  // Before deriving: the 22 seeded accounts.
  const baseline = await num(page, 'h3:has-text("What an observer sees")', /sees: (\d+) opaque labels/);
  expect(await page.locator('.label-list li').count()).toBe(baseline);

  // A name that is NOT already in the directory must add exactly one row.
  await page.locator('#vrf-name').fill('zaphod');
  await page.locator('#vrf-derive').click();
  const after = await num(page, 'h3:has-text("What an observer sees")', /sees: (\d+) opaque labels/);
  expect(after).toBe(baseline + 1);
  const rows = await page.locator('.label-list li code').allInnerTexts();
  expect(rows).toHaveLength(after);

  // Exactly one row is the derived one, and it is highlighted.
  await expect(page.locator('.label-mine')).toHaveCount(1);
  await expect(page.locator('.label-mine')).toContainText('the label you just derived');

  // The page claims rows are sorted by label (tree order). Check it.
  const labels = rows.map((r) => r.match(/label ([0-9a-f]+)/)![1]);
  expect(labels).toEqual([...labels].sort());

  // A name already in the directory must NOT add a row.
  await page.locator('#vrf-name').fill('bob');
  await page.locator('#vrf-derive').click();
  expect(await num(page, 'h3:has-text("What an observer sees")', /sees: (\d+) opaque labels/)).toBe(baseline);
});

test('exhibit 4 — one flipped bit in the proof is rejected', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#vrf-tamper')).toBeDisabled();
  await page.locator('#vrf-derive').click();
  await expect(page.locator('#vrf-tamper')).toBeEnabled();
  await page.locator('#vrf-tamper').click();

  await expect(page.locator('.chip-neutral', { hasText: 'ECVRF_verify on the tampered proof' })).toContainText(
    'INVALID',
  );
  await expect(page.locator('.chip-ok', { hasText: 'REJECTED' })).toContainText(
    'REJECTED — the directory cannot forge or reassign a label',
  );
  await expect(page.locator('.slot-title', { hasText: 'You flipped bit 0 of byte 40' })).toBeVisible();
});

// ---------------------------------------------------------------- Exhibit 5

test('exhibit 5 — honest log: Bob’s audit is CLEAN and every entry proves inclusion', async ({ page }) => {
  await page.goto('.');
  await setToggles(page, { malicious: false, tamper: false });
  await page.locator('#monitor-run').click();

  const panel = page.locator('.panel', { hasText: 'Monitoring — the attacker must leave a receipt' });
  const claimed = await num(panel, 'h3', /published log \((\d+) entr/);
  await expect(panel.locator('.checklist li')).toHaveCount(claimed);
  await expect(panel.locator('.check-fail')).toHaveCount(0);
  // Every inclusion proof really verified.
  const details = await panel.locator('.check-detail').allInnerTexts();
  expect(details).toHaveLength(claimed);
  for (const d of details) expect(d).toContain('verifies ✓');

  await expect(page.locator('.chip-ok')).toContainText('CLEAN — every key in Bob’s history is one Bob registered');
});

test('exhibit 5 — malicious log: the planted key is found, with its inclusion proof', async ({ page }) => {
  await page.goto('.');
  await setToggles(page, { malicious: true, tamper: false });
  await page.locator('#monitor-run').click();

  const panel = page.locator('.panel', { hasText: 'Monitoring — the attacker must leave a receipt' });
  const claimed = await num(panel, 'h3', /published log \((\d+) entr/);
  await expect(panel.locator('.checklist li')).toHaveCount(claimed);

  // The verdict's planted count must equal the number of unrecognised rows.
  const planted = await panel.locator('.check-fail').count();
  expect(planted).toBeGreaterThan(0);
  const verdict = await panel.locator('.chip-alarm').innerText();
  const m = verdict.match(/INTRUSION FOUND — (\d+) key under Bob’s name that Bob never made/);
  expect(m, `unexpected verdict: ${verdict}`).not.toBeNull();
  expect(Number(m![1])).toBe(planted);
  // ...and the recognised rows account for the rest.
  expect(claimed - planted).toBe(await panel.locator('.checklist li:not(.check-fail)').count());

  await expect(panel.locator('.check-fail .check-label')).toContainText('I NEVER generated this key');
  // The receipt: the planted entry's own inclusion proof verifies against the signed root.
  await expect(panel.locator('.check-fail .check-detail')).toContainText('verifies ✓');
  await expect(panel.locator('.check-fail .check-detail')).toContainText(
    'this entry is now cryptographic evidence of the attack',
  );
  await expect(page.locator('.chip-warn')).toContainText('Detection, not prevention');
});
