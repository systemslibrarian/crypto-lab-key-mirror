import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this replaces
 *     opened `prepare()` with `addStyleTag({ content: '*{animation:none
 *     !important;transition:none!important}' })`. That does not merely steady
 *     the page — it BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` blocks (there are two, one for
 *     `.flow-node`/`.flow-edge` and one for `.steps li`) instead of exercising
 *     them, so the suite was structurally unable to see a defect in the code
 *     path a motion-sensitive reader gets. It also force-opened every
 *     `<details>` from script rather than clicking its summary.
 *
 *  2. THE SHIPPED DEFAULT IS SCANNED. The replaced spec's very first action was
 *     `if (!(await evil.isChecked())) await evil.check()` — it turned the
 *     directory malicious before it scanned anything, so the HONEST state, which
 *     is what every visitor loads, was never measured once. That is the
 *     "a gate that scans one configuration scans one half" failure exactly: the
 *     safe/green palette and the single-ledger layout had no coverage at all.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE, and one scan at the end of a drive
 *     throws away every state the drive built. The replaced spec ran the entire
 *     lab — five exhibits, both attack modes — and then scanned once. See
 *     `scan`, which is called after every step.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** `await`-able soft wrapper for the assertions that live inside a helper. */
async function softCall(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String((e as Error).message ?? e));
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The SHIPPED DEFAULTS are asserted rather than assumed. Every one of them
 * matters to what a scan sees: the directory arrives HONEST (one ledger, green
 * verdict palette, six flow parts instead of eight), the bit-flip toggle is OFF,
 * the defense ladder sits at layer 0, the consistency stepper on the honest
 * append scenario, and the VRF proof-tamper button starts disabled. The spec
 * this replaces asserted none of them and flipped the first one before its first
 * scan.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
  // index.html's anti-flash script stamps `data-theme` unconditionally
  // (`saved ?? 'dark'`) from the same 'theme' key the shared header's toggle
  // writes, so both themes are checkable by attribute here.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The exhibits are mounted by an async `boot()`; nothing exists before it.
  await expect(page.locator('#exhibits .panel')).toHaveCount(7);
  await expect(page.locator('.cl-hero-title')).toHaveText('Key Mirror');

  // Shipped defaults, asserted.
  await expect(page.locator('#evil-toggle')).not.toBeChecked();
  await expect(page.locator('#tamper-toggle')).not.toBeChecked();
  await expect(page.locator('.ledger-shadow')).toHaveCount(0);
  await expect(page.locator('#layer-0')).toBeChecked();
  await expect(page.locator('#scn-append')).toBeChecked();
  await expect(page.locator('#vrf-tamper')).toBeDisabled();
  await expect(page.locator('#attack-step')).toBeEnabled();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex roots, a two-column ledger
 * grid, a four-column consistency-trace table and a message-journey diagram
 * whose nodes carry `min-width: 6.5rem`.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This lab does not have
    // that rule today; the check stays honest against one being added.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // consistency-trace table lives inside `.tracewrap`, an `overflow-x: auto`
    // scroller, so its bounding rect is far wider than a phone viewport while
    // contributing nothing to the document's scroll width — naming it would
    // send you off fixing an element that is already reachable.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0]!;
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest:
        `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
        `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
        ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`,
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * `.label-scroll` and `.tracewrap` already carry it. `.flow-track` does not,
 * and it only overflows once the message-journey diagram has been populated at
 * a narrow viewport — a state that exists only part-way through the drive,
 * which is why this runs after every step rather than once at the end.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr` and
 *    `aria-required-children`, neither of which reliably reaches `violations`.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * WCAG 1.4.11 (non-text contrast) has no oracle here either; the repo keeps a
 * dedicated spec for it in `border-contrast.spec.ts`.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await softCall(() => expectNotBlank(page, label));
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await softCall(() => expectScrollersReachable(page, label));
  await softCall(() => expectNoHorizontalOverflow(page, label));
}

/**
 * Step exhibit 1 to completion ONE PRESS AT A TIME, scanning each step.
 *
 * The step list is the exhibit: each `<li>` moves from `.step-pending` (dashed,
 * dimmed) through `.step-active` (accent ring) to done or `.step-alarm`, and the
 * message-journey diagram lights one more `.flow-node`/`.flow-edge` per press.
 * Pressing "Run all steps" — which is what the replaced spec did — skips every
 * intermediate rendering, and scanning only at the end throws away all of them.
 */
async function stepAttackThrough(page: Page, label: string): Promise<void> {
  const step = page.locator('#attack-step');
  let pressed = 0;
  while (await step.isEnabled()) {
    await step.click();
    pressed++;
    await expect(page.locator('.steps li').nth(pressed - 1)).not.toHaveClass(/step-pending/);
    await scan(page, `${label} / step ${pressed}`);
    // The lab disables the button on the last step; guard against a runaway.
    expect(pressed, 'the attack sequence must terminate').toBeLessThan(12);
  }
  expect(pressed, 'the attack must have at least five steps').toBeGreaterThanOrEqual(5);
  await expect(page.locator('#attack-step')).toBeDisabled();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five exhibits, and the two-by-two fork at the top of the first one — the
 * directory honest or malicious, crossed with the ciphertext bit-flip on or
 * off — because each quadrant produces a DIFFERENT verdict chip and a different
 * palette:
 *
 *   honest + clean   → `.chip-ok`    CONSISTENT
 *   honest + flipped → `.chip-warn`  TAMPER DETECTED
 *   evil   + clean   → `.chip-alarm` INTERCEPTED, UNDETECTED
 *   evil   + flipped → `.chip-warn`  plus the alarm ledger and the shadow view
 *
 * The replaced spec scanned only the third of those, once, at the end.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint (honest directory)`);

  // The skip link is `top: -3rem` until focused. Its focused rendering is the
  // only one a keyboard user ever sees, and it is the first tab stop.
  await page.keyboard.press('Tab');
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await scan(page, `${theme} / skip link focused`);

  /* ── Exhibit 1, quadrant 1: honest directory, clean ciphertext ────────── */
  await stepAttackThrough(page, `${theme} / honest+clean`);
  await expect(page.locator('#exhibits .panel').nth(1).locator('.chip-ok')).toContainText(
    'CONSISTENT',
  );
  await scan(page, `${theme} / honest+clean verdict`);

  // The expert disclosure, opened through its own summary rather than by
  // setting `.open` from script.
  const expert = page.locator('#exhibits details.expert').first();
  await expert.locator('summary').click();
  await expect(expert).toHaveAttribute('open', '');
  await scan(page, `${theme} / expert note open`);
  await expert.locator('summary').click();
  await expect(expert).not.toHaveAttribute('open', '');

  /* ── Exhibit 1, quadrant 2: honest directory, bit flipped ─────────────── */
  // Toggling this re-runs `reset()`, so the sequence starts over.
  await page.locator('#tamper-toggle').check();
  await expect(page.locator('#attack-step')).toBeEnabled();
  await scan(page, `${theme} / honest+flipped, reset`);
  await page.locator('#attack-run').click();
  await expect(page.locator('.chip-warn')).toContainText('TAMPER DETECTED');
  await scan(page, `${theme} / honest+flipped verdict`);

  /* ── Exhibit 1, quadrant 3: malicious directory, clean ─────────────────── */
  await page.locator('#tamper-toggle').uncheck();
  await page.locator('#evil-toggle').check();
  await expect(page.locator('.ledger-shadow')).toBeVisible();
  await expect(page.locator('#attack-step')).toBeEnabled();
  await scan(page, `${theme} / malicious directory, before any step`);
  await stepAttackThrough(page, `${theme} / evil+clean`);
  await expect(page.locator('.chip-alarm')).toContainText('INTERCEPTED, UNDETECTED');
  await scan(page, `${theme} / evil+clean verdict`);

  /* ── Exhibit 1, quadrant 4: malicious directory, bit flipped ──────────── */
  await page.locator('#tamper-toggle').check();
  await page.locator('#attack-run').click();
  await expect(page.locator('.chip-warn')).toContainText('TAMPER DETECTED');
  await scan(page, `${theme} / evil+flipped verdict`);

  // A custom message, so the exhibit is not only ever scanned with its default
  // text — and Reset, the exhibit's own reset control.
  await page.locator('#tamper-toggle').uncheck();
  await page.locator('#attack-msg').fill('a much longer message, long enough to wrap the log line it lands in');
  await page.locator('#attack-reset').click();
  await expect(page.locator('#attack-step')).toBeEnabled();
  await page.locator('#attack-run').click();
  await scan(page, `${theme} / evil, custom message, run all`);

  /* ── Exhibit 2: every defense layer, not just the two extremes ─────────── */
  // The directory is still malicious here, which is the only setting under
  // which layers 1-3 teach anything: each check PASSES and the lie stands.
  for (const layer of [0, 1, 2, 3, 4]) {
    await page.locator(`#layer-${layer}`).check();
    await page.locator('#ladder-run').click();
    await expect(page.locator('#exhibits .panel').nth(2).locator('.chip').first()).toBeVisible();
    await scan(page, `${theme} / defense layer ${layer}`);
  }
  await expect(page.getByText('EQUIVOCATION PROVEN')).toBeVisible();

  // "New devices (forget anchors)" — the exhibit's reset.
  await page.locator('#ladder-forget').click();
  await scan(page, `${theme} / ladder anchors forgotten`);

  /* ── Exhibit 3: both scenarios, stepped and then run to the end ────────── */
  for (const scenario of ['append', 'fork'] as const) {
    await page.locator(`#scn-${scenario}`).check();
    await expect(page.locator('#stepper-all')).toBeEnabled();
    await scan(page, `${theme} / stepper ${scenario}, no steps taken`);
    // Three individual presses first: `.trace-now` only ever marks one row, and
    // "Run all" jumps past every intermediate rendering of it.
    for (let i = 0; i < 3 && (await page.locator('#stepper-next').isEnabled()); i++) {
      await page.locator('#stepper-next').click();
      await expect(page.locator('.trace-table tr.trace-now')).toHaveCount(1);
      await scan(page, `${theme} / stepper ${scenario}, step ${i + 1}`);
    }
    // The honest-append trace is short enough that three presses can already
    // finish it, at which point the lab disables both controls — so "run all"
    // is only pressed when there is still something left to run.
    if (await page.locator('#stepper-all').isEnabled()) {
      await page.locator('#stepper-all').click();
    }
    await expect(page.locator('#stepper-next')).toBeDisabled();
    await scan(page, `${theme} / stepper ${scenario}, complete`);
  }
  await expect(page.getByText('FORK EXPOSED')).toBeVisible();

  /* ── Exhibit 4: VRF derive, then the tamper rejection ──────────────────── */
  await page.locator('#vrf-derive').click();
  await expect(page.locator('#vrf-tamper')).toBeEnabled();
  await expect(page.locator('.label-list li.label-mine')).toHaveCount(1);
  await scan(page, `${theme} / vrf derived for the default name`);

  // A name that is NOT one of the 22 seeded users takes the other branch of
  // `renderObserver`: the list grows by one rather than highlighting a row.
  await page.locator('#vrf-name').fill('zebedee');
  await page.locator('#vrf-derive').click();
  await expect(page.locator('.label-list li')).toHaveCount(23);
  await scan(page, `${theme} / vrf derived for an unseeded name`);

  await page.locator('#vrf-tamper').click();
  await expect(page.getByText('REJECTED — the directory cannot forge')).toBeVisible();
  await scan(page, `${theme} / vrf proof tampered and rejected`);

  /* ── Exhibit 5: the monitor's audit ────────────────────────────────────── */
  await page.locator('#monitor-run').click();
  await expect(page.getByText('INTRUSION FOUND')).toBeVisible();
  await scan(page, `${theme} / monitor found the planted key`);

  /* ── Back to honest: the exhibit-1 palette nobody had measured ─────────── */
  await page.locator('#evil-toggle').uncheck();
  await expect(page.locator('.ledger-shadow')).toHaveCount(0);
  await page.locator('#attack-run').click();
  // Scoped to exhibit 1: by this point the ladder, stepper and VRF exhibits
  // have all left `.chip-ok` chips of their own on the page.
  await expect(page.locator('#exhibits .panel').nth(1).locator('.chip-ok')).toContainText(
    'CONSISTENT',
  );
  await scan(page, `${theme} / directory returned to honest`);
}
