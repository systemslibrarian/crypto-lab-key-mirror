import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and scanned after every step:
 * the arrival state, where the directory is HONEST — one ledger, the green
 * verdict palette, six flow parts instead of eight — which the spec this
 * replaces never scanned once, because its first action was to turn the
 * directory malicious; the skip link focused; all four quadrants of exhibit 1's
 * fork (honest/malicious crossed with the ciphertext bit-flip on/off), each of
 * which produces a different verdict chip; the attack sequence stepped ONE PRESS
 * AT A TIME rather than run in one go, so every `.step-active` ring and every
 * partially-lit message-journey diagram is measured; the expert `<details>`
 * opened through its own summary; all five defense layers rather than only 0 and
 * 4; both consistency-proof scenarios, stepped and then completed; the VRF label
 * derived for both a seeded and an unseeded name and then tampered; the
 * monitor's audit; and the return to an honest directory. Every one of those
 * states is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why the shipped
 * defaults are asserted rather than assumed, and why `violations` is not the
 * whole oracle. WCAG 1.4.11 is covered separately in `border-contrast.spec.ts`.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
