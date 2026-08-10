import { expect, test } from '@playwright/test';
import { boot, driveAllStates } from './gate';

/**
 * WCAG 2.1 SC 1.4.11 — non-text contrast, for the boundaries that identify a
 * control.
 *
 * WHY THIS FILE WAS REWRITTEN. The version it replaces queried exactly one
 * selector: `#app input[type="text"]`. That is the ONLY rule in `styles.css`
 * that ever used `--control-border`, the 3:1 token — every other control,
 * including every `.btn`, was drawn with `--border`, the decorative one, at
 * 1.42-1.73:1. So the spec asserted the one place the fix had already been
 * applied and was structurally incapable of reporting the ten places it had
 * not. A check that cannot fail is not a check; it is a claim.
 *
 * The rewrite enumerates every interactive control the page actually renders,
 * in every state the drive reaches, and measures each one's boundary against
 * the surface behind it. "Enumerates" is the load-bearing word: nothing here
 * names a class, so a control added later is covered the day it ships.
 *
 * What counts as the boundary: an element's own `outline` if it draws one,
 * otherwise its border. What it is measured against: the nearest ancestor that
 * paints an opaque background — which is not always the parent, because this
 * page nests controls inside `.controls` rows that paint nothing.
 *
 * A control whose FILL already clears 3:1 against that surface needs no border
 * at all (SC 1.4.11 asks that the component be perceivable, not that it be
 * outlined), so either measurement passing is a pass. `.btn-primary` is the
 * case that matters: it is a solid accent fill, and its border is the same
 * colour as the fill.
 *
 * Disabled controls are exempt — SC 1.4.11 excludes inactive components, and
 * this lab disables `#stepper-next`, `#attack-step` and `#vrf-tamper` at the
 * ends of their sequences.
 */

interface Finding {
  selector: string;
  state: string;
  boundary: number;
  fill: number;
  detail: string;
}

async function auditControlBoundaries(page: import('@playwright/test').Page, state: string) {
  return page.evaluate((label: string) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    const resolve = (c: string): [number, number, number, number] | null => {
      if (!c) return null;
      // Two sentinels: a valid colour normalises to the same value from either,
      // an invalid one leaves each sentinel in place and they disagree. This is
      // also what converts `color-mix(in oklab, ...)` — which Chromium reports
      // back verbatim — into sRGB, so the accent-tinted fills here are readable.
      ctx.fillStyle = '#000';
      ctx.fillStyle = c;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = c;
      if (a !== ctx.fillStyle) return null;
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = c;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return [d[0]!, d[1]!, d[2]!, d[3]! / 255];
    };
    const over = (
      s: [number, number, number, number],
      d: [number, number, number, number],
    ): [number, number, number, number] => {
      const a = s[3] + d[3] * (1 - s[3]);
      if (a === 0) return [0, 0, 0, 0];
      return [
        (s[0] * s[3] + d[0] * d[3] * (1 - s[3])) / a,
        (s[1] * s[3] + d[1] * d[3] * (1 - s[3])) / a,
        (s[2] * s[3] + d[2] * d[3] * (1 - s[3])) / a,
        a,
      ];
    };
    const lum = (c: [number, number, number, number]): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
    };
    const ratio = (a: [number, number, number, number], b: [number, number, number, number]) => {
      const l1 = lum(a);
      const l2 = lum(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };

    /** The first ancestor that paints something opaque behind this element. */
    const surfaceBehind = (el: Element): [number, number, number, number] => {
      let acc: [number, number, number, number] = [0, 0, 0, 0];
      let n: Element | null = el.parentElement;
      while (n) {
        const c = resolve(getComputedStyle(n).backgroundColor);
        if (c && c[3] > 0) {
          acc = over(acc, c);
          if (acc[3] >= 1) return acc;
        }
        n = n.parentElement;
      }
      // The canvas: the root's background paints the whole page regardless of
      // the root's own box.
      const root = resolve(getComputedStyle(document.documentElement).backgroundColor);
      return root && root[3] > 0 ? over(acc, root) : over(acc, [255, 255, 255, 1]);
    };

    const CONTROLS = 'button, input, select, textarea, [tabindex]:not([tabindex="-1"])';
    const out: {
      selector: string;
      state: string;
      boundary: number;
      fill: number;
      detail: string;
    }[] = [];

    for (const el of Array.from(document.querySelectorAll<HTMLElement>(`#app ${CONTROLS}`))) {
      if ((el as HTMLInputElement).disabled) continue;
      if (el.getAttribute('aria-disabled') === 'true') continue;
      if (!el.checkVisibility?.()) continue;
      const r = el.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) continue;
      const cs = getComputedStyle(el);
      // Native checkboxes and radios are painted by the UA from `accent-color`;
      // there is no author boundary to measure and the UA guarantees its own.
      const type = (el as HTMLInputElement).type;
      if (type === 'checkbox' || type === 'radio') continue;

      const behind = surfaceBehind(el);
      // An `outline` paints OUTSIDE the border box, so its backdrop is the
      // surround; a border may composite over the element's own fill, so it is
      // judged against the surround too (the stricter of the two readings).
      const outlineWidth = parseFloat(cs.outlineWidth);
      const hasOutline = cs.outlineStyle !== 'none' && outlineWidth > 0;
      const borderWidth = Math.max(
        parseFloat(cs.borderTopWidth),
        parseFloat(cs.borderLeftWidth),
      );
      const hasBorder = cs.borderTopStyle !== 'none' && borderWidth > 0;
      const edgeColor = hasOutline
        ? resolve(cs.outlineColor)
        : hasBorder
          ? resolve(cs.borderTopColor)
          : null;
      const fillColor = resolve(cs.backgroundColor);

      const boundary = edgeColor && edgeColor[3] > 0 ? ratio(over(edgeColor, behind), behind) : 0;
      const fill = fillColor && fillColor[3] > 0 ? ratio(over(fillColor, behind), behind) : 0;

      const show = (c: [number, number, number, number] | null) =>
        c ? `rgb(${c.slice(0, 3).map(Math.round).join(', ')})` : 'none';
      out.push({
        selector:
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
          `${el.className ? '.' + String(el.className).trim().split(/\s+/).join('.') : ''}`,
        state: label,
        boundary: Math.round(boundary * 100) / 100,
        fill: Math.round(fill * 100) / 100,
        detail: `edge ${show(edgeColor)} / fill ${show(fillColor)} on ${show(behind)}`,
      });
    }
    return out;
  }, state);
}

const findings: Finding[] = [];

/**
 * Sampled at every state of the full drive, not once at load. Several of these
 * controls do not exist, or are disabled, until the lab has been driven — and
 * `.btn:hover` and `:focus-visible` change the boundary colour outright.
 */
for (const theme of ['dark', 'light'] as const) {
  test(`${theme}: every control boundary clears 3:1 (SC 1.4.11)`, async ({ page }) => {
    test.setTimeout(900_000);
    const seen: Finding[] = [];
    await boot(page, theme);
    seen.push(...(await auditControlBoundaries(page, `${theme} / first paint`)));
    // Reuse the a11y drive so this spec covers exactly the states that one
    // does — including the ones where a control is first enabled.
    await driveAllStates(page, `${theme} / 1.4.11 sweep`);
    seen.push(...(await auditControlBoundaries(page, `${theme} / end of drive`)));

    // Hover and keyboard focus, sampled on the control itself. `.btn:hover`
    // swaps the border to `--accent-text`, and `#app :focus-visible` draws a
    // 2px outline that replaces the border as the boundary.
    const first = page.locator('#app .btn:not([disabled])').first();
    await first.hover();
    seen.push(...(await auditControlBoundaries(page, `${theme} / hovered`)));
    await page.keyboard.press('Tab');
    seen.push(...(await auditControlBoundaries(page, `${theme} / focused`)));

    findings.push(...seen);
    const failing = seen.filter((f) => f.boundary < 3 && f.fill < 3);
    expect(
      failing.map((f) => `${f.state}: ${f.selector} — boundary ${f.boundary}:1, fill ${f.fill}:1 (${f.detail})`),
      'control boundaries below 3:1 (SC 1.4.11)',
    ).toEqual([]);

    // A check that never looks at anything is the failure mode this file is
    // being rewritten to remove — the version it replaces measured ONE
    // selector — so assert the sweep found a plausible population, both at load
    // and across the drive. Ten controls are on screen at first paint.
    const atLoad = seen.filter((f) => f.state.endsWith('first paint'));
    expect(atLoad.length, 'the load-time sweep must cover every control, not one').toBeGreaterThanOrEqual(8);
    expect(seen.length, 'the sweep must actually find controls to measure').toBeGreaterThanOrEqual(32);
  });
}
