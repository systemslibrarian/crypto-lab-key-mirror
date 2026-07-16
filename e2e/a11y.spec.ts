import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal collapsed content and drive every exhibit — including the attack's
 * alarm states, the layer-4 gossip verdict, the failing fork trace, the VRF
 * tamper rejection, and the monitor's intrusion finding — so axe scans the
 * page in its richest state.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });

  // Exhibit 1: turn the directory malicious and run the whole interception.
  const evil = page.locator('#evil-toggle');
  if (!(await evil.isChecked())) await evil.check();
  await expect(page.locator('.ledger-shadow')).toBeVisible();
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-step')).toBeDisabled();

  // Exhibit 2: run the ladder at layer 0, then layer 4 (gossip verdict).
  await page.locator('#ladder-run').click();
  await page.locator('#layer-4').check();
  await page.locator('#ladder-run').click();
  await expect(page.getByText('EQUIVOCATION PROVEN')).toBeVisible();

  // Exhibit 3: run the forked-history trace to completion.
  await page.locator('#scn-fork').check();
  await expect(page.locator('#stepper-all')).toBeEnabled();
  await page.locator('#stepper-all').click();
  await expect(page.getByText('FORK EXPOSED')).toBeVisible();

  // Exhibit 4: derive a label, then tamper with the proof.
  await page.locator('#vrf-derive').click();
  await page.locator('#vrf-tamper').click();
  await expect(page.getByText('REJECTED — the directory cannot forge')).toBeVisible();

  // Exhibit 5: Bob audits and finds the planted key.
  await page.locator('#monitor-run').click();
  await expect(page.getByText('INTRUSION FOUND')).toBeVisible();

  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
