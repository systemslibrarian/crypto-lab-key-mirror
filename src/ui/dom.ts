/** Tiny DOM helpers — no framework, no magic. */

type Attrs = Record<string, string | boolean | undefined>;
type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'className') node.setAttribute('class', String(v));
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/**
 * A crypto-result chip: NEUTRAL styling with icon + text. Raw crypto results
 * never carry the green/red integrity colors — those belong to verdicts.
 */
export function resultChip(label: string, ok: boolean): HTMLElement {
  return el(
    'p',
    { className: 'chip chip-neutral' },
    el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, ok ? '✓' : '✗'),
    `${label}: ${ok ? 'valid' : 'INVALID'}`,
  );
}

export type Verdict = 'safe' | 'alarm' | 'warn';

/** A verdict chip: color tracks SYSTEM INTEGRITY (icon + text + color, never color alone). */
export function verdictChip(kind: Verdict, text: string): HTMLElement {
  const icon = kind === 'safe' ? '✓' : kind === 'alarm' ? '⚠' : '●';
  return el(
    'p',
    { className: `chip chip-${kind === 'safe' ? 'ok' : kind}` },
    el('span', { className: 'chip-icon', 'aria-hidden': 'true' }, icon),
    text,
  );
}

export function hexBlock(label: string, hex: string, extra?: string): HTMLElement {
  return el(
    'div',
    {},
    el('span', { className: 'hexlabel' }, label),
    el('code', { className: 'hexblock' }, hex, extra ? el('span', { className: 'msg-meta' }, ` ${extra}`) : null),
  );
}

/** Render two hex strings with per-nibble diff highlighting (byte-level honesty). */
export function hexDiff(a: string, b: string): { aNode: HTMLElement; bNode: HTMLElement; differs: boolean } {
  const len = Math.max(a.length, b.length);
  const aNode = el('code', { className: 'hexblock' });
  const bNode = el('code', { className: 'hexblock' });
  let differs = false;
  for (let i = 0; i < len; i += 2) {
    const ca = a.slice(i, i + 2);
    const cb = b.slice(i, i + 2);
    const same = ca === cb;
    if (!same) differs = true;
    aNode.append(el('span', { className: same ? 'hex-match' : 'hex-diff' }, ca));
    bNode.append(el('span', { className: same ? 'hex-match' : 'hex-diff' }, cb));
  }
  return { aNode, bNode, differs };
}

export function short(hex: string, n = 16): string {
  return hex.length <= n ? hex : `${hex.slice(0, n)}…`;
}

/** A live region that announces its updates politely. */
export function liveRegion(className = ''): HTMLElement {
  return el('div', { role: 'status', 'aria-live': 'polite', className });
}
