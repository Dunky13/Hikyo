import AxeBuilder from '@axe-core/playwright';
import { expect, type Locator, type Page } from '@playwright/test';

import { recordPinnedRun } from '../registry.ts';

/**
 * The pinned assertion set (mvp-boundary S3, ui-spec).
 *
 * Every flow in the registry runs these; later tickets add flows, never a new
 * definition of "accessible". Each one is here because a locked decision says
 * so, and the comment says which:
 *
 *   1. axe-core serious/critical = 0.
 *   2. Every error and status state is carried by TEXT and ARIA — asserted
 *      with colour stripped, because "never colour-only" is only proven when
 *      the colour is gone.
 *   3. Every interactive element a flow touches has a VISIBLE focus
 *      indicator.
 *   4. Text contrast >= 4.5:1, computed from the rendered pixels.
 *   5. Touch targets >= 44px on the mobile viewport.
 *   6. Computed styles match DESIGN.md's token table — radius roles, the
 *      reserved pill, the two typefaces.
 */

// --- 1. axe ----------------------------------------------------------------

export async function expectNoSeriousAxeViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'])
    .analyze();
  const blocking = results.violations.filter(
    (v) => v.impact === 'serious' || v.impact === 'critical',
  );
  expect(
    blocking.map((v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target).join(' | ')}`),
    'axe-core serious/critical violations',
  ).toEqual([]);
}

// --- 2. state without colour ----------------------------------------------

/**
 * expectStatusIsTextAndAria asserts a state is announced and readable with
 * every colour removed. `forced-colors: active` is the strongest available
 * stand-in for "the colour is gone": the OS repaints the palette, so anything
 * still legible is legible because of its text, its glyph or its border.
 */
export async function expectStatusIsTextAndAria(page: Page, status: Locator): Promise<void> {
  await expect(status).toBeVisible();

  const role = await status.getAttribute('role');
  const live = await status.getAttribute('aria-live');
  expect(
    role === 'alert' || role === 'status' || live === 'polite' || live === 'assertive',
    'a state must announce itself: role="alert"/"status" or aria-live',
  ).toBe(true);

  await page.emulateMedia({ forcedColors: 'active' });
  try {
    await expect(status).toBeVisible();
    const text = ((await status.textContent()) ?? '').trim();
    expect(text.length, 'a state carried by colour alone says nothing here').toBeGreaterThan(0);
  } finally {
    await page.emulateMedia({ forcedColors: 'none' });
  }
}

// --- 3. focus --------------------------------------------------------------

/**
 * expectVisibleFocusIndicator focuses an element and requires a ring that is
 * actually VISIBLE.
 *
 * "The computed style changed" is not enough and neither is "outline-style is
 * not none": `outline: 2px solid transparent` satisfies both and draws
 * nothing, and an outline the same colour as what it sits on is invisible for
 * the same reason a white ring on white paper is. So the assertion samples the
 * ring's colour through the browser, requires it to be opaque, and requires it
 * to clear WCAG 2.2's 3:1 non-text contrast against the surface behind it.
 *
 * The ring may be drawn with `outline` or with `box-shadow`; both are checked,
 * because forbidding one would be a house style rather than an accessibility
 * rule.
 *
 * It is then re-checked under `forced-colors`, where the OS repaints the
 * palette: a ring that only exists as an author colour disappears there, and
 * that is precisely the user who most needs it.
 */
export async function expectVisibleFocusIndicator(page: Page, target: Locator): Promise<void> {
  // Establish keyboard modality first. Chrome only matches `:focus-visible` on
  // a scripted focus when the last interaction was a key press, so focusing
  // straight from a click-driven test would measure the wrong state and report
  // a missing ring on a surface that has one.
  await page.keyboard.press('Tab');
  await target.focus();
  await expect(target).toBeFocused();

  const ring = await target.evaluate((el) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) {
      throw new Error('no 2d context to sample colours with');
    }
    const sample = (value: string): [number, number, number, number] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = value;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return [d[0] ?? 0, d[1] ?? 0, d[2] ?? 0, (d[3] ?? 0) / 255];
    };
    const luminance = ([r, g, b]: [number, number, number, number]) => {
      const ch = (c: number) => {
        const v = c / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
    };
    // The ring is painted OUTSIDE the element, over whatever its ancestors
    // paint — so that, not the element's own fill, is what it must stand out
    // against.
    let node: Element | null = el.parentElement;
    let behind = getComputedStyle(document.body).backgroundColor;
    while (node !== null) {
      const value = getComputedStyle(node).backgroundColor;
      if (sample(value)[3] > 0.99) {
        behind = value;
        break;
      }
      node = node.parentElement;
    }

    const style = getComputedStyle(el);
    const drawn: Array<{ how: string; colour: string }> = [];
    if (style.outlineStyle !== 'none' && Number.parseFloat(style.outlineWidth) > 0) {
      drawn.push({ how: `outline ${style.outlineWidth} ${style.outlineStyle}`, colour: style.outlineColor });
    }
    if (style.boxShadow !== 'none' && style.boxShadow !== '') {
      // Computed box-shadow starts with its colour.
      const colour = /^(rgba?\([^)]*\)|oklch\([^)]*\)|#[0-9a-f]+)/i.exec(style.boxShadow)?.[1];
      if (colour !== undefined) {
        drawn.push({ how: `box-shadow ${style.boxShadow}`, colour });
      }
    }

    const behindL = luminance(sample(behind));
    const rings = drawn.map((d) => {
      const rgba = sample(d.colour);
      const l = luminance(rgba);
      return {
        how: d.how,
        colour: d.colour,
        alpha: rgba[3],
        contrast: (Math.max(l, behindL) + 0.05) / (Math.min(l, behindL) + 0.05),
      };
    });
    return { behind, rings };
  });

  expect(ring.rings.length, 'nothing is drawn on focus: no outline and no box-shadow').toBeGreaterThan(0);
  const visible = ring.rings.filter((r) => r.alpha > 0.99 && r.contrast >= 3);
  expect(
    visible.length,
    `no VISIBLE focus ring against ${ring.behind}: ` +
      ring.rings
        .map((r) => `${r.how} (${r.colour}, alpha ${r.alpha}, contrast ${r.contrast.toFixed(2)}:1)`)
        .join('; '),
  ).toBeGreaterThan(0);

  // Forced colors: the OS owns the palette, so an author-coloured ring is
  // gone. Chromium repaints `outline` with the system highlight; a component
  // that suppressed the outline in favour of a painted shadow has nothing left
  // here, which is the failure this leg exists to catch.
  await page.emulateMedia({ forcedColors: 'active' });
  try {
    await target.focus();
    const forced = await target.evaluate((el) => {
      const s = getComputedStyle(el);
      return { style: s.outlineStyle, width: Number.parseFloat(s.outlineWidth) };
    });
    expect(
      forced.style !== 'none' && forced.width > 0,
      `no focus outline under forced-colors (outline: ${forced.width}px ${forced.style})`,
    ).toBe(true);
  } finally {
    await page.emulateMedia({ forcedColors: 'none' });
  }
}

/** expectEveryFocusIndicator runs the focus assertion over a flow's controls. */
export async function expectEveryFocusIndicator(page: Page, targets: Locator[]): Promise<void> {
  for (const target of targets) {
    await expectVisibleFocusIndicator(page, target);
  }
}

// --- 4. contrast -----------------------------------------------------------

type Contrast = { ratio: number; foreground: string; background: string };

/** sampleRGB asks the browser what sRGB a CSS colour actually paints. */
async function sampleRGB(page: Page, colour: string): Promise<number[]> {
  return page.evaluate((value) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) {
      throw new Error('no 2d context to sample colours with');
    }
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = value;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    return [d[0] ?? 0, d[1] ?? 0, d[2] ?? 0];
  }, colour);
}

/**
 * measureContrast computes the WCAG ratio from the RENDERED colours: the
 * element's own text colour against the first ancestor that actually paints a
 * background. Reading the token values instead would prove the tokens contrast
 * with each other, not that this element does.
 */
async function measureContrast(target: Locator): Promise<Contrast> {
  return target.evaluate((el) => {
    // Colours are authored in OKLCH and `getComputedStyle` returns them that
    // way, so the ratio cannot be computed by pulling three numbers out of the
    // string. Painting each colour into a 1x1 canvas asks the BROWSER for the
    // sRGB it will actually display, which is the only honest source — and it
    // keeps working when the palette moves to another colour space.
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) {
      throw new Error('no 2d context to sample colours with');
    }
    const sample = (value: string): [number, number, number, number] => {
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = value;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return [d[0] ?? 0, d[1] ?? 0, d[2] ?? 0, (d[3] ?? 0) / 255];
    };
    const luminance = ([r, g, b]: [number, number, number, number]): number => {
      const channel = (c: number) => {
        const v = c / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
    };

    const foreground = getComputedStyle(el).color;
    // The effective background is the first ancestor that actually paints one.
    // A translucent layer keeps the walk going rather than being blended: the
    // skeleton has none, and guessing at compositing would make the number
    // look more precise than it is.
    let node: Element | null = el;
    let background = getComputedStyle(document.body).backgroundColor;
    while (node !== null) {
      const value = getComputedStyle(node).backgroundColor;
      if (sample(value)[3] > 0.99) {
        background = value;
        break;
      }
      node = node.parentElement;
    }

    const lf = luminance(sample(foreground));
    const lb = luminance(sample(background));
    const ratio = (Math.max(lf, lb) + 0.05) / (Math.min(lf, lb) + 0.05);
    return { ratio, foreground, background };
  });
}

/**
 * measureSurfaceLuminance reports how dark the page's own surface is, sampled
 * through the browser rather than parsed out of an OKLCH string. The
 * dark-default claim in DESIGN.md is about what a human SEES, so it is checked
 * against a rendered colour.
 */
export async function measureSurfaceLuminance(
  page: Page,
): Promise<{ colour: string; luminance: number }> {
  return page.evaluate(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx === null) {
      throw new Error('no 2d context to sample colours with');
    }
    const colour = getComputedStyle(document.body).backgroundColor;
    ctx.fillStyle = colour;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    const channel = (c: number) => {
      const v = c / 255;
      return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    };
    const luminance =
      0.2126 * channel(d[0] ?? 0) + 0.7152 * channel(d[1] ?? 0) + 0.0722 * channel(d[2] ?? 0);
    return { colour, luminance };
  });
}

export async function expectContrast(target: Locator, minimum = 4.5): Promise<void> {
  const { ratio, foreground, background } = await measureContrast(target);
  expect(
    ratio,
    `contrast ${ratio.toFixed(2)}:1 for ${foreground} on ${background}, want >= ${minimum}:1`,
  ).toBeGreaterThanOrEqual(minimum);
}

export async function expectEveryContrast(targets: Locator[], minimum = 4.5): Promise<void> {
  for (const target of targets) {
    await expectContrast(target, minimum);
  }
}

// --- 5. touch targets ------------------------------------------------------

/** The floor DESIGN.md fixes for touch: ~44px targets on mobile. */
export const TOUCH_TARGET_PX = 44;

/**
 * expectTouchTargets enforces the 44px floor where DESIGN.md actually sets it
 * — a coarse pointer. Desktop density is deliberately tighter (36px rows), so
 * applying the touch floor there would not be stricter, it would be wrong: it
 * would force the phone's spacing onto a mouse-driven grid the design says
 * should be dense.
 *
 * The check is skipped, never silently passed: on the desktop project the
 * mobile project is the one that runs it, and both run every flow.
 */
export async function expectTouchTargets(page: Page, targets: Locator[]): Promise<void> {
  const coarse = await page.evaluate(() => matchMedia('(pointer: coarse)').matches);
  if (!coarse) {
    return;
  }
  for (const target of targets) {
    const box = await target.boundingBox();
    expect(box, 'a control a flow touches has no box').not.toBeNull();
    if (box === null) {
      continue;
    }
    const name = (await target.getAttribute('aria-label')) ?? (await target.innerText());
    // Sub-pixel layout rounds: 43.99 is a 44px target, 40 is not.
    expect(Math.round(box.height), `touch height of ${name}`).toBeGreaterThanOrEqual(
      TOUCH_TARGET_PX,
    );
    expect(Math.round(box.width), `touch width of ${name}`).toBeGreaterThanOrEqual(TOUCH_TARGET_PX);
  }
}

// --- 6. DESIGN.md token conformance ---------------------------------------

/** The CSS properties DESIGN.md fixes a palette token for. */
export type ColourProp = 'color' | 'backgroundColor' | 'borderTopColor' | 'borderLeftColor';

/**
 * expectColourToken checks a component's rendered colour against a DESIGN.md
 * palette token.
 *
 * Both sides are sampled through the browser rather than string-compared: the
 * palette is OKLCH, `getComputedStyle` hands back whatever the author wrote,
 * and `oklch(0.19 0.012 220)` and a `color-mix` that resolves to the same
 * pixel are the same colour to a human. Comparing the PIXELS also catches the
 * failure that matters — a component that hard-coded a hex which happens to
 * look close.
 */
export async function expectColourToken(
  page: Page,
  target: Locator,
  prop: ColourProp,
  token: string,
): Promise<void> {
  const want = await tokenValue(page, token);
  const [got, expected] = await Promise.all([
    target.evaluate((el, p: ColourProp) => getComputedStyle(el)[p], prop),
    Promise.resolve(want),
  ]);
  const [a, b] = await Promise.all([sampleRGB(page, got), sampleRGB(page, expected)]);
  const near = a.every((v, i) => Math.abs(v - (b[i] ?? 0)) <= 1);
  expect(near, `${prop} is ${got} (rgb ${a.join()}), DESIGN.md's ${token} is ${expected} (rgb ${b.join()})`).toBe(
    true,
  );
}

/**
 * expectHairline checks DESIGN.md's "hairline borders (1px) over shadows":
 * a container that reaches for a 2px rule or a drop shadow instead is off the
 * design language, and on a phone it is also the thing that makes a dense
 * layout feel noisy.
 */
export async function expectHairline(target: Locator): Promise<void> {
  const width = await target.evaluate((el) => getComputedStyle(el).borderTopWidth);
  expect(width, 'DESIGN.md fixes hairline borders at 1px').toBe('1px');
}

/**
 * expectDensity checks a component against DESIGN.md's density scale: rows are
 * ~36px on a desktop pointer and grow to the 44px touch floor on a coarse one.
 * The token is read live, so the assertion tracks DESIGN.md rather than
 * restating it.
 */
export async function expectDensity(page: Page, target: Locator, token: string): Promise<void> {
  const want = Number.parseFloat(await tokenValue(page, token));
  const box = await target.boundingBox();
  expect(box, 'a component with no box has no density').not.toBeNull();
  expect(Math.round(box?.height ?? 0), `height against DESIGN.md's ${token}`).toBe(Math.round(want));
}

export type RadiusRole = 'container' | 'control' | 'badge' | 'pill';
export type FontRole = 'ui' | 'mono';

const RADIUS_TOKEN: Record<RadiusRole, string> = {
  container: '--radius-container',
  control: '--radius-control',
  badge: '--radius-badge',
  pill: '--radius-pill',
};

const FONT_TOKEN: Record<FontRole, string> = { ui: '--font-ui', mono: '--font-mono' };

async function tokenValue(page: Page, name: string): Promise<string> {
  return page.evaluate(
    (token) => getComputedStyle(document.documentElement).getPropertyValue(token).trim(),
    name,
  );
}

/**
 * expectRadiusRole checks a component against DESIGN.md's radius scale:
 * containers 6px, controls 4px, badges 3px, and the 999px pill reserved for
 * identity circles, count badges and matrix cell states.
 *
 * The expectation is read from the token at runtime rather than hard-coded, so
 * the assertion tracks DESIGN.md through one edit instead of two — and a
 * component that hard-codes `border-radius: 8px` fails whatever the token says.
 */
export async function expectRadiusRole(
  page: Page,
  target: Locator,
  role: RadiusRole,
): Promise<void> {
  const want = await tokenValue(page, RADIUS_TOKEN[role]);
  const got = await target.evaluate((el) => getComputedStyle(el).borderTopLeftRadius);
  // The pill is a clamp: 999px on a 36px circle computes to half the box.
  if (role === 'pill') {
    const box = await target.boundingBox();
    const half = Math.min(box?.width ?? 0, box?.height ?? 0) / 2;
    expect(Number.parseFloat(got), 'a pill must be fully round').toBeGreaterThanOrEqual(half - 0.5);
    return;
  }
  expect(got, `radius role "${role}" (DESIGN.md says ${want})`).toBe(want);
}

/** expectFontRole checks a component uses Archivo (UI) or IBM Plex Mono (keys/values). */
export async function expectFontRole(page: Page, target: Locator, role: FontRole): Promise<void> {
  const want = await tokenValue(page, FONT_TOKEN[role]);
  const got = await target.evaluate((el) => getComputedStyle(el).fontFamily);
  const first = (list: string) => (list.split(',')[0] ?? '').trim().replace(/^['"]|['"]$/g, '');
  expect(first(got), `font role "${role}" (DESIGN.md says ${want})`).toBe(first(want));
}

/**
 * expectNoStrayPills fails when anything other than an identity circle, a
 * count badge or a matrix cell-state pill is fully rounded. DESIGN.md reserves
 * the shape for exactly those three, and a reserved shape only stays reserved
 * if something checks.
 */
export async function expectNoStrayPills(page: Page): Promise<void> {
  const stray = await page.evaluate(() => {
    const allowed = ['avatar', 'count', 'cell-state'];
    const offenders: string[] = [];
    for (const el of document.querySelectorAll<HTMLElement>('body *')) {
      const box = el.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) {
        continue;
      }
      const radius = Number.parseFloat(getComputedStyle(el).borderTopLeftRadius);
      const round = radius >= Math.min(box.width, box.height) / 2 - 0.5 && radius > 8;
      if (round && !allowed.some((cls) => el.classList.contains(cls))) {
        offenders.push(`${el.tagName.toLowerCase()}.${el.className || '(no class)'}`);
      }
    }
    return offenders;
  });
  expect(stray, 'the 999px pill is reserved for identity circles, count badges and cell states').toEqual(
    [],
  );
}

// --- the whole set, over everything the flow can touch ---------------------

/**
 * interactiveElements is every focusable, visible control on the page.
 *
 * The S3 criterion says "every interactive element the flow touches". A
 * hand-written list satisfies the letter and drifts the moment someone adds a
 * button: the list is edited by the person who remembers, and nobody
 * remembers. Discovering the elements instead makes coverage STRUCTURAL — a
 * new control is asserted the day it renders, whether or not the flow author
 * thought about it — and it is a superset of "touched", so it can only be
 * stricter.
 */
export async function interactiveElements(page: Page): Promise<Locator[]> {
  // The native focusable set, not just the four obvious tags: `summary`,
  // editable regions and media controls are keyboard stops too, and a surface
  // that grows one should be asserted the day it renders.
  const selector = [
    'a[href]',
    'area[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    'summary',
    'iframe',
    'audio[controls]',
    'video[controls]',
    '[contenteditable]:not([contenteditable="false"])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(', ');
  // A MODAL DIALOG makes the rest of the document inert, and an inert element
  // is not an interactive one: focusing it is impossible by design, so
  // asserting a focus ring on it would fail for a reason that is the platform
  // working. When one is open, "every interactive element the page offers" is
  // exactly the set inside it.
  const modal = page.locator('dialog[open]');
  const scope = (await modal.count()) > 0 ? modal.first() : page;
  const all = scope.locator(selector);
  const out: Locator[] = [];
  for (let i = 0; i < (await all.count()); i++) {
    const one = all.nth(i);
    if (await one.isVisible()) {
      out.push(one);
    }
  }
  expect(out.length, 'a surface with no interactive elements is not a surface').toBeGreaterThan(0);
  return out;
}

/** PinnedSurface is what a flow declares about the surface it is standing on. */
export type PinnedSurface = {
  /** The registry flow this execution belongs to. */
  readonly flow: string;
  /** The registry surface being asserted — recorded, then checked at teardown. */
  readonly surface: string;
  /** Which theme this pass ran under, for the teardown report. */
  readonly theme: string;
  /** Text the human is expected to read. Contrast is asserted on each. */
  readonly text: readonly Locator[];
  /** Components whose radius role DESIGN.md fixes. */
  readonly radii: ReadonlyArray<readonly [Locator, RadiusRole]>;
  /** Components whose typeface role DESIGN.md fixes. */
  readonly fonts: ReadonlyArray<readonly [Locator, FontRole]>;
  /** Components whose palette token DESIGN.md fixes. */
  readonly colours: ReadonlyArray<readonly [Locator, ColourProp, string]>;
  /** Containers DESIGN.md says are drawn with a hairline. */
  readonly hairlines: readonly Locator[];
  /** Components measured against a density token (`--row`, `--touch`, `--rail`). */
  readonly density: ReadonlyArray<readonly [Locator, string]>;
};

/**
 * expectPinnedAssertionSet runs the mvp-boundary S3 set over a surface.
 *
 * One entry point, so a new flow cannot pick up half of it: axe, then focus,
 * touch and contrast over EVERY interactive element on the page, then the
 * DESIGN.md token conformance the flow declares.
 *
 * The execution is RECORDED before the assertions run, so a surface the flow
 * claimed and then failed on is still counted as executed — teardown is asking
 * "did anything check this?", and the answer is yes even when the answer to
 * "did it pass?" is no. A surface nobody ever reached records nothing and
 * teardown says so.
 */
export async function expectPinnedAssertionSet(page: Page, surface: PinnedSurface): Promise<void> {
  recordPinnedRun({ flow: surface.flow, surface: surface.surface, theme: surface.theme });

  await expectNoSeriousAxeViolations(page);

  const interactive = await interactiveElements(page);
  await expectEveryFocusIndicator(page, interactive);
  await expectTouchTargets(page, interactive);
  await expectEveryContrast([...interactive, ...surface.text]);

  for (const [target, role] of surface.radii) {
    await expectRadiusRole(page, target, role);
  }
  for (const [target, role] of surface.fonts) {
    await expectFontRole(page, target, role);
  }
  for (const [target, prop, token] of surface.colours) {
    await expectColourToken(page, target, prop, token);
  }
  for (const target of surface.hairlines) {
    await expectHairline(target);
  }
  for (const [target, token] of surface.density) {
    await expectDensity(page, target, token);
  }
  await expectNoStrayPills(page);
}
