import assert from 'node:assert/strict';

// Inspect rendered border boxes, not just declared padding. This also catches
// oversized children, intrinsic grid sizing and stale travelling-cap offsets.
export async function auditControlGeometry(page) {
  const report = await page.evaluate(() => {
    const inset = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--control-inset'));
    const tolerance = .15; // Allow accumulated CSS grid subpixel rounding.
    const records = [], failures = [];
    const visible = el => el.getBoundingClientRect().width > 0 && el.getBoundingClientRect().height > 0;
    const name = el => el.id || el.className;
    const gaps = (well, cap) => [cap.top - well.top, well.right - cap.right, well.bottom - cap.bottom, cap.left - well.left];
    const check = (label, values, expected = inset) => {
      records.push({ label, gaps: values });
      if (values.some(value => !Number.isFinite(value) || Math.abs(value - expected) > tolerance)) failures.push({ label, gaps: values, inset: expected });
    };
    {
      const wells = document.querySelectorAll('.title-search, .window-control-well, .title-switch, .language-switch, .nav, .filter-strip, .command-well, .card-actions, .agent-row-actions, #connection-modal .module-add-wrap');
      for (const well of wells) {
        if (!visible(well) || getComputedStyle(well).boxShadow === 'none') continue;
        const children = [...well.children].filter(el => visible(el) && getComputedStyle(el).position !== 'absolute');
        if (!children.length) continue;
        const outer = well.getBoundingClientRect(), boxes = children.map(el => el.getBoundingClientRect());
        const union = { top: Math.min(...boxes.map(r => r.top)), bottom: Math.max(...boxes.map(r => r.bottom)), left: Math.min(...boxes.map(r => r.left)), right: Math.max(...boxes.map(r => r.right)) };
        const expected = well.matches('.card-actions') ? 2 : inset;
        check(`${name(well)} outer clearance`, gaps(outer, union), expected);
        if (!well.matches('.card-actions')) {
          for (const child of children) {
            const r = child.getBoundingClientRect();
            check(`${name(well)} / ${name(child)} vertical clearance`, [r.top - outer.top, outer.bottom - r.bottom], expected);
          }
        }
      }
      const pseudoRect = (host, pseudo) => {
        const r = host.getBoundingClientRect(), s = getComputedStyle(host, pseudo), base = getComputedStyle(host);
        const matrix = new DOMMatrixReadOnly(s.transform === 'none' ? undefined : s.transform);
        return new DOMRect(r.left + parseFloat(base.borderLeftWidth) + parseFloat(s.left) + matrix.m41,
          r.top + parseFloat(base.borderTopWidth) + parseFloat(s.top) + matrix.m42, parseFloat(s.width), parseFloat(s.height));
      };
      for (const control of document.querySelectorAll('.title-switch, .language-switch, .nav, .filter-strip, .creation-options, .switch, .module-agent-toggle')) {
        if (!visible(control)) continue;
        const compact = control.matches('.switch, .module-agent-toggle');
        const count = compact || control.matches('.title-switch') ? 2 : control.querySelectorAll('button').length;
        const well = control.matches('.creation-options') ? control.parentElement : control;
        const capRect = () => control.matches('.switch') ? pseudoRect(control.querySelector('span'), '::after')
          : control.matches('.module-agent-toggle') ? control.querySelector('i').getBoundingClientRect() : pseudoRect(control, '::before');
        const verify = position => {
          const clearance = gaps(well.getBoundingClientRect(), capRect());
          check(`${name(control)} cap at ${position}`, [clearance[0], clearance[2], ...(position === 0 ? [clearance[3]] : []), ...(position === count - 1 ? [clearance[1]] : [])]);
          if (clearance.some(value => value < inset - tolerance)) failures.push({ label: `${name(control)} cap overlaps its rim`, gaps: clearance });
        };
        const current = control.matches('.switch') ? Number(control.querySelector('input').checked)
          : control.matches('.module-agent-toggle') ? Number(control.getAttribute('aria-pressed') === 'true')
          : control.matches('.title-switch') ? Number(control.getAttribute('aria-checked') === 'true')
          : control.matches('.filter-strip') ? parseFloat(getComputedStyle(control).getPropertyValue('--selected-type'))
          : control.matches('.creation-options') ? Number(well.dataset.mode === 'draft')
          : [...control.querySelectorAll('button')].findIndex(button => button.classList.contains('active'));
        const oldStyle = control.getAttribute('style'), oldClass = control.className;
        try {
          // Use the real drag state to remove interpolation without injecting
          // inline stylesheets (the renderer deliberately disallows them).
          control.classList.add('is-dragging');
          verify(current);
          control.classList.add('has-drag-preview');
          for (const position of [0, (count - 1) / 2, count - 1]) {
            control.style.setProperty('--drag-type', position);
            verify(position);
          }
        } finally {
          // Restore the real state while interpolation is still disabled, then
          // flush layout before reinstating transitions. Auditing must not leave
          // the UI travelling back from the synthetic endpoint in screenshots.
          control.className = oldClass;
          control.classList.add('is-dragging');
          if (oldStyle === null) control.removeAttribute('style'); else control.style.cssText = oldStyle;
          capRect();
          control.className = oldClass;
        }
      }
    }
    const physicalInset = inset * devicePixelRatio;
    if (Math.abs(physicalInset - Math.round(physicalInset)) > .001) failures.push({ label: 'The rim falls between device pixels', physicalInset });
    return { scale: devicePixelRatio, language: document.documentElement.lang, theme: document.documentElement.dataset.theme, records, failures };
  });
  assert.deepEqual(report.failures, [], `Uneven control clearances at ${report.scale}x: ${JSON.stringify(report.failures)}`);
  assert.ok(report.records.length > 0, 'The geometry audit must inspect visible controls');
  return report;
}
