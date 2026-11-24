import assert from 'node:assert/strict';

export async function auditControlStates(page) {
  const states = await page.evaluate(() => {
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
    const context = canvas.getContext('2d');
    const rgb = color => {
      context.clearRect(0, 0, 1, 1); context.fillStyle = color; context.fillRect(0, 0, 1, 1);
      return [...context.getImageData(0, 0, 1, 1).data].slice(0, 3);
    };
    const luminance = color => rgb(color).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
    const contrast = (a, b) => { const [lo, hi] = [luminance(a), luminance(b)].sort((x, y) => x - y); return (hi + .05) / (lo + .05); };
    const active = rgb(getComputedStyle(document.querySelector('.nav-item.active')).color);
    return [...document.querySelectorAll('.switch, .module-agent-toggle')].filter(el => el.getBoundingClientRect().width).map(el => {
      const module = el.matches('.module-agent-toggle');
      const enabled = module ? el.getAttribute('aria-pressed') === 'true' : el.querySelector('input').checked;
      const disabled = module ? el.disabled : el.querySelector('input').disabled;
      const well = module ? el : el.querySelector('span');
      const label = getComputedStyle(well, module ? '::after' : '::before');
      const glyph = getComputedStyle(module ? el.querySelector('i') : well, module ? '::before' : '::after');
      const caption = module ? el.closest('.module-row').querySelector('[data-module-visibility]').textContent : null;
      const expectedCaption = document.documentElement.lang.startsWith('zh') ? `Agent ${enabled ? '可见' : '隐藏'}` : `AGENT ${enabled ? 'VISIBLE' : 'HIDDEN'}`;
      return { enabled, disabled, caption, expectedCaption, word: label.content.replaceAll('"', ''), glyph: glyph.content.replaceAll('"', ''),
        activeColor: JSON.stringify(rgb(label.color)) === JSON.stringify(active),
        neutralColor: JSON.stringify(rgb(label.color)) === JSON.stringify(rgb(label.getPropertyValue(disabled ? '--state-disabled-ink' : '--state-inactive-ink'))),
        glow: label.textShadow, contrast: contrast(label.color, getComputedStyle(well).backgroundColor),
        material: [getComputedStyle(well).backgroundColor, getComputedStyle(well).boxShadow] };
    });
  });
  assert.ok(states.length, 'Inspect at least one binary control');
  for (const state of states) {
    assert.equal(state.word, state.enabled ? 'ON' : 'OFF');
    assert.equal(state.glyph, state.enabled ? '✓' : '−');
    if (state.caption !== null) assert.equal(state.caption, state.expectedCaption);
    assert.equal(state.activeColor, state.enabled && !state.disabled, 'Only enabled controls use selected-state ink');
    if (state.disabled || !state.enabled) {
      assert.equal(state.neutralColor, true, 'OFF and unavailable controls use their respective neutral ink');
      assert.equal(state.glow, 'none', 'Inactive and disabled labels must not look enabled');
    }
    if (!state.disabled) assert.ok(state.contrast >= 4.5, `State text must remain readable: ${state.contrast.toFixed(2)}:1`);
  }
  return states;
}
