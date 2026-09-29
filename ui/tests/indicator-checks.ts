const check = (value: unknown, label: string) => { if (!value) throw new Error(label); };
const near = (a: number, b: number) => Math.abs(a - b) < .6;

/** Check the rendered geometry, including host padding and theme resolution. */
export function checkIndicator(host: HTMLElement, content: Element, colorToken = '--accent') {
  const style = getComputedStyle(host), bar = getComputedStyle(host, '::before');
  const box = host.getBoundingClientRect(), child = content.getBoundingClientRect();
  const width = parseFloat(bar.width), height = parseFloat(bar.height), left = parseFloat(bar.insetInlineStart);
  check(style.borderLeftWidth === '0px', 'old edge border removed');
  check(near(width, 3) && near(height, Math.min(24, host.clientHeight - 16)), 'short indicator dimensions');
  check(near(left, 8) && near(parseFloat(bar.top), host.clientHeight / 2), 'indicator inset and centered');
  check(parseFloat(bar.borderRadius) >= width / 2 && bar.pointerEvents === 'none', 'rounded non-intercepting indicator');
  check(child.left - box.left - left - width >= 7.5, 'indicator leaves eight pixels before content');
  const probe = document.createElement('span');
  probe.style.cssText = `position:absolute;visibility:hidden;color:var(${colorToken})`;
  host.append(probe);
  check(bar.backgroundColor === getComputedStyle(probe).color, 'theme-aware indicator color');
  probe.remove();
  const before = child.left;
  host.style.setProperty('--indicator-color', 'rgb(37, 135, 201)');
  check(getComputedStyle(host, '::before').backgroundColor === 'rgb(37, 135, 201)', 'instance color override');
  check(near(content.getBoundingClientRect().left, before), 'color does not move content');
  host.style.removeProperty('--indicator-color');
  check(box.width > 0 && getComputedStyle(host, '::before').opacity === '1', 'active indicator visible');
}

export function checkIndicatorSizeOverride() {
  const sample = document.createElement('div');
  sample.className = 'inset-indicator'; sample.dataset.indicatorActive = 'true';
  sample.style.cssText = 'height:20px;width:80px;--indicator-width:4px;--indicator-height:32px;--indicator-inset:6px';
  document.body.append(sample);
  const bar = getComputedStyle(sample, '::before');
  check(bar.height === '4px' && bar.width === '4px' && bar.insetInlineStart === '6px', 'custom dimensions preserve top and bottom breathing room');
  sample.remove();
}

export function checkNoSelectionShift(before: number[], rows: HTMLElement[]) {
  rows.forEach((row, index) => check(near(row.firstElementChild!.getBoundingClientRect().left, before[index]), 'selection keeps content aligned'));
  check(rows.filter(row => getComputedStyle(row, '::before').opacity === '1').length === 1, 'exactly one selected indicator');
}
