(async () => {
  const { checkLink } = await import(chrome.runtime.getURL('check.js'));
  const arabic = /^ar\b/i.test(navigator.language);
  const cache = new WeakMap();
  const pending = new Set();
  const tooltip = document.createElement('div');
  tooltip.id = 'scamshield-guard-tooltip';
  tooltip.dir = arabic ? 'rtl' : 'ltr';
  tooltip.lang = arabic ? 'ar' : 'en';
  tooltip.hidden = true;
  document.body.append(tooltip);
  let timer;
  let hovered;

  function inspect(anchor) {
    const href = anchor.href;
    const previous = cache.get(anchor);
    if (previous?.href === href) return previous.result;
    const analyzed = checkLink(href);
    const result = analyzed?.verdict === 'dangerous' ? analyzed : null;
    cache.set(anchor, { href, result });
    anchor.classList.toggle('scamshield-guard-danger', Boolean(result));
    return result;
  }

  function show(anchor) {
    const result = anchor && inspect(anchor);
    tooltip.hidden = !result;
    if (!result) return;
    const heading = arabic ? 'درع الاحتيال: رابط خطير' : 'ScamShield: Dangerous link';
    tooltip.textContent = [heading, result.signals[0]?.[arabic ? 'ar' : 'en']].filter(Boolean).join(' · ');
    const bounds = anchor.getBoundingClientRect();
    const left = Math.max(8, Math.min(bounds.left, innerWidth - tooltip.offsetWidth - 8));
    const top = bounds.bottom + tooltip.offsetHeight + 12 < innerHeight
      ? bounds.bottom + 6 : Math.max(8, bounds.top - tooltip.offsetHeight - 6);
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
  }

  const linkFrom = (node) => node instanceof Element ? node.closest('a[href]') : null;
  document.addEventListener('pointerover', (event) => {
    const anchor = linkFrom(event.target);
    if (anchor && anchor !== linkFrom(event.relatedTarget)) {
      hovered = anchor;
      show(anchor);
    }
  });
  document.addEventListener('pointerout', (event) => {
    if (hovered && linkFrom(event.target) === hovered && linkFrom(event.relatedTarget) !== hovered) {
      hovered = null;
      show(null);
    }
  });
  document.addEventListener('focusin', (event) => show(linkFrom(event.target)));
  document.addEventListener('focusout', () => show(hovered));

  function scan() {
    for (const element of pending) {
      if (!element.isConnected) continue;
      if (element.matches('a')) inspect(element);
      for (const anchor of element.querySelectorAll('a[href]')) inspect(anchor);
    }
    pending.clear();
    if (hovered && !hovered.isConnected) {
      hovered = null;
      show(null);
    }
  }

  const observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === 'attributes') {
        pending.add(record.target);
        if (record.target === hovered) show(hovered);
      }
      for (const node of record.addedNodes) {
        if (node instanceof Element) pending.add(node);
      }
    }
    if (!pending.size && (!hovered || hovered.isConnected)) return;
    clearTimeout(timer);
    timer = setTimeout(scan, 100);
  });
  pending.add(document.body);
  scan();
  observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['href'] });
})().catch(() => {});
