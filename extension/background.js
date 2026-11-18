import { checkLink, webHost } from './check.js';

const warningPage = chrome.runtime.getURL('warning.html');
const pendingChecks = new Map();
const allowKey = (host) => 'allowed:' + host;

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'check-link',
    title: /^ar\b/i.test(navigator.language)
      ? 'افحص هذا الرابط باستخدام درع الاحتيال'
      : 'Check this link with ScamShield',
    contexts: ['link'],
  });
});

chrome.contextMenus.onClicked.addListener(({ menuItemId, linkUrl }) => {
  if (menuItemId !== 'check-link' || !linkUrl) return;
  const page = new URL(chrome.runtime.getURL('popup.html'));
  page.searchParams.set('check', linkUrl);
  chrome.windows.create({ url: page.href, type: 'popup', width: 410, height: 630 })
    .catch(console.warn);
});

async function inspectNavigation({ tabId, frameId, url }, committed) {
  if (frameId !== 0 || tabId < 0) return;
  const token = {};
  pendingChecks.set(tabId, token);
  try {
    const result = webHost(url) ? checkLink(url) : null;
    if (result?.verdict === 'dangerous') {
      const key = allowKey(result.host);
      const allowed = (await chrome.storage.session.get(key))[key];
      if (pendingChecks.get(tabId) !== token) return;
      if (!allowed) {
        const page = new URL(warningPage);
        page.searchParams.set('u', url);
        await chrome.tabs.update(tabId, { url: page.href });
        return;
      }
    }
    if (!committed) return;
    const suspicious = result?.verdict === 'suspicious';
    if (suspicious) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#F5A524' });
      if (pendingChecks.get(tabId) !== token) return;
    }
    await chrome.action.setBadgeText({ tabId, text: suspicious ? '!' : '' });
  } catch (error) {
    console.warn('ScamShield navigation check failed', error.name);
  } finally {
    if (pendingChecks.get(tabId) === token) pendingChecks.delete(tabId);
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((event) => inspectNavigation(event, false));
chrome.webNavigation.onCommitted.addListener((event) => inspectNavigation(event, true));
chrome.tabs.onRemoved.addListener((tabId) => pendingChecks.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!['continue', 'leave'].includes(message?.action) || sender.tab?.id == null ||
      sender.frameId !== 0 || !sender.url?.startsWith(warningPage + '?')) return;
  (async () => {
    const destination = new URL(sender.url).searchParams.get('u');
    if (message.action === 'continue') {
      const host = webHost(destination);
      if (!host || checkLink(destination)?.verdict !== 'dangerous') return { ok: false };
      await chrome.storage.session.set({ [allowKey(host)]: true });
      await chrome.tabs.update(sender.tab.id, { url: destination });
    } else {
      await chrome.tabs.update(sender.tab.id, { url: 'about:blank' });
    }
    return { ok: true };
  })().then(sendResponse, () => sendResponse({ ok: false }));
  return true;
});
