import { analyzeUrl } from './engine/scamshield.js';

export function webHost(value) {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:' || url.protocol === 'http:') {
      return url.hostname.replace(/\.$/, '');
    }
  } catch {
    // Browser pages and unparseable destinations have no web host.
  }
  return null;
}

export function checkLink(value) {
  if (!webHost(value) && !/^(javascript|vbscript|data):/i.test(value ?? '')) return null;
  try {
    return analyzeUrl(value);
  } catch (error) {
    if (!(error instanceof URIError)) return null;
    // Keep the host and retry with the literal path and query for scoring.
    const url = new URL(value);
    url.pathname = url.pathname.replaceAll('%', '%25');
    url.search = url.search.replaceAll('%', '%25');
    return analyzeUrl(url.href);
  }
}
