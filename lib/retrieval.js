/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// The retrieval policy (Section 4): only https URLs, and no loopback,
// link-local, or private addresses, or localhost names. Only the host as
// written is checked: there is no DNS lookup here, so a name that points to a
// private address is not caught, and redirects are the fetcher's to check.

// True when the retrieval policy allows a request to `url`.
export function retrievalAllowed(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch(error) {
    return false;
  }
  if(parsed.protocol !== 'https:') {
    return false;
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if(host === 'localhost' || host.endsWith('.localhost')) {
    return false;
  }
  return !isPrivateAddress(host);
}

// True when host is a loopback, link-local, private, or shared IPv4 or IPv6
// address literal.
export function isPrivateAddress(host) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
  if(v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if(host.includes(':')) {
    return host === '::1' || host === '::' || /^f[cd]/.test(host) ||
      /^fe[89ab]/.test(host) || host.startsWith('::ffff:');
  }
  return false;
}

// The URL a did:web resolves to, so the policy can check its host. Other
// identifiers that are URLs are checked as they are.
export function resolutionUrl(id) {
  if(id.startsWith('did:web:')) {
    const [host, ...path] = id.slice('did:web:'.length).split(':');
    const where = path.length > 0 ? path.join('/') : '.well-known';
    return `https://${decodeURIComponent(host)}/${where}/did.json`;
  }
  return id;
}

// Wraps the retrieval hooks so the policy is applied before any of them runs.
// A did:key is resolved from the DID itself, so it is passed through without
// a check. A blocked request throws, as a failed retrieval does.
export function applyRetrievalPolicy({
  resolveIdentifier, fetchCredential, fetchPresentation,
  allowed = retrievalAllowed
}) {
  const guard = fetch => fetch && (async url => {
    if(!allowed(url)) {
      throw new Error(`The retrieval policy blocks ${url}.`);
    }
    return fetch(url);
  });
  return {
    resolveIdentifier: resolveIdentifier && (async id => {
      if(typeof id === 'string' && !id.startsWith('did:key:') &&
        !allowed(resolutionUrl(id))) {
        throw new Error(`The retrieval policy blocks resolving ${id}.`);
      }
      return resolveIdentifier(id);
    }),
    fetchCredential: guard(fetchCredential),
    fetchPresentation: guard(fetchPresentation)
  };
}
