/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  applyRetrievalPolicy, isPrivateAddress, resolutionUrl, retrievalAllowed
} from '../lib/retrieval.js';
import {describe, it} from 'mocha';
import {expect} from 'chai';

describe('retrieval policy', () => {
  it('allows an https URL to a public host', () => {
    expect(retrievalAllowed('https://anchor.example/list.json')).to.be.true;
  });

  it('refuses anything that is not https', () => {
    expect(retrievalAllowed('http://anchor.example/list.json')).to.be.false;
    expect(retrievalAllowed('file:///etc/passwd')).to.be.false;
    expect(retrievalAllowed('not a url')).to.be.false;
  });

  it('refuses localhost names and loopback addresses', () => {
    expect(retrievalAllowed('https://localhost/x')).to.be.false;
    expect(retrievalAllowed('https://app.localhost/x')).to.be.false;
    expect(retrievalAllowed('https://127.0.0.1/x')).to.be.false;
    expect(retrievalAllowed('https://[::1]/x')).to.be.false;
  });

  it('refuses private, link-local and shared IPv4 addresses', () => {
    for(const host of ['10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.1.1',
      '169.254.169.254', '100.64.0.1', '0.0.0.0']) {
      expect(isPrivateAddress(host), host).to.be.true;
    }
  });

  it('allows public IPv4 addresses next to the private ranges', () => {
    for(const host of ['8.8.8.8', '172.32.0.1', '172.15.0.1', '100.63.0.1']) {
      expect(isPrivateAddress(host), host).to.be.false;
    }
  });

  it('refuses IPv6 loopback, unspecified, unique-local and link-local', () => {
    for(const host of ['::1', '::', 'fc00::1', 'fd12::1', 'fe80::1']) {
      expect(isPrivateAddress(host), host).to.be.true;
    }
  });

  it('maps did:web to its https document, and leaves URLs as they are', () => {
    expect(resolutionUrl('did:web:anchor.example')).to.equal(
      'https://anchor.example/.well-known/did.json');
    expect(resolutionUrl('did:web:anchor.example:issuers:one')).to.equal(
      'https://anchor.example/issuers/one/did.json');
    expect(resolutionUrl('https://anchor.example/x.json')).to.equal(
      'https://anchor.example/x.json');
  });

  it('blocks a refused fetch before the fetcher runs', async () => {
    let called = false;
    const hooks = applyRetrievalPolicy({
      fetchCredential: async () => {
        called = true; return {};
      }
    });
    let error;
    try {
      await hooks.fetchCredential('https://127.0.0.1/list.json');
    } catch(e) {
      error = e;
    }
    expect(error?.message).to.match(/retrieval policy blocks/);
    expect(called).to.be.false;
  });

  it('passes an allowed fetch and resolves did:key unchecked', async () => {
    const hooks = applyRetrievalPolicy({
      fetchCredential: async url => ({url}),
      resolveIdentifier: async id => ({id})
    });
    expect(await hooks.fetchCredential('https://anchor.example/x.json'))
      .to.deep.equal({url: 'https://anchor.example/x.json'});
    expect(await hooks.resolveIdentifier('did:key:z6Mk')).to.deep.equal(
      {id: 'did:key:z6Mk'});
  });

  it('blocks resolution of a did:web on a private host', async () => {
    const hooks = applyRetrievalPolicy({
      resolveIdentifier: async id => ({id})
    });
    let error;
    try {
      await hooks.resolveIdentifier('did:web:192.168.0.1');
    } catch(e) {
      error = e;
    }
    expect(error?.message).to.match(/retrieval policy blocks resolving/);
  });
});
