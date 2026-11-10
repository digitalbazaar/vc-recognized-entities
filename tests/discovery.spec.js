/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  ANCHOR, ISSUE_ACTION, ISSUER, LIST_URL, listCredential, OTHER,
  targetCredential
} from './fixtures.js';
import {
  CRYPTOGRAPHIC_SECURITY_ERROR, discoverCredentialChain,
  discoverIdentifierChains,
  LIMIT_EXCEEDED_ERROR, RETRIEVAL_ERROR
} from '../lib/index.js';
import {describe, it} from 'mocha';
import {expect} from 'chai';

const noFetch = async () => {
  throw new Error('fetch should not be called');
};
const fetchFrom = docs => async url => {
  if(!(url in docs)) {
    throw new Error(`not found: ${url}`);
  }
  return docs[url];
};
const expectError = async (promise, type) => {
  try {
    await promise;
  } catch(error) {
    expect(error.type).to.equal(type);
    return;
  }
  throw new Error(`expected ${type}`);
};

describe('discoverCredentialChain (Section 4.1)', () => {
  it('returns the chain from provided documents without fetching', async () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    const chain = await discoverCredentialChain({
      credential: targetCredential({recognizedIn: {id: LIST_URL}}),
      recognizedIssuers: [ANCHOR], maxDepth: 5,
      fetchCredential: noFetch, providedDocuments: [list]
    });
    expect(chain).to.have.lengthOf(2);
    expect(chain[1]).to.equal(list);
  });

  it('fetches the list when it is not provided', async () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    const chain = await discoverCredentialChain({
      credential: targetCredential({recognizedIn: {id: LIST_URL}}),
      recognizedIssuers: [ANCHOR], maxDepth: 5,
      fetchCredential: fetchFrom({[LIST_URL]: list})
    });
    expect(chain[1]).to.equal(list);
  });

  it('returns one credential for a directly recognized issuer', async () => {
    const credential = targetCredential();
    const chain = await discoverCredentialChain({
      credential: {...credential, issuer: ANCHOR},
      recognizedIssuers: [ANCHOR], maxDepth: 5, fetchCredential: noFetch
    });
    expect(chain).to.have.lengthOf(1);
  });

  it('raises LIMIT_EXCEEDED_ERROR past maxDepth', async () => {
    const list = listCredential({
      id: LIST_URL, issuer: OTHER,
      recognizedTo: ISSUE_ACTION
    });
    const next = listCredential({
      id: 'https://other.example/list.json', issuer: 'did:example:up',
      entity: OTHER
    });
    next.credentialSubject[0].recognizedTo = ISSUE_ACTION;
    list.issuer = {id: OTHER, recognizedIn: {id: next.id}};
    await expectError(discoverCredentialChain({
      credential: targetCredential({recognizedIn: {id: LIST_URL}}),
      recognizedIssuers: [ANCHOR], maxDepth: 2,
      fetchCredential: fetchFrom({[LIST_URL]: list, [next.id]: next})
    }), LIMIT_EXCEEDED_ERROR);
  });

  it('raises RETRIEVAL_ERROR when the list cannot be fetched', async () => {
    await expectError(discoverCredentialChain({
      credential: targetCredential({recognizedIn: {id: LIST_URL}}),
      recognizedIssuers: [ANCHOR], maxDepth: 5,
      fetchCredential: fetchFrom({})
    }), RETRIEVAL_ERROR);
  });
});

describe('discoverIdentifierChains (Section 4.2)', () => {
  const credential = targetCredential();
  const idDocument = {
    id: ISSUER,
    service: [{
      id: '#whois', type: ['WhoisService', 'PathService'],
      serviceEndpoint: 'https://issuer.example/whois.vp'
    }]
  };
  const presentation = list => ({
    type: 'VerifiablePresentation',
    verifiableCredential: [list]
  });
  const options = (overrides = {}) => ({
    credential, recognizedIssuers: [ANCHOR], maxDepth: 5, maxDuration: 60000,
    resolveIdentifier: async () => idDocument,
    verifyPresentation: async () => true,
    fetchCredential: async () => presentation(
      listCredential({recognizedTo: ISSUE_ACTION})),
    ...overrides
  });

  it('returns a candidate chain from the WhoisService presentation',
    async () => {
      const chains = await discoverIdentifierChains(options());
      expect(chains).to.have.lengthOf(1);
      expect(chains[0]).to.have.lengthOf(2);
      expect(chains[0][0]).to.equal(credential);
    });

  it('returns no chains when the issuer has no WhoisService', async () => {
    const chains = await discoverIdentifierChains(options({
      resolveIdentifier: async () => ({id: ISSUER})
    }));
    expect(chains).to.deep.equal([]);
  });

  it('returns no chains when the presentation cannot be fetched', async () => {
    const chains = await discoverIdentifierChains(options({
      fetchCredential: async () => {
        throw new Error('unreachable');
      }
    }));
    expect(chains).to.deep.equal([]);
  });

  it('raises CRYPTOGRAPHIC_SECURITY_ERROR when the proof fails', async () => {
    await expectError(discoverIdentifierChains(options({
      verifyPresentation: async () => false
    })), CRYPTOGRAPHIC_SECURITY_ERROR);
  });

  it('raises RETRIEVAL_ERROR when the identifier does not resolve',
    async () => {
      await expectError(discoverIdentifierChains(options({
        resolveIdentifier: async () => {
          throw new Error('no such DID');
        }
      })), RETRIEVAL_ERROR);
    });

  it('raises LIMIT_EXCEEDED_ERROR past maxDuration', async () => {
    let t = 0;
    await expectError(discoverIdentifierChains(options({
      maxDuration: 100,
      now: () => (t += 1000)
    })), LIMIT_EXCEEDED_ERROR);
  });
});
