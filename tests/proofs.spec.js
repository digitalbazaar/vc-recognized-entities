/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  CONTEXT, createIdentity, documentLoader, sign, verifierSuites
} from './proofs.js';
import {
  CRYPTOGRAPHIC_SECURITY_ERROR, discoverCredentialChain, validateRecognition
} from '../lib/index.js';
import {describe, it} from 'mocha';
import {expect} from 'chai';

const LIST_URL = 'https://anchor.example/lists/issuers.json';

// A signed chain: the anchor lists the issuer, and the issuer signs the target.
async function signedChain() {
  const anchor = await createIdentity();
  const issuer = await createIdentity();
  const list = await sign({
    '@context': CONTEXT,
    id: LIST_URL,
    type: ['VerifiableCredential', 'RecognizedEntityCredential'],
    issuer: anchor.did,
    validFrom: '2025-01-01T00:00:00Z',
    validUntil: '2030-01-01T00:00:00Z',
    credentialSubject: [{
      id: issuer.did,
      type: 'RecognizedEntity',
      recognizedTo: {
        type: 'RecognizedAction', action: 'issue', recognizedBy: anchor.did
      }
    }]
  }, anchor);
  const target = await sign({
    '@context': CONTEXT,
    type: ['VerifiableCredential', 'ExampleCredential'],
    issuer: {id: issuer.did, recognizedIn: {id: LIST_URL}},
    validFrom: '2025-06-01T00:00:00Z',
    credentialSubject: {id: 'urn:example:subject'}
  }, issuer);
  return {anchor, issuer, list, target};
}

const options = ({target, list, anchor, ...overrides}) => ({
  credential: target,
  recognizedIssuers: [anchor.did],
  maxDepth: 5,
  providedDocuments: [list],
  fetchCredential: async () => {
    throw new Error('should not fetch');
  },
  suite: verifierSuites(),
  documentLoader,
  ...overrides
});

describe('proof verification in discovery', () => {
  it('recognizes a chain whose credentials are signed', async () => {
    const {anchor, list, target} = await signedChain();
    const chain = await discoverCredentialChain(
      options({anchor, list, target}));
    expect(chain).to.have.lengthOf(2);
    const result = validateRecognition({
      chain, action: 'issue', recognizedIssuers: [anchor.did],
      evaluationDateTime: '2026-01-01T00:00:00Z', maxDepth: 5
    });
    expect(result).to.deep.equal({recognized: true, actionRecognized: true});
  });

  it('rejects a list whose signature does not verify', async () => {
    const {anchor, list, target} = await signedChain();
    const tampered = {
      ...list,
      credentialSubject: [{...list.credentialSubject[0], name: 'Mallory'}]
    };
    try {
      await discoverCredentialChain(options({
        anchor, list: tampered, target, providedDocuments: [tampered]
      }));
      throw new Error('expected a failure');
    } catch(error) {
      expect(error.type).to.equal(CRYPTOGRAPHIC_SECURITY_ERROR);
    }
  });

  it('requires suites and a document loader when verifying', async () => {
    const {anchor, list, target} = await signedChain();
    try {
      await discoverCredentialChain(options({
        anchor, list, target, suite: undefined
      }));
      throw new Error('expected a TypeError');
    } catch(error) {
      expect(error).to.be.instanceOf(TypeError);
    }
  });

  it('skips verification when verifyProofs is false', async () => {
    const {anchor, list, target} = await signedChain();
    const tampered = {
      ...list,
      credentialSubject: [{...list.credentialSubject[0], name: 'Mallory'}]
    };
    const chain = await discoverCredentialChain(options({
      anchor, list: tampered, target, providedDocuments: [tampered],
      verifyProofs: false, suite: undefined, documentLoader: undefined
    }));
    expect(chain).to.have.lengthOf(2);
  });
});
