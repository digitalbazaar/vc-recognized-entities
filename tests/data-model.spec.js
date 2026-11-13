/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  chainViolations, dataModelViolations, generalPropertyViolations,
  recognizedActionViolations, recognizedInViolations
} from '../lib/data-model.js';
import {describe, it} from 'mocha';
import {expect} from 'chai';

// A recognized entity credential that meets every section 3 rule.
function list() {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'RecognizedEntityCredential'],
    issuer: {
      id: 'did:example:anchor',
      type: 'RecognizedIssuer',
      recognizedIn: {id: 'https://anchor.example/list.json',
        type: 'RecognizedEntityCredential'}
    },
    validFrom: '2025-01-01T00:00:00Z',
    credentialSubject: [{
      id: 'did:example:issuer',
      type: 'RecognizedEntity',
      recognizedTo: {
        type: 'RecognizedAction',
        action: 'issue',
        validFrom: '2025-01-01T00:00:00Z',
        validUntil: '2030-01-01T00:00:00Z'
      }
    }]
  };
}

describe('data-model checks (section 3)', () => {
  it('accepts a list that meets every rule', () => {
    expect(dataModelViolations(list(), 'list')).to.deep.equal([]);
    expect(chainViolations({credential: {issuer: list().issuer},
      documents: [list()]})).to.deep.equal([]);
  });

  it('reports a list that is not a v2 credential or lacks its type', () => {
    const bad = list();
    bad['@context'] = ['https://example.org/other'];
    bad.type = ['VerifiableCredential'];
    expect(dataModelViolations(bad, 'list')).to.have.lengthOf(2);
  });

  it('reports a recognizedIn whose id is not a URL', () => {
    expect(recognizedInViolations(
      {recognizedIn: {id: 'not a url', type: 'RecognizedEntityCredential'}},
      'issuer')).to.have.lengthOf(1);
  });

  it('accepts an absent recognizedIn, which is allowed for an anchor', () => {
    expect(recognizedInViolations({id: 'did:example:anchor'}, 'issuer'))
      .to.deep.equal([]);
  });

  it('reports a recognized action with a fractional-second validFrom', () => {
    expect(recognizedActionViolations(
      {type: 'RecognizedAction', validFrom: '2025-01-01T00:00:00.5Z'},
      'action')).to.have.lengthOf(1);
  });

  it('reports a general property whose value is not a string', () => {
    expect(generalPropertyViolations({legalName: 42}, 'issuer'))
      .to.have.lengthOf(1);
  });

  it('names the place of each violation', () => {
    const [message] = recognizedActionViolations(
      {type: 'RecognizedEntity'}, 'credentialSubject[0].recognizedTo');
    expect(message).to.match(/^credentialSubject\[0\]\.recognizedTo: /);
  });
});
