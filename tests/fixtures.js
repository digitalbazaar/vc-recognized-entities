/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// Small in-memory credentials for the algorithm tests. Proofs are omitted:
// these algorithms assume each credential was verified individually.

export const ANCHOR = 'did:example:anchor';
export const ISSUER = 'did:example:issuer';
export const OTHER = 'did:example:other';
export const LIST_URL = 'https://anchor.example/lists/issuers.json';

export function listCredential({
  id = LIST_URL, issuer = ANCHOR, entity = ISSUER, recognizedTo,
  validFrom = '2025-01-01T00:00:00Z', validUntil = '2030-01-01T00:00:00Z'
} = {}) {
  const subject = {id: entity, type: 'RecognizedEntity'};
  if(recognizedTo !== undefined) {
    subject.recognizedTo = recognizedTo;
  }
  return {
    id,
    type: ['VerifiableCredential', 'RecognizedEntityCredential'],
    issuer,
    validFrom,
    validUntil,
    credentialSubject: [subject]
  };
}

export function targetCredential({
  issuer = ISSUER, recognizedIn, validFrom = '2025-06-01T00:00:00Z'
} = {}) {
  const issuerObject = recognizedIn ? {id: issuer, recognizedIn} : issuer;
  return {
    type: ['VerifiableCredential', 'ExampleCredential'],
    issuer: issuerObject,
    validFrom,
    credentialSubject: {id: 'urn:example:subject'}
  };
}

export const ISSUE_ACTION = {type: 'RecognizedAction', action: 'issue'};
