/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// Signing and loading helpers for the proof tests. Keys are generated per run.
// Contexts come from local packages, so no remote context is fetched.

import * as credentialsContext from '@digitalbazaar/credentials-context';
import * as dataIntegrityContext from '@digitalbazaar/data-integrity-context';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  createSignCryptosuite, createVerifyCryptosuite
} from '@digitalbazaar/eddsa-jcs-2022-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import jsonldSignatures from 'jsonld-signatures';

const {purposes: {AssertionProofPurpose}} = jsonldSignatures;
const CREDENTIALS_V2 = 'https://www.w3.org/ns/credentials/v2';
const DATA_INTEGRITY = 'https://w3id.org/security/data-integrity/v2';
export const TEST_CONTEXT_URL =
  'https://anchor.example/contexts/recognized-entities-test/v1';
export const TEST_CONTEXT = {
  '@context': {'@vocab': 'https://anchor.example/vocab/'}
};
export const CONTEXT = [CREDENTIALS_V2, DATA_INTEGRITY, TEST_CONTEXT_URL];

const toEntries = c => c instanceof Map ? [...c] : Object.entries(c);
const LOCAL = new Map([
  ...toEntries(credentialsContext.contexts),
  ...toEntries(dataIntegrityContext.contexts),
  [TEST_CONTEXT_URL, TEST_CONTEXT]
]);
const verificationMethods = new Map();

export async function documentLoader(url) {
  const document = LOCAL.get(url) ?? verificationMethods.get(url);
  if(document === undefined) {
    throw new Error(`Document not available locally: ${url}`);
  }
  return {contextUrl: null, documentUrl: url, document};
}

// A fresh Ed25519 did:key identity. Its verification method is loadable by URL.
export async function createIdentity() {
  const key = await Ed25519Multikey.generate();
  const did = `did:key:${key.publicKeyMultibase}`;
  key.id = `${did}#${key.publicKeyMultibase}`;
  key.controller = did;
  const method = key.export({publicKey: true, includeContext: true});
  verificationMethods.set(key.id, method);
  // The DID document lists the key for assertions, as credential purposes need.
  verificationMethods.set(did, {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [method],
    assertionMethod: [key.id]
  });
  return {did, key};
}

// Signs a document with the identity's key, using eddsa-jcs-2022.
export async function sign(document, {key}) {
  const suite = new DataIntegrityProof({
    signer: key.signer(), cryptosuite: createSignCryptosuite()
  });
  const proof = await suite.createProof({
    document, purpose: new AssertionProofPurpose(), documentLoader
  });
  return {...document, proof};
}

// The suite list a caller passes to discovery when verifying.
export function verifierSuites() {
  return [new DataIntegrityProof({cryptosuite: createVerifyCryptosuite()})];
}
