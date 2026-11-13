/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {CRYPTOGRAPHIC_SECURITY_ERROR, ProblemDetailsError} from './errors.js';
import {issuerIdOf} from './common.js';
import {verifyCredential} from '@digitalbazaar/vc';

// Proof verification for the credentials discovery adds to a chain. The
// caller supplies the signature suites and a document loader, as the bitstring
// status list library does. Verification is on by default, and discovery can
// turn it off with `verifyProofs: false`.
//
// Instead of suites and a document loader, a caller can pass a verifyProof
// hook: verifyProof({credential, role}) returns {verified, error?}, as
// verifyCredential does. `role` is 'credential' for the credential under test
// and 'list' for a recognized entity credential that discovery adds.

// Throws TypeError when verification is on but its inputs are missing.
export function assertVerificationOptions(
  {verifyProofs, suite, documentLoader, verifyProof}) {
  if(!verifyProofs) {
    return;
  }
  if(verifyProof !== undefined) {
    if(typeof verifyProof !== 'function') {
      throw new TypeError('"verifyProof" must be a function.');
    }
    return;
  }
  if(!Array.isArray(suite) || suite.length === 0) {
    throw new TypeError('"suite" must be a non-empty array when verifying.');
  }
  if(typeof documentLoader !== 'function') {
    throw new TypeError('"documentLoader" must be a function when verifying.');
  }
}

// Throws ProblemDetailsError (CRYPTOGRAPHIC_SECURITY_ERROR) when the
// credential's proof does not verify.
export async function assertCredentialProof({
  credential, suite, documentLoader, verifyProof, role = 'list',
  message = 'A credential proof did not verify.'
}) {
  const result = verifyProof ?
    await verifyProof({credential, role}) :
    await verifyCredential({credential, suite, documentLoader});
  if(!result?.verified) {
    throw new ProblemDetailsError({
      type: CRYPTOGRAPHIC_SECURITY_ERROR,
      message,
      details: {issuerId: issuerIdOf(credential), cause: result?.error?.message}
    });
  }
}
