/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  assertCredentialProof, assertVerificationOptions
} from './verify.js';
import {
  CRYPTOGRAPHIC_SECURITY_ERROR, LIMIT_EXCEEDED_ERROR, ProblemDetailsError,
  RETRIEVAL_ERROR
} from './errors.js';
import {
  isRecognizedEntityCredential, issuerIdOf, listOf, recognizedEntitiesOf
} from './common.js';

// Discovery (Sections 4.1 and 4.2). These find the recognized entity
// credentials that might establish recognition. They do not decide recognition;
// pass the result to validateRecognition.
//
// Shared inputs:
//   recognizedIssuers: identifiers of the anchors the verifier trusts.
//   maxDepth: the longest chain to follow.
//   fetchCredential(url): returns the credential at url, or throws. This is
//     where the retrieval policy applies.
//   providedDocuments: credentials the holder supplied, which are used before
//     any fetch.
//   now(): returns the current time in milliseconds. Defaults to Date.now.
//   verifyProof({credential, role}): optional; verifies a list's proof in
//     place of suite and documentLoader. See verify.js.

// Credential-based discovery (Section 4.1). Follows recognizedIn references
// until it reaches an issuer in recognizedIssuers or runs out of references.
// Returns the chain, starting with credential. The chain may still fail
// recognition validation.
export async function discoverCredentialChain({
  credential, recognizedIssuers, maxDepth, fetchCredential,
  providedDocuments = [], deadline = Infinity, now = Date.now,
  verifyProofs = true, suite, documentLoader, verifyProof
}) {
  assertVerificationOptions({verifyProofs, suite, documentLoader, verifyProof});
  const verify = verifyProofs ?
    credential => assertCredentialProof(
      {credential, suite, documentLoader, verifyProof}) :
    async () => {};
  const chain = [credential];
  let current = credential;
  for(;;) {
    if(chain.length > maxDepth) {
      throw new ProblemDetailsError({
        type: LIMIT_EXCEEDED_ERROR,
        message: 'Recognition chain exceeds maxDepth.',
        details: {limit: 'maxDepth', maxDepth}
      });
    }
    const issuer = current.issuer;
    const id = issuerIdOf(current);
    if(recognizedIssuers.includes(id)) {
      return chain;
    }
    const recognizedIn =
      typeof issuer === 'object' ? issuer.recognizedIn : null;
    if(!recognizedIn) {
      return chain;
    }
    const listId = recognizedIn.id;
    const provided = providedDocuments.find(doc => doc.id === listId);
    let list = provided;
    if(!list) {
      list = await fetchOrFail({listId, fetchCredential, deadline, now});
    }
    await verify(list);
    chain.push(list);
    current = list;
  }
}

// Identifier-based discovery (Section 4.2). Resolves the issuer's identifier,
// fetches a presentation from its WhoisService endpoint, and returns every
// candidate chain. Each chain starts with credential.
//
// Additional inputs:
//   resolveIdentifier(issuerId): returns the controlled identifier document.
//   verifyPresentation(presentation, issuerId): returns true when the proof
//     verifies and is bound to issuerId.
//   maxDuration: time budget in milliseconds for the whole operation.
//   fetchPresentation(url): returns the presentation at the service endpoint,
//     or throws. Defaults to fetchCredential. A caller passes it when the
//     endpoint retrieval and the recognizedIn retrievals use different
//     retrieval policies.
export async function discoverIdentifierChains({
  credential, recognizedIssuers, maxDepth, maxDuration,
  resolveIdentifier, verifyPresentation, fetchCredential,
  fetchPresentation = fetchCredential,
  providedDocuments = [], now = Date.now,
  verifyProofs = true, suite, documentLoader, verifyProof
}) {
  assertVerificationOptions({verifyProofs, suite, documentLoader, verifyProof});
  const started = now();
  const deadline = started + maxDuration;
  const chains = [];
  const issuerId = issuerIdOf(credential);

  let idDocument;
  try {
    idDocument = await resolveIdentifier(issuerId);
  } catch(error) {
    throw new ProblemDetailsError({
      type: RETRIEVAL_ERROR,
      message: `Identifier "${issuerId}" could not be resolved.`,
      details: {url: issuerId}
    });
  }
  const service = listOf(idDocument?.service).find(s => {
    const types = listOf(s.type);
    return types.includes('WhoisService') && types.includes('PathService');
  });
  if(!service) {
    return chains;
  }

  // Fetch failure is not an error in the current text: the chains are empty.
  let presentation;
  try {
    presentation = await fetchPresentation(service.serviceEndpoint);
  } catch(error) {
    return chains;
  }
  if(!await verifyPresentation(presentation, issuerId)) {
    throw new ProblemDetailsError({
      type: CRYPTOGRAPHIC_SECURITY_ERROR,
      message: 'The presentation proof does not verify for the issuer.',
      details: {issuerId}
    });
  }

  const candidates = listOf(presentation.verifiableCredential).filter(
    vc => isRecognizedEntityCredential(vc) &&
      recognizedEntitiesOf(vc).some(e => e.id === issuerId));
  for(const list of candidates) {
    // The presentation's proof does not cover the credentials inside it.
    if(verifyProofs) {
      await assertCredentialProof(
        {credential: list, suite, documentLoader, verifyProof});
    }
    if(recognizedIssuers.includes(issuerIdOf(list))) {
      chains.push([credential, list]);
    } else if(list.issuer?.recognizedIn) {
      const sub = await discoverCredentialChain({
        credential: list, recognizedIssuers, maxDepth, fetchCredential,
        providedDocuments, deadline, now, verifyProofs, suite, documentLoader,
        verifyProof
      });
      chains.push([credential, ...sub]);
    }
    if(now() > deadline) {
      throw new ProblemDetailsError({
        type: LIMIT_EXCEEDED_ERROR,
        message: 'Discovery exceeded maxDuration.',
        details: {limit: 'maxDuration', maxDuration}
      });
    }
  }
  return chains;
}

async function fetchOrFail({listId, fetchCredential, deadline, now}) {
  if(now() > deadline) {
    throw new ProblemDetailsError({
      type: LIMIT_EXCEEDED_ERROR,
      message: 'Discovery exceeded maxDuration.',
      details: {limit: 'maxDuration'}
    });
  }
  try {
    return await fetchCredential(listId);
  } catch(error) {
    throw new ProblemDetailsError({
      type: RETRIEVAL_ERROR,
      message:
        `Recognized entity credential "${listId}" could not be obtained.`,
      details: {url: listId}
    });
  }
}
