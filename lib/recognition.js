/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  CREDENTIAL_VALIDATION_ERROR, LIMIT_EXCEEDED_ERROR, ProblemDetailsError
} from './errors.js';
import {
  discoverCredentialChain, discoverIdentifierChains
} from './discovery.js';
import {
  isRecognizedEntityCredential, issuerIdOf, listOf, recognizedEntitiesOf,
  timeOf, typesOf
} from './common.js';
import {applyRetrievalPolicy} from './retrieval.js';
import {assertCredentialProof} from './verify.js';
import {chainViolations} from './data-model.js';
import {runValidatorInSandbox} from './sandbox.js';
import {validateCredential} from './validators.js';

// Recognition validation (Section 4.3). Given a chain of credentials, decides
// whether the first credential's issuer is recognized by an anchor, and
// whether it is recognized to perform `action`. Every failure is a result,
// not an error, as in the spec.
//
// Inputs:
//   chain: credentials, starting with the one under test.
//   action: the action to check, such as 'issue'.
//   recognizedIssuers: identifiers of the anchors the verifier trusts.
//   evaluationDateTime: ISO 8601 UTC string.
//   maxDepth: the longest chain the verifier accepts.
//
// Returns {recognized, actionRecognized}.
export function validateRecognition({
  chain, action, recognizedIssuers, evaluationDateTime, maxDepth
}) {
  const result = {recognized: false, actionRecognized: false};
  if(chain.length < 2) {
    return result;
  }
  if(chain.length > maxDepth) {
    return result;
  }

  // No issuer may appear twice.
  const seen = new Set();
  for(const credential of chain) {
    const id = issuerIdOf(credential);
    if(seen.has(id)) {
      return result;
    }
    seen.add(id);
  }

  // The window is the period in which every credential was valid.
  const evaluated = timeOf(evaluationDateTime);
  const starts = chain.map(c => timeOf(c.validFrom)).filter(t => !isNaN(t));
  const ends = chain.map(c => timeOf(c.validUntil)).filter(t => !isNaN(t));
  const start = starts.length ? Math.max(...starts) : -Infinity;
  const end = ends.length ? Math.min(...ends) : Infinity;
  if(end < start) {
    return result;
  }
  if(!(evaluated >= start && evaluated <= end)) {
    return result;
  }

  // Each later credential must be a recognized entity credential that lists
  // the issuer of the credential before it.
  for(let i = 0; i < chain.length - 1; i++) {
    const subject = chain[i];
    const list = chain[i + 1];
    if(!isRecognizedEntityCredential(list)) {
      return result;
    }
    const subjectId = issuerIdOf(subject);
    const listed = recognizedEntitiesOf(list).some(e => e.id === subjectId);
    if(!listed) {
      return result;
    }
  }

  // The final issuer must be a configured anchor.
  const last = chain[chain.length - 1];
  if(!recognizedIssuers.includes(issuerIdOf(last))) {
    return result;
  }
  result.recognized = true;

  // Action recognition: the list that recognizes the first issuer.
  const credential = chain[0];
  const list = chain[1];
  const entity = recognizedEntitiesOf(list)
    .find(e => e.id === issuerIdOf(credential));
  for(const recognizedTo of listOf(entity?.recognizedTo)) {
    if(recognizedTo.action !== action) {
      continue;
    }
    // Validity: a missing property falls back to the enclosing credential's.
    const actionStart = timeOf(recognizedTo.validFrom);
    const actionEnd = timeOf(recognizedTo.validUntil);
    const from = isNaN(actionStart) ? timeOf(list.validFrom) : actionStart;
    const until = isNaN(actionEnd) ? timeOf(list.validUntil) : actionEnd;
    const inPeriod = (isNaN(from) || evaluated >= from) &&
      (isNaN(until) || evaluated <= until);
    if(!inPeriod) {
      continue;
    }
    result.actionRecognized = true;
    break;
  }
  return result;
}

// The whole recognition chain for one credential: the data model checks of
// section 3 on the supplied documents (1.1), the proof of the credential under
// test, discovery (4.1 or 4.2), and recognition validation with credential
// validation (4.3, 4.4, 4.4.1) on each candidate chain.
//
// Inputs:
//   credential: the credential under test.
//   documents: recognized entity credentials the holder supplied. Discovery
//     uses them before any fetch.
//   action, evaluationDateTime, recognizedIssuers, maxDepth: as for
//     validateRecognition.
//   maxDuration: time budget in milliseconds. It bounds identifier-based
//     discovery (4.2), and each recognition validation (4.3) separately.
//   hooks:
//     verifyProof({credential, role}): required. Returns {verified, error?}.
//       role is 'credential' for the credential under test, 'list' for a
//       recognized entity credential that discovery adds.
//     fetchCredential(url): returns the credential at url, or throws.
//       Defaults to a fetcher that always fails.
//     resolveIdentifier(id): returns the controlled identifier document.
//     fetchPresentation(url): returns the presentation at a WhoisService
//       endpoint. Defaults to fetchCredential.
//     verifyPresentation(presentation, issuerId): returns true when the proof
//       verifies and is bound to issuerId.
//     runValidator({source, input, timeoutMs, environment}): runs a
//       JavaScript validator; returns {ok, result, error, errorType,
//       limitExceeded}. Defaults to runValidatorInSandbox.
//     now(): the current time in milliseconds. Defaults to Date.now.
//     retrievalAllowed(url): the retrieval policy. Defaults to the one in
//       retrieval.js. It is applied before fetchCredential, resolveIdentifier
//       and fetchPresentation run.
//   nonConformingDocumentType: the ProblemDetails type for a supplied document
//     that breaks the data model. The spec defines none, so it defaults to
//     CREDENTIAL_VALIDATION_ERROR.
//
// Returns {recognized, actionRecognized, errors, warnings}. Throws a
// ProblemDetailsError (RETRIEVAL_ERROR, LIMIT_EXCEEDED_ERROR,
// CRYPTOGRAPHIC_SECURITY_ERROR) when discovery or validation raises one, and a
// TypeError when there is no credential.
export async function recognize({
  credential, documents = [], action, evaluationDateTime, recognizedIssuers,
  maxDepth, maxDuration, hooks = {},
  nonConformingDocumentType = CREDENTIAL_VALIDATION_ERROR
}) {
  if(!credential || typeof credential !== 'object') {
    throw new TypeError('The presentation has no credential to verify.');
  }
  const {
    verifyProof, verifyPresentation, runValidator = runValidatorInSandbox,
    now = Date.now, retrievalAllowed,
    fetchCredential = async url => {
      throw new Error(`Retrieval is disabled: ${url}`);
    }
  } = hooks;
  if(typeof verifyProof !== 'function') {
    throw new TypeError('"hooks.verifyProof" must be a function.');
  }
  const retrieval = applyRetrievalPolicy({
    resolveIdentifier: hooks.resolveIdentifier,
    fetchCredential,
    fetchPresentation: hooks.fetchPresentation ?? fetchCredential,
    allowed: retrievalAllowed
  });

  // 1.1: a conforming processor produces errors when it consumes a
  // non-conforming document. The supplied credentials are recognized entity
  // credentials, so each must follow the data model of section 3.
  const violations = chainViolations({credential, documents});
  if(violations.length > 0) {
    return {
      recognized: false, actionRecognized: false, warnings: [],
      errors: violations.map(detail => ({
        type: nonConformingDocumentType,
        title: 'Non-conforming document', detail
      }))
    };
  }
  // Section 4 assumes every proof in the chain has been verified. Discovery
  // verifies the lists it adds; this verifies the credential under test.
  await assertCredentialProof({
    credential, verifyProof, role: 'credential',
    message: 'The proof of the credential under test did not verify.'
  });

  const issuer = credential.issuer;
  let chains;
  if((issuer !== null && typeof issuer === 'object' && issuer.recognizedIn) ||
    recognizedIssuers.includes(issuerIdOf(credential))) {
    chains = [await discoverCredentialChain({
      credential, recognizedIssuers, maxDepth,
      fetchCredential: retrieval.fetchCredential,
      providedDocuments: documents, now, verifyProof
    })];
  } else {
    // 4.2: no recognizedIn, so start from the issuer's identifier.
    chains = await discoverIdentifierChains({
      credential, recognizedIssuers, maxDepth, maxDuration,
      resolveIdentifier: retrieval.resolveIdentifier ?? (async () => {
        throw new Error('No identifier resolver is configured.');
      }),
      verifyPresentation, fetchCredential: retrieval.fetchCredential,
      fetchPresentation: retrieval.fetchPresentation,
      providedDocuments: documents, now, verifyProof
    });
  }

  // 4.3: run validation on each candidate chain and choose among the results.
  const results = [];
  let raised;
  for(const chain of chains) {
    try {
      const result = await validateChain({
        chain, action, evaluationDateTime, recognizedIssuers, maxDepth,
        runValidator, now, maxDuration, nonConformingDocumentType
      });
      if(result.recognized && result.actionRecognized) {
        return result;
      }
      results.push(result);
    } catch(error) {
      raised = raised ?? error;
    }
  }
  if(raised) {
    throw raised;
  }
  return results.find(result => result.recognized) ?? results[0] ?? {
    recognized: false, actionRecognized: false, errors: [], warnings: []
  };
}

// Recognition validation (4.3) of one candidate chain, with credential
// validation. Returns the result, or throws when a validator exceeded a limit.
async function validateChain({
  chain, action, evaluationDateTime, recognizedIssuers, maxDepth,
  runValidator, now, maxDuration, nonConformingDocumentType
}) {
  // Section 1.1 applies to every credential in the chain. Discovery adds
  // lists the holder did not supply, so the chain is checked here, not only
  // the supplied documents.
  const violations = chainViolations({
    credential: chain[0], documents: chain.slice(1)
  });
  if(violations.length > 0) {
    return {
      recognized: false, actionRecognized: false, warnings: [],
      errors: violations.map(detail => ({
        type: nonConformingDocumentType,
        title: 'Non-conforming document', detail
      }))
    };
  }
  // 4.3 budget: maxDuration, measured from when this algorithm starts.
  const started = now();
  const budgetLeft = () => maxDuration === undefined ?
    Infinity : maxDuration - (now() - started);
  const exceeded = () => new ProblemDetailsError({
    type: LIMIT_EXCEEDED_ERROR,
    message: 'Recognition validation exceeded maxDuration.',
    details: {limit: 'maxDuration', maxDuration}
  });

  // validateRecognition runs the steps of 4.3 up to and including the anchor
  // check. The action steps, which run credential validators, are below.
  const {recognized} = validateRecognition({
    chain, action, recognizedIssuers, evaluationDateTime, maxDepth
  });
  const result = {
    recognized, actionRecognized: false, errors: [], warnings: []
  };
  if(!recognized) {
    return result;
  }
  const evaluated = Date.parse(evaluationDateTime);
  const validate = async (subject, validators, rest) => {
    const remaining = budgetLeft();
    if(remaining <= 0) {
      throw exceeded();
    }
    // Each validator gets the time left in the budget, so a validator that
    // runs on cannot outlast it. undefined keeps the validator's default.
    const validation = await validateCredential({
      credential: subject,
      validators,
      options: {chain: rest, action, evaluationDateTime},
      runValidator,
      timeoutMs: Number.isFinite(remaining) ? remaining : undefined
    });
    result.errors.push(...validation.errors);
    result.warnings.push(...validation.warnings);
    if(validation.errors.some(e => e?.type === LIMIT_EXCEEDED_ERROR)) {
      throw new ProblemDetailsError({
        type: LIMIT_EXCEEDED_ERROR,
        message: 'A credential validator exceeded a limit.',
        details: {errors: validation.errors}
      });
    }
    if(budgetLeft() < 0) {
      throw exceeded();
    }
    return validation.valid;
  };

  // 4.3: check each intermediate recognized entity credential, from the one
  // next to the anchor down to the second credential. Every recognized action
  // of its entity that is valid at the evaluation time must pass, whatever
  // its action value.
  for(let i = chain.length - 2; i >= 1; i--) {
    const intermediate = chain[i];
    const list = chain[i + 1];
    const entity = entityFor({list, credential: intermediate});
    if(entity?.recognizedTo === undefined) {
      continue;
    }
    const actions = actionsInPeriod({entity, list, evaluated});
    if(actions.length === 0) {
      return result;
    }
    for(const recognizedAction of actions) {
      const validators = listOf(recognizedAction.credentialValidator);
      if(validators.length > 0 &&
        !await validate(intermediate, validators, chain.slice(i + 1))) {
        return result;
      }
    }
  }

  // 4.3: the first credential. Any recognized action that names the action,
  // is valid at the evaluation time, and declares no credential validator or
  // has every validator accept the credential, recognizes the action.
  const entity = entityFor({list: chain[1], credential: chain[0]});
  for(const recognizedAction of actionsInPeriod(
    {entity, list: chain[1], evaluated})) {
    if(recognizedAction.action !== action) {
      continue;
    }
    const validators = listOf(recognizedAction.credentialValidator);
    if(validators.length === 0 ||
      await validate(chain[0], validators, chain.slice(1))) {
      result.actionRecognized = true;
      break;
    }
  }
  return result;
}

// The recognized entity in `list` whose id is the issuer of `credential`.
export function entityFor({list, credential}) {
  return listOf(list?.credentialSubject).find(subject =>
    typesOf(subject).includes('RecognizedEntity') &&
    subject.id === issuerIdOf(credential));
}

// The entity's recognized actions whose validity period includes the
// evaluation time (milliseconds). A missing endpoint falls back to the
// enclosing credential's. Endpoints are inclusive.
export function actionsInPeriod({entity, list, evaluated}) {
  return listOf(entity?.recognizedTo).filter(recognizedAction => {
    const from = Date.parse(recognizedAction?.validFrom ?? list.validFrom);
    const until = Date.parse(recognizedAction?.validUntil ?? list.validUntil);
    return (Number.isNaN(from) || evaluated >= from) &&
      (Number.isNaN(until) || evaluated <= until);
  });
}
