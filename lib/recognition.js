/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  isRecognizedEntityCredential, issuerIdOf, listOf, recognizedEntitiesOf,
  timeOf
} from './common.js';

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
//   validateOutputValidation(credential, outputValidation): returns true when
//     the credential conforms to one data schema. Called once per schema.
//     Required when a recognized action declares an outputValidation.
//
// Returns {recognized, actionRecognized}.
export function validateRecognition({
  chain, action, recognizedIssuers, evaluationDateTime, maxDepth,
  validateOutputValidation
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
    // Output validation: the credential must conform to every schema.
    const schemas = listOf(recognizedTo.outputValidation);
    if(schemas.length > 0) {
      if(typeof validateOutputValidation !== 'function') {
        throw new TypeError(
          'validateOutputValidation is required when outputValidation is ' +
          'present.');
      }
      const conforms = schema =>
        validateOutputValidation(credential, schema);
      if(!schemas.every(conforms)) {
        continue;
      }
    }
    result.actionRecognized = true;
    break;
  }
  return result;
}
