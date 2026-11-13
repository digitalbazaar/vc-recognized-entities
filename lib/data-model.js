/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {issuerIdOf, isUrl, listOf, typesOf} from './common.js';

// Data model checks (Section 3) for recognized entity credentials that a
// holder supplies. Section 1.1: a conforming processor produces errors when it
// consumes a non-conforming document. Each function returns a list of
// violations, as strings that start with `where`; an empty list means the
// document conforms.

const DATE_TIME_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// Violations for a credential under test and the recognized entity
// credentials supplied with it. Only the recognizedIn object of the
// credential's issuer is checked; each document is checked as a recognized
// entity credential. `path(i)` names position i, where 0 is the credential and
// 1 onward are the documents; it defaults to the position in a presentation's
// verifiableCredential array.
export function chainViolations({
  credential, documents = [], path = i => `verifiableCredential[${i}]`
}) {
  return [
    ...recognizedInViolations(credential?.issuer, path(0)),
    ...documents.flatMap((doc, i) => dataModelViolations(doc, path(i + 1)))
  ];
}

// Section 3 rules for one recognized entity credential.
export function dataModelViolations(vc, where) {
  const violations = [];
  const add = message => violations.push(`${where}: ${message}`);
  if(!Array.isArray(vc?.['@context']) ||
    vc['@context'][0] !== 'https://www.w3.org/ns/credentials/v2') {
    add('@context must start with the VC Data Model v2.0 context');
  }
  if(!typesOf(vc).includes('VerifiableCredential') ||
    !typesOf(vc).includes('RecognizedEntityCredential')) {
    add('type must include VerifiableCredential and ' +
      'RecognizedEntityCredential');
  }
  if(typeof issuerIdOf(vc) !== 'string' || issuerIdOf(vc) === '') {
    add('issuer is required');
  }
  const {issuer} = vc ?? {};
  if(issuer !== null && typeof issuer === 'object') {
    if(!typesOf(issuer).includes('RecognizedIssuer')) {
      add('issuer type must be RecognizedIssuer');
    }
    violations.push(...generalPropertyViolations(issuer, `${where}.issuer`));
    violations.push(...recognizedInViolations(issuer, `${where}.issuer`));
  }
  const entities = listOf(vc?.credentialSubject);
  if(entities.length === 0) {
    add('credentialSubject is required');
  }
  entities.forEach((entity, i) => {
    const at = `${where}.credentialSubject[${i}]`;
    if(!typesOf(entity).includes('RecognizedEntity')) {
      violations.push(`${at}: type must be RecognizedEntity`);
    }
    violations.push(...generalPropertyViolations(entity, at));
    violations.push(...recognizedInViolations(entity, at));
    listOf(entity?.recognizedTo).forEach((recognizedAction, j) => {
      violations.push(...recognizedActionViolations(
        recognizedAction, `${at}.recognizedTo[${j}]`));
    });
  });
  return violations;
}

// 3.1: legalName, image, url, and sameAs, when present.
export function generalPropertyViolations(object, where) {
  const violations = [];
  const add = message => violations.push(`${where}: ${message}`);
  if(object?.legalName !== undefined && !listOf(object.legalName).every(v =>
    (typeof v === 'string' && v !== '') ||
    (v !== null && typeof v === 'object' && typeof v['@value'] === 'string'))) {
    add('legalName must be strings or language value objects');
  }
  for(const name of ['image', 'url']) {
    if(object?.[name] !== undefined && !isUrl(object[name])) {
      add(`${name} must be a URL`);
    }
  }
  if(object?.sameAs !== undefined && !listOf(object.sameAs).every(isUrl)) {
    add('sameAs values must be URLs');
  }
  return violations;
}

// 3.2: a recognizedIn object's id is a URL, and its type is a type value.
export function recognizedInViolations(object, where) {
  const recognizedIn = object?.recognizedIn;
  if(recognizedIn === undefined || typeof object !== 'object') {
    return [];
  }
  const violations = [];
  if(!isUrl(recognizedIn?.id)) {
    violations.push(`${where}.recognizedIn: id must be a URL`);
  }
  const types = typesOf(recognizedIn);
  if(types.length === 0 ||
    !types.every(type => typeof type === 'string' && type !== '')) {
    violations.push(`${where}.recognizedIn: type must be a type value`);
  }
  return violations;
}

// 3.3 and 3.5: a recognized action and its credential validators.
export function recognizedActionViolations(recognizedAction, where) {
  const violations = [];
  const add = message => violations.push(`${where}: ${message}`);
  if(!typesOf(recognizedAction).includes('RecognizedAction')) {
    add('type must be RecognizedAction');
  }
  for(const name of ['validFrom', 'validUntil']) {
    const value = recognizedAction?.[name];
    if(value !== undefined && !(DATE_TIME_UTC.test(value) &&
      !Number.isNaN(Date.parse(value)))) {
      add(`${name} must be a UTC dateTime with no sub-second precision`);
    }
  }
  if(recognizedAction?.credentialValidator !== undefined) {
    const validators = listOf(recognizedAction.credentialValidator);
    if(validators.length === 0) {
      add('credentialValidator must be one or more credential validators');
    }
    validators.forEach((validator, i) => {
      const at = `credentialValidator[${i}]`;
      if(validator?.id === undefined || !isUrl(validator.id)) {
        add(`${at}: id is required and must be a URL`);
      }
      if(!typesOf(validator).includes('CredentialValidator')) {
        add(`${at}: type must be CredentialValidator`);
      }
      if(typeof validator?.mediaType !== 'string' ||
        validator.mediaType === '') {
        add(`${at}: mediaType is required`);
      }
    });
  }
  return violations;
}
