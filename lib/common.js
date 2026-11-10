/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// Helpers shared by recognition validation and discovery.

export function issuerIdOf(credential) {
  const {issuer} = credential ?? {};
  return typeof issuer === 'string' ? issuer : issuer?.id;
}

export function typesOf(object) {
  return [].concat(object?.type ?? []);
}

export function isRecognizedEntityCredential(credential) {
  return typesOf(credential).includes('RecognizedEntityCredential');
}

// Entries of an array-or-single property, as an array.
export function listOf(value) {
  if(value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

// Recognized entities in a credential's credentialSubject.
export function recognizedEntitiesOf(credential) {
  return listOf(credential?.credentialSubject)
    .filter(subject => typesOf(subject).includes('RecognizedEntity'));
}

// Parses an XML Schema dateTime. Returns NaN when the value is not a date.
export function timeOf(value) {
  return typeof value === 'string' ? Date.parse(value) : NaN;
}
