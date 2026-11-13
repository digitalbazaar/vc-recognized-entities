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

// True when value is a string that parses as an absolute URL.
export function isUrl(value) {
  if(typeof value !== 'string') {
    return false;
  }
  try {
    new URL(value);
    return true;
  } catch(error) {
    return false;
  }
}

const EVALUATION_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// True when value is a full date and time in UTC, such as
// 2026-11-12T00:00:00Z. Fractional seconds are accepted.
export function isEvaluationDateTime(value) {
  return typeof value === 'string' && EVALUATION_TIME.test(value) &&
    isRealDate(value);
}

// Date.parse rolls impossible days over (2026-02-30), so compare the date
// part of the round trip.
export function isRealDate(value) {
  const time = Date.parse(value);
  return !Number.isNaN(time) &&
    new Date(time).toISOString().slice(0, 10) === value.slice(0, 10);
}
