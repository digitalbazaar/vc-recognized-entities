/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// ProblemDetails types from Section 4.4 of VC Recognized Entities v1.0.
// CRYPTOGRAPHIC_SECURITY_ERROR is defined in the VC Data Model.
export const RETRIEVAL_ERROR =
  'https://www.w3.org/TR/vc-data-model#RETRIEVAL_ERROR';
export const LIMIT_EXCEEDED_ERROR =
  'https://www.w3.org/TR/vc-data-model#LIMIT_EXCEEDED_ERROR';
export const CRYPTOGRAPHIC_SECURITY_ERROR =
  'https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR';

// An error raised by a discovery algorithm. `type` is one of the URLs above.
export class ProblemDetailsError extends Error {
  constructor({type, message, details = {}}) {
    super(message);
    this.name = 'ProblemDetailsError';
    this.type = type;
    this.details = details;
  }
}
