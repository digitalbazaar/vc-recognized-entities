/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

import {
  CREDENTIAL_VALIDATION_ERROR, CRYPTOGRAPHIC_SECURITY_ERROR,
  LIMIT_EXCEEDED_ERROR, RETRIEVAL_ERROR
} from './errors.js';
import {isUrl, listOf} from './common.js';
import Ajv from 'ajv';
import {createHash} from 'node:crypto';

// Credential validation (Sections 4.4 and 4.4.1).
//
// Credential validators must be data: URLs; any other URL is not retrieved,
// so the validator fails with a RETRIEVAL_ERROR.
//
// runValidator({source, input, timeoutMs, environment}) runs one JavaScript
// validator and returns {ok, result, error, errorType, limitExceeded}. The
// host must supply it; a JavaScript validator without one is an error.

export const DEFAULT_VALIDATOR_TIMEOUT_MS = 5000;

// Credential validation (4.4). Returns {valid, errors, warnings}. A validator
// that rejects the credential, or that cannot be applied, makes the result
// invalid. Only a limit that ran out is reported for the caller to raise.
export async function validateCredential({
  credential, validators, options, runValidator,
  timeoutMs = DEFAULT_VALIDATOR_TIMEOUT_MS
}) {
  const result = {valid: true, errors: [], warnings: []};
  const fail = (type, detail) => {
    result.valid = false;
    result.errors.push({type, title: 'Credential validation failed', detail});
  };
  for(const validator of listOf(validators)) {
    if(validator?.type !== 'CredentialValidator') {
      fail(CREDENTIAL_VALIDATION_ERROR,
        `Validator type is ${JSON.stringify(validator?.type)}.`);
      continue;
    }
    if(validator.mediaType === 'application/schema+json') {
      const text = inlineData(validator.id, 'application/schema+json');
      if(text === undefined) {
        fail(RETRIEVAL_ERROR, `Cannot retrieve ${validator.id}.`);
        continue;
      }
      if(digestMatches(text, validator) === false) {
        fail(CRYPTOGRAPHIC_SECURITY_ERROR,
          'The schema does not match the hash in the validator.');
        continue;
      }
      try {
        const ajv = new Ajv({strict: false, allErrors: false});
        if(!ajv.validate(JSON.parse(text), credential)) {
          fail(CREDENTIAL_VALIDATION_ERROR,
            'The credential does not conform to the JSON Schema.');
        }
      } catch(error) {
        fail(CREDENTIAL_VALIDATION_ERROR,
          `The JSON Schema cannot be applied: ${error.message}`);
      }
      continue;
    }
    if(validator.mediaType === 'text/javascript') {
      const outcome = await runJavaScriptValidator(
        {validator, credential, options, runValidator, timeoutMs});
      result.errors.push(...outcome.errors);
      result.warnings.push(...outcome.warnings);
      if(outcome.valid !== true) {
        result.valid = false;
      }
      continue;
    }
    fail(CREDENTIAL_VALIDATION_ERROR,
      `Unsupported mediaType ${JSON.stringify(validator.mediaType)}.`);
  }
  return result;
}

// JavaScript validator processing (4.4.1). The sandbox reports the evaluation
// time as the current time and seeds Math.random with a constant, so a
// validator that reads them still gives the same result every time.
export async function runJavaScriptValidator({
  validator, credential, options, runValidator,
  timeoutMs = DEFAULT_VALIDATOR_TIMEOUT_MS
}) {
  const result = {valid: false, errors: [], warnings: []};
  const problem = (type, detail) => result.errors.push(
    {type, title: 'JavaScript validator failed', detail});
  if(typeof runValidator !== 'function') {
    throw new TypeError('A runValidator hook is required for a JavaScript ' +
      'validator.');
  }
  const source = inlineData(validator.id, 'text/javascript');
  if(source === undefined) {
    problem(RETRIEVAL_ERROR, `Cannot retrieve ${validator.id}.`);
    return result;
  }
  if(digestMatches(source, validator) === false) {
    problem(CRYPTOGRAPHIC_SECURITY_ERROR,
      'The validator code does not match the hash in the validator.');
    return result;
  }
  const reply = await runValidator({
    source,
    input: {credential, options},
    timeoutMs,
    environment: {now: Date.parse(options.evaluationDateTime), seed: 0}
  });
  if(!reply.ok) {
    if(reply.limitExceeded) {
      problem(LIMIT_EXCEEDED_ERROR, reply.error);
    } else {
      problem(isUrl(reply.errorType) ? reply.errorType :
        CREDENTIAL_VALIDATION_ERROR, reply.error);
    }
    return result;
  }
  const output = reply.result;
  if(!isValidationResult(output)) {
    problem(CREDENTIAL_VALIDATION_ERROR,
      'The validator did not return a validation result.');
    return result;
  }
  result.valid = output.valid;
  result.errors.push(...listOf(output.errors));
  result.warnings.push(...listOf(output.warnings));
  if(result.errors.length > 0) {
    result.valid = false;
  }
  return result;
}

// 4.4.1.1: {valid: boolean, errors?, warnings?}, where errors and warnings are
// arrays of ProblemDetails objects, and errors is empty when valid is true.
export function isValidationResult(output) {
  if(output === null || typeof output !== 'object' ||
    typeof output.valid !== 'boolean') {
    return false;
  }
  const items = name => output[name] === undefined ? [] : output[name];
  for(const name of ['errors', 'warnings']) {
    const value = items(name);
    if(!Array.isArray(value) || !value.every(item =>
      item !== null && typeof item === 'object' && isUrl(item.type))) {
      return false;
    }
  }
  return !(output.valid && items('errors').length > 0);
}

// The content of a data: URL with the given media type, or undefined. Other
// URLs are not retrieved.
export function inlineData(id, mediaType) {
  const match = /^data:([^,;]*)((?:;[^,;]*)*),(.*)$/s.exec(id ?? '');
  if(!match || match[1] !== mediaType) {
    return undefined;
  }
  return match[2].includes(';base64') ?
    Buffer.from(match[3], 'base64').toString('utf8') :
    decodeURIComponent(match[3]);
}

// Checks the cryptographic hash a credential validator may carry (4.4.1): the
// digestSRI or digestMultibase property, as described in section 5.3 of VC
// Data Model 2.0. Only SHA-256 is supported. A validator whose hash cannot be
// checked does not match.

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const SHA256_MULTIHASH_PREFIX = [0x12, 0x20];

// base58btc, the encoding of a multibase value that starts with 'z'.
function base58Decode(text) {
  let value = 0n;
  for(const ch of text) {
    const index = BASE58.indexOf(ch);
    if(index < 0) {
      throw new Error('not base58');
    }
    value = value * 58n + BigInt(index);
  }
  let hex = value.toString(16);
  if(hex.length % 2) {
    hex = '0' + hex;
  }
  const leadingZeros = [...text].findIndex(ch => ch !== '1');
  const zeros = leadingZeros < 0 ? text.length : leadingZeros;
  return Buffer.concat([Buffer.alloc(zeros),
    value === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex')]);
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest();
}

// True when the validator's hash matches the code. Undefined when the
// validator carries no hash, so the caller can skip the check.
export function digestMatches(code, validator) {
  if(validator?.digestSRI !== undefined) {
    const expected = sha256(code).toString('base64');
    return String(validator.digestSRI).split(/\s+/).some(
      token => token === `sha256-${expected}`);
  }
  if(validator?.digestMultibase !== undefined) {
    const value = String(validator.digestMultibase);
    if(!value.startsWith('z')) {
      return false;
    }
    try {
      const bytes = base58Decode(value.slice(1));
      const [a, b] = SHA256_MULTIHASH_PREFIX;
      return bytes[0] === a && bytes[1] === b &&
        bytes.subarray(2).equals(sha256(code));
    } catch(error) {
      return false;
    }
  }
  return undefined;
}
