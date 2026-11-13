/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

import {
  CREDENTIAL_VALIDATION_ERROR, CRYPTOGRAPHIC_SECURITY_ERROR,
  LIMIT_EXCEEDED_ERROR, RETRIEVAL_ERROR
} from './errors.js';
import {isUrl, listOf} from './common.js';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {Worker} from 'node:worker_threads';

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
      const outcome = await validateSchemaInWorker(
        {text, credential, timeoutMs});
      if(outcome.limitExceeded) {
        fail(LIMIT_EXCEEDED_ERROR, outcome.error);
      } else if(!outcome.ok) {
        fail(CREDENTIAL_VALIDATION_ERROR,
          `The JSON Schema cannot be applied: ${outcome.error}`);
      } else if(!outcome.valid) {
        fail(CREDENTIAL_VALIDATION_ERROR,
          'The credential does not conform to the JSON Schema.');
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

// Runs a JSON Schema in a worker thread and waits at most timeoutMs. Returns
// {ok, valid} when the schema ran, {ok: false, error} when it could not be
// applied, and {ok: false, limitExceeded: true, error} when the time ran out.
// The worker is ended in every case, so a slow pattern cannot keep running.
export function validateSchemaInWorker({text, credential, timeoutMs}) {
  return new Promise(resolve => {
    const state = {settled: false, timer: undefined};
    const worker = new Worker(
      fileURLToPath(new URL('./schema-worker.js', import.meta.url)),
      {workerData: {text, credential}});
    const settle = outcome => {
      if(state.settled) {
        return;
      }
      state.settled = true;
      clearTimeout(state.timer);
      worker.terminate();
      resolve(outcome);
    };
    state.timer = setTimeout(() => settle({
      ok: false, limitExceeded: true,
      error: `The JSON Schema did not finish within ${timeoutMs} ms.`
    }), timeoutMs);
    worker.once('message', settle);
    worker.once('error', error => settle({ok: false, error: error.message}));
    worker.once('exit', () => settle({
      ok: false, error: 'The schema worker stopped without a result.'
    }));
  });
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
    return multihashMatches(String(validator.digestMultibase), code);
  }
  return undefined;
}

// A multibase value with the 'z' (base58btc) or 'u' (base64url, no padding)
// prefix, decoded to bytes. Undefined for any other prefix or a body that does
// not encode back to the same text.
function multibaseDecode(value) {
  if(value.startsWith('z')) {
    return base58Decode(value.slice(1));
  }
  if(value.startsWith('u')) {
    const body = value.slice(1);
    const bytes = Buffer.from(body, 'base64url');
    return bytes.toString('base64url') === body ? bytes : undefined;
  }
  return undefined;
}

function multihashMatches(value, code) {
  let bytes;
  try {
    bytes = multibaseDecode(value);
  } catch(error) {
    return false;
  }
  const [a, b] = SHA256_MULTIHASH_PREFIX;
  return bytes !== undefined && bytes[0] === a && bytes[1] === b &&
    bytes.subarray(2).equals(sha256(code));
}
