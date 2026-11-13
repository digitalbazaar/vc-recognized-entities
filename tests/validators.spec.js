/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  CREDENTIAL_VALIDATION_ERROR, CRYPTOGRAPHIC_SECURITY_ERROR,
  LIMIT_EXCEEDED_ERROR
} from '../lib/errors.js';
import {describe, it} from 'mocha';
import {
  digestMatches, isValidationResult, runJavaScriptValidator, validateCredential
} from '../lib/validators.js';
import {createHash} from 'node:crypto';
import {expect} from 'chai';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const OPTIONS = {action: 'issue', evaluationDateTime: '2026-11-12T00:00:00Z'};

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest();
}

// 'z' + base58btc of a SHA-256 multihash, as digestMultibase carries it.
function multibaseOf(text) {
  let value = BigInt('0x' + Buffer.concat(
    [Buffer.from([0x12, 0x20]), sha256(text)]).toString('hex'));
  let out = '';
  while(value > 0n) {
    out = BASE58[Number(value % 58n)] + out;
    value /= 58n;
  }
  return 'z' + out;
}

// 'u' + base64url (no padding) of a SHA-256 multihash, the other form.
function multibaseBase64UrlOf(text) {
  return 'u' + Buffer.concat(
    [Buffer.from([0x12, 0x20]), sha256(text)]).toString('base64url');
}

function schemaValidator(schema) {
  return {
    type: 'CredentialValidator',
    id: 'data:application/schema+json,' +
      encodeURIComponent(JSON.stringify(schema)),
    mediaType: 'application/schema+json'
  };
}

const CODE = 'export default function validate() { return {valid: true}; }';

function jsValidator(code = CODE, extra = {}) {
  return {
    type: 'CredentialValidator',
    id: 'data:text/javascript,' + encodeURIComponent(code),
    mediaType: 'text/javascript',
    ...extra
  };
}

// A runner that answers with a fixed reply and records what it was asked.
function runnerReplying(reply) {
  const calls = [];
  const runner = async request => {
    calls.push(request);
    return reply;
  };
  return {runner, calls};
}

const credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  validFrom: '2025-06-01T00:00:00Z',
  credentialSubject: {id: 'urn:example:subject'}
};

describe('credential validators', () => {
  describe('JSON Schema validators', () => {
    it('accepts a credential that conforms to the inline schema', async () => {
      const result = await validateCredential({credential, options: OPTIONS,
        validators: [schemaValidator({required: ['validFrom']})]});
      expect(result.valid).to.be.true;
    });

    it('refuses a credential that does not conform', async () => {
      const result = await validateCredential({credential, options: OPTIONS,
        validators: [schemaValidator({required: ['expirationDate']})]});
      expect(result.valid).to.be.false;
      expect(result.errors[0].type).to.equal(CREDENTIAL_VALIDATION_ERROR);
    });

    it('applies 2020-12 keywords when the schema declares them', async () => {
      // prefixItems is a 2020-12 keyword; draft-07 ignores it.
      const schema = {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'object',
        properties: {tags: {prefixItems: [{const: 'a'}]}}
      };
      const tagged = {...credential, tags: ['b']};
      const result = await validateCredential({
        credential: tagged, options: OPTIONS,
        validators: [schemaValidator(schema)]
      });
      expect(result.valid).to.be.false;
      expect(result.errors[0].type).to.equal(CREDENTIAL_VALIDATION_ERROR);
    });

    it('ends a schema that runs past the time limit', async () => {
      // A nested quantifier that backtracks for a long time on this input.
      const schema = {
        type: 'object',
        properties: {x: {type: 'string', pattern: '^(a+)+$'}}
      };
      const slow = {...credential, x: 'a'.repeat(40) + '!'};
      const started = Date.now();
      const result = await validateCredential({
        credential: slow, options: OPTIONS, timeoutMs: 200,
        validators: [schemaValidator(schema)]
      });
      expect(Date.now() - started).to.be.below(5000);
      expect(result.valid).to.be.false;
      expect(result.errors[0].type).to.equal(LIMIT_EXCEEDED_ERROR);
    });
  });

  describe('JavaScript validators', () => {
    it('uses the runner, and accepts a result of valid true', async () => {
      const {runner, calls} = runnerReplying({ok: true,
        result: {valid: true, errors: [], warnings: []}});
      const result = await validateCredential({credential, options: OPTIONS,
        validators: [jsValidator()], runValidator: runner});
      expect(calls).to.have.lengthOf(1);
      expect(result.valid).to.be.true;
    });

    it('refuses a result of valid false', async () => {
      const {runner} = runnerReplying({ok: true,
        result: {valid: false, errors: [], warnings: []}});
      const result = await validateCredential({credential, options: OPTIONS,
        validators: [jsValidator()], runValidator: runner});
      expect(result.valid).to.be.false;
    });

    it('refuses code whose hash does not match, unrun', async () => {
      const {runner, calls} = runnerReplying({ok: true,
        result: {valid: true, errors: [], warnings: []}});
      const validator = jsValidator(CODE,
        {digestMultibase: multibaseOf('other')});
      const outcome = await runJavaScriptValidator({validator, credential,
        options: OPTIONS, runValidator: runner});
      expect(calls).to.have.lengthOf(0);
      expect(outcome.valid).to.be.false;
      expect(outcome.errors[0].type).to.equal(CRYPTOGRAPHIC_SECURITY_ERROR);
    });

    it('requires a runner hook for a JavaScript validator', async () => {
      let error;
      try {
        await validateCredential({credential, options: OPTIONS,
          validators: [jsValidator()]});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.instanceOf(TypeError);
      expect(error.message).to.match(/runValidator hook is required/);
    });
  });

  it('refuses a validator with a media type it does not support', async () => {
    const result = await validateCredential({credential, options: OPTIONS,
      validators: [{type: 'CredentialValidator', id: 'x',
        mediaType: 'text/plain'}]});
    expect(result.valid).to.be.false;
    expect(result.errors[0].type).to.equal(CREDENTIAL_VALIDATION_ERROR);
  });
});

describe('digest checks (4.4.1)', () => {
  it('matches a digestSRI of the code, and not of other code', () => {
    const sri = 'sha256-' + sha256(CODE).toString('base64');
    expect(digestMatches(CODE, {digestSRI: sri})).to.be.true;
    expect(digestMatches('other', {digestSRI: sri})).to.be.false;
  });

  it('matches a digestMultibase of the code, and not of other code', () => {
    const multibase = multibaseOf(CODE);
    expect(digestMatches(CODE, {digestMultibase: multibase})).to.be.true;
    expect(digestMatches('other', {digestMultibase: multibase})).to.be.false;
  });

  it('matches a digestMultibase in base64url form (u prefix)', () => {
    const multibase = multibaseBase64UrlOf(CODE);
    expect(digestMatches(CODE, {digestMultibase: multibase})).to.be.true;
    expect(digestMatches('other', {digestMultibase: multibase})).to.be.false;
  });

  it('refuses a digestMultibase with a non-canonical base64url body', () => {
    const multibase = multibaseBase64UrlOf(CODE) + '=';
    expect(digestMatches(CODE, {digestMultibase: multibase})).to.be.false;
  });

  it('is undefined when the validator carries no digest', () => {
    expect(digestMatches(CODE, {})).to.be.undefined;
  });
});

describe('validation results', () => {
  it('accepts a result with a boolean valid and array lists', () => {
    expect(isValidationResult({valid: true, errors: [], warnings: []}))
      .to.be.true;
  });

  it('rejects a result without a boolean valid', () => {
    expect(isValidationResult({errors: []})).to.be.false;
    expect(isValidationResult({valid: 'yes'})).to.be.false;
  });
});
