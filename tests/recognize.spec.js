/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  ANCHOR, ISSUE_ACTION, ISSUER, LIST_URL, listCredential, targetCredential
} from './fixtures.js';
import {
  applyRetrievalPolicy, chainViolations, CREDENTIAL_VALIDATION_ERROR,
  CRYPTOGRAPHIC_SECURITY_ERROR, dataModelViolations, digestMatches,
  inlineData, isEvaluationDateTime, isValidationResult, LIMIT_EXCEEDED_ERROR,
  recognize, RETRIEVAL_ERROR, retrievalAllowed, validateCredential
} from '../lib/index.js';
import {describe, it} from 'mocha';
import {createHash} from 'node:crypto';
import {expect} from 'chai';

const EVAL = '2026-01-01T00:00:00Z';
const V2 = 'https://www.w3.org/ns/credentials/v2';
const CODE = 'export default () => ({valid: true});';
const jsValidator = (extra = {}) => ({
  id: `data:text/javascript,${encodeURIComponent(CODE)}`,
  type: 'CredentialValidator',
  mediaType: 'text/javascript',
  ...extra
});
const sri = text =>
  `sha256-${createHash('sha256').update(text).digest('base64')}`;
const stubRunner = reply => async () => reply;
const verified = async () => ({verified: true});

// A list that conforms to the data model of section 3.
const conformingList = options => ({
  '@context': [V2], ...listCredential(options)
});
const base = {
  action: 'issue', evaluationDateTime: EVAL, recognizedIssuers: [ANCHOR],
  maxDepth: 5, maxDuration: 1000
};
const stapled = recognizedTo => ({
  credential: targetCredential(
    {recognizedIn: {id: LIST_URL, type: 'RecognizedEntityCredential'}}),
  documents: [conformingList({recognizedTo})]
});

describe('recognize', () => {
  it('recognizes a stapled chain for a listed action', async () => {
    const result = await recognize({
      ...base, ...stapled(ISSUE_ACTION), hooks: {verifyProof: verified}
    });
    expect(result).to.deep.equal(
      {recognized: true, actionRecognized: true, errors: [], warnings: []});
  });

  it('refuses a stapled list that breaks the data model', async () => {
    const {credential} = stapled(ISSUE_ACTION);
    const result = await recognize({
      ...base, credential, documents: [listCredential()],
      hooks: {verifyProof: verified}, nonConformingDocumentType: 'urn:x'
    });
    expect(result.recognized).to.equal(false);
    expect(result.errors[0].type).to.equal('urn:x');
  });

  it('raises CRYPTOGRAPHIC_SECURITY_ERROR for a bad proof', async () => {
    const roles = [];
    const verifyProof = async ({role}) => {
      roles.push(role);
      return {verified: false};
    };
    const error = await recognize({
      ...base, ...stapled(ISSUE_ACTION), hooks: {verifyProof}
    }).catch(e => e);
    expect(error.type).to.equal(CRYPTOGRAPHIC_SECURITY_ERROR);
    expect(roles).to.deep.equal(['credential']);
  });

  it('runs credential validators with the runValidator hook', async () => {
    const result = await recognize({
      ...base,
      ...stapled({...ISSUE_ACTION, credentialValidator: jsValidator()}),
      hooks: {
        verifyProof: verified,
        runValidator: stubRunner({ok: true, result: {valid: false}})
      }
    });
    expect(result.recognized).to.equal(true);
    expect(result.actionRecognized).to.equal(false);
  });

  it('raises LIMIT_EXCEEDED_ERROR when a validator runs out', async () => {
    const error = await recognize({
      ...base,
      ...stapled({...ISSUE_ACTION, credentialValidator: jsValidator()}),
      hooks: {
        verifyProof: verified,
        runValidator: stubRunner({ok: false, limitExceeded: true, error: 't'})
      }
    }).catch(e => e);
    expect(error.type).to.equal(LIMIT_EXCEEDED_ERROR);
  });

  it('checks a list that discovery fetches against section 3', async () => {
    const result = await recognize({
      ...base,
      credential: targetCredential(
        {recognizedIn: {id: LIST_URL, type: 'RecognizedEntityCredential'}}),
      documents: [],
      nonConformingDocumentType: 'urn:x',
      hooks: {
        verifyProof: verified,
        // A list without the @context that section 3 requires.
        fetchCredential: async () => listCredential(
          {recognizedTo: ISSUE_ACTION})
      }
    });
    expect(result.recognized).to.equal(false);
    expect(result.errors[0].type).to.equal('urn:x');
  });

  describe('an intermediate credential in a three-credential chain', () => {
    // The credential under test is listed by LIST_URL, which the intermediate
    // issuer recognizes. The intermediate issuer is listed by LIST_B, which
    // the anchor recognizes. LIST_B's validator for the intermediate issuer
    // is what runs on LIST_URL's credential.
    const intermediate = 'did:example:intermediate';
    const listB = 'https://anchor.example/lists/intermediate.json';
    const documents = () => [
      conformingList({
        id: LIST_URL,
        issuer: {id: intermediate, type: 'RecognizedIssuer', recognizedIn: {
          id: listB, type: 'RecognizedEntityCredential'
        }},
        entity: ISSUER,
        recognizedTo: ISSUE_ACTION
      }),
      conformingList({
        id: listB,
        issuer: ANCHOR,
        entity: intermediate,
        recognizedTo: {...ISSUE_ACTION, credentialValidator: [jsValidator()]}
      })
    ];
    const credential = () => targetCredential(
      {recognizedIn: {id: LIST_URL, type: 'RecognizedEntityCredential'}});
    const refusal = {
      type: 'https://anchor.example/problems/refused', title: 'Refused'
    };

    it('recognizes when the validator accepts the intermediate', async () => {
      const runs = [];
      const result = await recognize({
        ...base, credential: credential(), documents: documents(),
        hooks: {
          verifyProof: verified,
          runValidator: async request => {
            runs.push(request);
            return {ok: true, result: {valid: true, errors: [], warnings: []}};
          }
        }
      });
      expect(result.recognized).to.equal(true);
      expect(result.actionRecognized).to.equal(true);
      expect(runs).to.have.length(1);
      expect(runs[0].input.credential.id).to.equal(LIST_URL);
      expect(runs[0].input.options.chain).to.have.length(1);
    });

    it('refuses the action when the validator rejects the intermediate',
      async () => {
        const result = await recognize({
          ...base, credential: credential(), documents: documents(),
          hooks: {
            verifyProof: verified,
            runValidator: async () => ({
              ok: true, result: {valid: false, errors: [refusal], warnings: []}
            })
          }
        });
        expect(result.recognized).to.equal(true);
        expect(result.actionRecognized).to.equal(false);
        expect(result.errors[0].type).to.equal(refusal.type);
      });
  });

  it('raises LIMIT_EXCEEDED_ERROR when validation runs past maxDuration',
    async () => {
      const clock = {t: 0};
      const timeouts = [];
      const error = await recognize({
        ...base, maxDuration: 1000,
        ...stapled({...ISSUE_ACTION, credentialValidator: jsValidator()}),
        hooks: {
          verifyProof: verified,
          now: () => clock.t,
          runValidator: async request => {
            timeouts.push(request.timeoutMs);
            clock.t += 1500;
            return {ok: true, result: {valid: true, errors: [], warnings: []}};
          }
        }
      }).catch(e => e);
      expect(error.type).to.equal(LIMIT_EXCEEDED_ERROR);
      expect(timeouts[0]).to.be.at.most(1000);
    });

  it('applies the retrieval policy before resolving an identifier',
    async () => {
      let called = false;
      const error = await recognize({
        ...base,
        credential: targetCredential({issuer: 'did:web:localhost'}),
        hooks: {
          verifyProof: verified,
          resolveIdentifier: async () => {
            called = true;
            return {};
          }
        }
      }).catch(e => e);
      expect(error.type).to.equal(RETRIEVAL_ERROR);
      expect(called).to.equal(false);
    });

  it('requires a verifyProof hook', async () => {
    const error = await recognize({...base, ...stapled(ISSUE_ACTION)})
      .catch(e => e);
    expect(error).to.be.instanceOf(TypeError);
  });
});

describe('validateCredential (Sections 4.4, 4.4.1)', () => {
  const options = {chain: [], action: 'issue', evaluationDateTime: EVAL};
  const run = (validator, reply) => validateCredential({
    credential: {}, validators: [validator], options,
    runValidator: stubRunner(reply)
  });

  it('accepts when the validator returns valid', async () => {
    const result = await run(jsValidator({digestSRI: sri(CODE)}),
      {ok: true, result: {valid: true}});
    expect(result.valid).to.equal(true);
  });

  it('refuses when the hash does not match', async () => {
    const result = await run(jsValidator({digestSRI: sri('other')}),
      {ok: true, result: {valid: true}});
    expect(result.valid).to.equal(false);
    expect(result.errors[0].type).to.equal(CRYPTOGRAPHIC_SECURITY_ERROR);
  });

  it('refuses when the validator rejects', async () => {
    const result = await run(jsValidator(), {ok: false, error: 'rejected'});
    expect(result.valid).to.equal(false);
    expect(result.errors[0].type).to.equal(CREDENTIAL_VALIDATION_ERROR);
  });

  it('refuses a validator that cannot be applied', async () => {
    const result = await run(
      {...jsValidator(), id: 'https://example.com/v.js'}, {ok: true});
    expect(result.valid).to.equal(false);
    expect(result.errors[0].type).to.equal(RETRIEVAL_ERROR);
  });

  it('checks a JSON Schema validator', async () => {
    const schema = JSON.stringify({required: ['type']});
    const result = await run({
      id: `data:application/schema+json,${encodeURIComponent(schema)}`,
      type: 'CredentialValidator', mediaType: 'application/schema+json'
    });
    expect(result.valid).to.equal(false);
  });

  it('runs a validator in the default sandbox', async () => {
    const result = await validateCredential(
      {credential: {}, validators: [jsValidator()], options});
    expect(result.valid).to.equal(true);
  });
});

describe('validator helpers', () => {
  it('matches digestSRI and digestMultibase', () => {
    expect(digestMatches(CODE, {digestSRI: sri(CODE)})).to.equal(true);
    expect(digestMatches(CODE, {})).to.equal(undefined);
    expect(digestMatches(CODE, {digestMultibase: 'uAAAA'})).to.equal(false);
  });

  it('reads data: URLs', () => {
    expect(inlineData('data:text/plain;base64,aGk=', 'text/plain'))
      .to.equal('hi');
    expect(inlineData('https://example.com/', 'text/plain'))
      .to.equal(undefined);
  });

  it('checks the validation result shape', () => {
    expect(isValidationResult({valid: true})).to.equal(true);
    expect(isValidationResult({valid: true, errors: [{type: 'urn:x'}]}))
      .to.equal(false);
    expect(isValidationResult({valid: 'yes'})).to.equal(false);
  });

  it('checks the evaluation time format', () => {
    expect(isEvaluationDateTime(EVAL)).to.equal(true);
    expect(isEvaluationDateTime('2026-02-30T00:00:00Z')).to.equal(false);
    expect(isEvaluationDateTime('2026-01-01')).to.equal(false);
  });
});

describe('data model checks (Section 3)', () => {
  it('accepts a conforming list', () => {
    expect(dataModelViolations(conformingList(), 'list')).to.deep.equal([]);
  });

  it('reports a bad recognizedIn on the credential under test', () => {
    const credential = targetCredential({recognizedIn: {id: 'not a url'}});
    expect(chainViolations({credential})).to.have.length(2);
  });
});

describe('retrieval policy (Section 4)', () => {
  it('allows only public https URLs', () => {
    expect(retrievalAllowed('https://example.com/')).to.equal(true);
    expect(retrievalAllowed('http://example.com/')).to.equal(false);
    expect(retrievalAllowed('https://127.0.0.1/')).to.equal(false);
    expect(retrievalAllowed('https://[::1]/')).to.equal(false);
    expect(retrievalAllowed('https://a.localhost/')).to.equal(false);
  });

  it('passes did:key through and checks did:web hosts', async () => {
    const {resolveIdentifier} = applyRetrievalPolicy(
      {resolveIdentifier: async id => id});
    expect(await resolveIdentifier('did:key:z6Mk')).to.equal('did:key:z6Mk');
    expect(await resolveIdentifier(ISSUER).catch(e => e))
      .to.be.instanceOf(Error);
    expect(await resolveIdentifier('did:web:example.com'))
      .to.equal('did:web:example.com');
    expect(await resolveIdentifier('did:web:10.0.0.1').catch(e => e))
      .to.be.instanceOf(Error);
  });
});
