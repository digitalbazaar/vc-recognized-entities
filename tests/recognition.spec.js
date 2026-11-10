/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {
  ANCHOR, ISSUE_ACTION, listCredential, OTHER, targetCredential
} from './fixtures.js';
import {describe, it} from 'mocha';
import {expect} from 'chai';
import {validateRecognition} from '../lib/index.js';

const EVAL = '2026-01-01T00:00:00Z';
const base = {
  action: 'issue',
  recognizedIssuers: [ANCHOR],
  evaluationDateTime: EVAL,
  maxDepth: 5
};
const direct = list => [targetCredential(), list];

describe('validateRecognition (Section 4.3)', () => {
  it('recognizes a chain to an anchor for a listed action', () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    expect(validateRecognition({...base, chain: direct(list)}))
      .to.deep.equal({recognized: true, actionRecognized: true});
  });

  it('recognizes the issuer but not the action', () => {
    const list = listCredential({recognizedTo: {action: 'verify'}});
    expect(validateRecognition({...base, chain: direct(list)}))
      .to.deep.equal({recognized: true, actionRecognized: false});
  });

  it('rejects a chain of fewer than two credentials', () => {
    expect(validateRecognition({...base, chain: [targetCredential()]}))
      .to.deep.equal({recognized: false, actionRecognized: false});
  });

  it('rejects a chain whose final issuer is not an anchor', () => {
    const list = listCredential({issuer: OTHER, recognizedTo: ISSUE_ACTION});
    expect(validateRecognition({...base, chain: direct(list)}).recognized)
      .to.be.false;
  });

  it('rejects a list that does not name the issuer', () => {
    const list = listCredential({entity: OTHER, recognizedTo: ISSUE_ACTION});
    expect(validateRecognition({...base, chain: direct(list)}).recognized)
      .to.be.false;
  });

  it('rejects an evaluation time outside the window', () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    const result = validateRecognition({
      ...base, chain: direct(list),
      evaluationDateTime: '2031-01-01T00:00:00Z'
    });
    expect(result.recognized).to.be.false;
  });

  it('treats validity endpoints as inclusive', () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    const result = validateRecognition({
      ...base, chain: direct(list),
      evaluationDateTime: '2030-01-01T00:00:00Z'
    });
    expect(result.actionRecognized).to.be.true;
  });

  it('falls back to the list validity for a missing action validUntil', () => {
    const list = listCredential({
      recognizedTo: {action: 'issue', validFrom: '2025-01-01T00:00:00Z'},
      validUntil: '2026-06-01T00:00:00Z'
    });
    const result = validateRecognition({
      ...base, chain: direct(list),
      evaluationDateTime: '2027-01-01T00:00:00Z'
    });
    expect(result).to.deep.equal({recognized: false, actionRecognized: false});
  });

  it('rejects a chain that repeats an issuer', () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    const chain = [targetCredential(), list, list];
    expect(validateRecognition({...base, chain}).recognized).to.be.false;
  });

  it('rejects a chain longer than maxDepth', () => {
    const list = listCredential({recognizedTo: ISSUE_ACTION});
    expect(validateRecognition({...base, maxDepth: 1, chain: direct(list)})
      .recognized).to.be.false;
  });

  it('uses outputValidation to decide actionRecognized', () => {
    const list = listCredential({recognizedTo: {
      ...ISSUE_ACTION, outputValidation: [{type: 'JsonSchema', id: 'x'}]
    }});
    const pass = validateRecognition({
      ...base, chain: direct(list), validateOutputValidation: () => true
    });
    const fail = validateRecognition({
      ...base, chain: direct(list), validateOutputValidation: () => false
    });
    expect(pass.actionRecognized).to.be.true;
    expect(fail.actionRecognized).to.be.false;
  });

  it('requires a schema validator when outputValidation is present', () => {
    const list = listCredential({recognizedTo: {
      ...ISSUE_ACTION, outputValidation: {type: 'JsonSchema', id: 'x'}
    }});
    expect(() => validateRecognition({...base, chain: direct(list)}))
      .to.throw(TypeError);
  });
});
