/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

import {describe, it} from 'mocha';
import {expect} from 'chai';
import {runValidatorInSandbox} from '../lib/sandbox.js';

const INPUT = {credential: {type: ['VerifiableCredential']}, options: {}};

// Source that runs a validator's body with a value the sandbox must not have.
function validator(body) {
  return `export default function validate(credential, options) { ${body} }`;
}

describe('validator sandbox', () => {
  it('returns the result of a valid validator', async () => {
    const reply = await runValidatorInSandbox({
      source: validator(`return {valid: credential.type.includes(
        'VerifiableCredential'), errors: [], warnings: []};`),
      input: INPUT
    });
    expect(reply.ok).to.be.true;
    expect(reply.result.valid).to.be.true;
  });

  it('refuses an import of a Node module', async () => {
    const reply = await runValidatorInSandbox({
      source: `import fs from 'node:fs';
        export default () => ({valid: fs.readFileSync('/etc/passwd') !== ''});`,
      input: INPUT
    });
    expect(reply.ok).to.be.false;
    expect(reply.error).to.match(/not allowed in the sandbox/);
  });

  it('refuses other imports, including data: URLs', async () => {
    for(const source of [
      'import x from \'other\'; export default () => ({valid: x === 1});',
      'import x from \'data:text/javascript,export default 1\'; ' +
        'export default () => ({valid: x === 1});'
    ]) {
      const reply = await runValidatorInSandbox({source, input: INPUT});
      expect(reply.ok).to.be.false;
    }
  });

  it('has no host globals such as fetch, process or timers', async () => {
    const reply = await runValidatorInSandbox({
      source: validator(`return {valid: typeof fetch === 'undefined' &&
        typeof process === 'undefined' && typeof require === 'undefined' &&
        typeof setTimeout === 'undefined'};`),
      input: INPUT
    });
    expect(reply.ok).to.be.true;
    expect(reply.result.valid).to.be.true;
  });

  it('refuses a call to fetch, which the sandbox lacks', async () => {
    const reply = await runValidatorInSandbox({
      source: validator(
        `fetch('https://example.com/'); return {valid: true};`),
      input: INPUT
    });
    expect(reply.ok).to.be.false;
    expect(reply.error).to.match(/fetch/);
  });

  it('stops a validator that never finishes, at the time limit', async () => {
    const reply = await runValidatorInSandbox({
      source: validator('for(;;) {}'),
      input: INPUT,
      timeoutMs: 1000
    });
    expect(reply.ok).to.be.false;
    expect(reply.limitExceeded).to.be.true;
  });

  it('stops a validator that exhausts memory', async () => {
    const reply = await runValidatorInSandbox({
      source: validator(
        'const big = []; for(;;) big.push(new Array(1e6).fill(0));'),
      input: INPUT,
      memoryBytes: 32 * 1024 * 1024
    });
    expect(reply.ok).to.be.false;
  });

  it('accepts an async validator that resolves', async () => {
    const reply = await runValidatorInSandbox({
      source: 'export default async () => ({valid: true});',
      input: INPUT
    });
    expect(reply.ok).to.be.true;
    expect(reply.result.valid).to.be.true;
  });

  it('refuses a module whose default export is not a function', async () => {
    const reply = await runValidatorInSandbox({
      source: 'export default 42;',
      input: INPUT
    });
    expect(reply.ok).to.be.false;
    expect(reply.error).to.match(/default-export a function/);
  });

  it('keeps no state from one run to the next', async () => {
    await runValidatorInSandbox({
      source: validator('globalThis.leak = 1; return {valid: true};'),
      input: INPUT
    });
    const reply = await runValidatorInSandbox({
      source: validator(
        `return {valid: typeof globalThis.leak === 'undefined'};`),
      input: INPUT
    });
    expect(reply.ok).to.be.true;
    expect(reply.result.valid).to.be.true;
  });
});
