/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

// Runs a JavaScript credential validator in a sandbox built from QuickJS, a
// JavaScript engine compiled to WebAssembly (quickjs-emscripten). This is the
// sandbox the verifier uses. It meets the requirements of section 4.4.1 of
// VC Recognized Entities v1.0:
//
// - No network: the engine has no fetch, sockets, or timers from the host.
// - No host state: the engine's heap is separate from the host's, and the only
//   host values it sees are the copies passed in as JSON.
// - No other modules: the module loader accepts the validator module and
//   refuses every other import, including data: URLs and node: modules.
// - Fresh sandbox per run: each call creates and disposes its own runtime.
// - The host can stop the validator: a deadline interrupts running code, and a
//   memory limit stops allocation.
//
// The engine runs in the host process, so this is not a separate OS process.
// The spec lists WebAssembly-compiled engines as an acceptable environment.

import {getQuickJS, shouldInterruptAfterDeadline} from 'quickjs-emscripten';

export const DEFAULT_TIMEOUT_MS = 5000;
export const DEFAULT_MEMORY_BYTES = 64 * 1024 * 1024;
const MAX_STACK_BYTES = 512 * 1024;
const MAX_RESULT_CHARS = 1024 * 1024;
const VALIDATOR_MODULE = 'validator';

// Runs in the sandbox after the validator module loads. It wraps the default
// export so that the host can call it with JSON input and read JSON output.
// Section 4.4.1: the validation function is called as
// validate(credential, options), and a returned promise is awaited.
const ENTRY = `
import validate from '${VALIDATOR_MODULE}';
if(typeof validate !== 'function') {
  throw new TypeError('the validator must default-export a function');
}
globalThis.__runValidator = async function(json) {
  const {credential, options} = JSON.parse(json);
  return JSON.stringify(await validate(credential, options));
};
`;

// Optional: replaces Date and Math.random in the sandbox before the validator
// loads, so the host decides what the current time and random numbers are.
// The verifier pins them, and the test suite varies them between runs to check
// that a validator does not depend on them (4.4.1.1).
const ENVIRONMENT = `(function(now, seed) {
  const RealDate = Date;
  function FixedDate(...args) {
    if(!new.target) {
      return new RealDate(now).toString();
    }
    return args.length === 0 ? new RealDate(now) : new RealDate(...args);
  }
  FixedDate.prototype = RealDate.prototype;
  FixedDate.now = () => now;
  FixedDate.parse = RealDate.parse;
  FixedDate.UTC = RealDate.UTC;
  globalThis.Date = FixedDate;
  let state = seed >>> 0;
  Math.random = function() {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
})`;

// Messages QuickJS gives when the memory limit or the stack limit stops the
// code. The sandbox has no InternalError constructor, so an error with that
// name came from the engine. Validator code can make any other error, so its
// message is not enough.
const ENGINE_LIMIT = /out of memory|stack overflow|call stack size exceeded/i;
const ENGINE_ERROR_NAME = 'InternalError';

let quickJSPromise;
function quickJS() {
  quickJSPromise ??= getQuickJS();
  return quickJSPromise;
}

/**
 * Runs one validator in a fresh sandbox.
 *
 * @param {object} options - The run's options.
 * @param {string} options.source - The validator module's source code.
 * @param {object} options.input - `{credential, options}`. The validator's
 *   default export is called as validate(credential, options).
 * @param {number} [options.timeoutMs] - Time limit in milliseconds.
 * @param {number} [options.memoryBytes] - Memory limit in bytes.
 * @param {{now: number, seed: number}} [options.environment] - When given,
 *   Date reports `now` (milliseconds) as the current time, and Math.random is
 *   a generator seeded with `seed`.
 * @returns {Promise<{ok: boolean, result?: any, error?: string,
 *   errorType?: string, limitExceeded?: boolean}>} The validator's result, or
 *   the error it raised or hit. `errorType` is the thrown value's `type`
 *   property, when that is a string. `limitExceeded` is true when the time or
 *   memory limit stopped the validator.
 */
export async function runValidatorInSandbox({
  source,
  input,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  memoryBytes = DEFAULT_MEMORY_BYTES,
  environment
}) {
  const QuickJS = await quickJS();
  const runtime = QuickJS.newRuntime();
  let context;
  const host = {timedOut: false};
  try {
    runtime.setMemoryLimit(memoryBytes);
    runtime.setMaxStackSize(MAX_STACK_BYTES);
    // The host records when its own deadline stops the code. That record, not
    // the error's text, is how a time limit is reported.
    const deadline = shouldInterruptAfterDeadline(Date.now() + timeoutMs);
    runtime.setInterruptHandler(() => {
      const stop = deadline();
      host.timedOut ||= stop;
      return stop;
    });
    runtime.setModuleLoader(name => {
      if(name === VALIDATOR_MODULE) {
        return source;
      }
      throw new Error(`import of "${name}" is not allowed in the sandbox`);
    });
    context = runtime.newContext();

    if(environment) {
      const now = Number(environment.now);
      const seed = Number(environment.seed);
      const setup = context.evalCode(`${ENVIRONMENT}(${now}, ${seed});`);
      if(setup.error) {
        return failure(context, setup.error, host);
      }
      setup.value.dispose();
    }

    const entry = context.evalCode(ENTRY, 'entry.js', {type: 'module'});
    if(entry.error) {
      return failure(context, entry.error, host);
    }
    entry.value.dispose();

    const payload = context.newString(JSON.stringify(input ?? null));
    const fn = context.getProp(context.global, '__runValidator');
    const call = context.callFunction(fn, context.undefined, payload);
    payload.dispose();
    fn.dispose();
    if(call.error) {
      return failure(context, call.error, host);
    }
    // Settle the promise. The sandbox has no timers or I/O, so running the
    // pending jobs either settles it or leaves it pending for good.
    const jobs = runtime.executePendingJobs();
    if(jobs.error) {
      call.value.dispose();
      return failure(context, jobs.error, host);
    }
    const state = context.getPromiseState(call.value);
    call.value.dispose();
    if(state.type === 'pending') {
      return {ok: false, error: 'the validator promise never settled'};
    }
    if(state.type === 'rejected') {
      return failure(context, state.error, host);
    }
    const text = context.getString(state.value);
    state.value.dispose();
    if(text.length > MAX_RESULT_CHARS) {
      return {ok: false, error: 'validator result is too large'};
    }
    const result = text === 'undefined' ? undefined : JSON.parse(text);
    return {ok: true, result};
  } catch(error) {
    const message = String(error?.message ?? error);
    // A host-side exception comes from the engine, never from validator code,
    // so its text can be matched.
    return {
      ok: false, error: message,
      limitExceeded: host.timedOut || ENGINE_LIMIT.test(message)
    };
  } finally {
    context?.dispose();
    runtime.dispose();
  }
}

// The reply for an error raised inside the sandbox: its message, its `type`
// property when that is a string, and whether a limit stopped the code.
function failure(context, handle, host) {
  const typeHandle = context.typeof(handle) === 'object' ?
    context.getProp(handle, 'type') : undefined;
  const type = typeHandle && context.typeof(typeHandle) === 'string' ?
    context.getString(typeHandle) : undefined;
  typeHandle?.dispose();
  const error = context.dump(handle);
  handle.dispose();
  const message = error && typeof error === 'object' && 'message' in error ?
    String(error.message) : String(error);
  const name = error && typeof error === 'object' ? error.name : undefined;
  const reply = {ok: false, error: message};
  if(type !== undefined) {
    reply.errorType = type;
  }
  const engineLimit = type === undefined && name === ENGINE_ERROR_NAME &&
    ENGINE_LIMIT.test(message);
  if(host.timedOut || engineLimit) {
    reply.limitExceeded = true;
  }
  return reply;
}
