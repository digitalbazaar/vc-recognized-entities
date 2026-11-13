/*
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */

// Runs one JSON Schema against a credential, in a worker thread, so that
// validateSchemaInWorker can end it when the time limit runs out. The schema's
// $schema decides the draft: 2020-12 uses Ajv 2020, and anything else uses the
// default draft (draft-07).

import {parentPort, workerData} from 'node:worker_threads';
import Ajv from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';

const SCHEMA_2020_12 = 'https://json-schema.org/draft/2020-12/schema';

try {
  const schema = JSON.parse(workerData.text);
  const Engine = schema?.$schema === SCHEMA_2020_12 ? Ajv2020 : Ajv;
  const ajv = new Engine({strict: false, allErrors: false});
  parentPort.postMessage({
    ok: true,
    valid: ajv.validate(schema, workerData.credential) === true
  });
} catch(error) {
  parentPort.postMessage({ok: false, error: error.message});
}
