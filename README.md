# @digitalbazaar/vc-recognized-entities

Recognition validation and discovery for
[VC Recognized Entities v1.0](https://www.w3.org/TR/vc-recognized-entities-1.0/).

## Status

Early. The core algorithms are implemented and tested. The HTTP verifier and
the test-suite integration are not written yet.

## What it provides

- `discoverCredentialChain` (Section 4.1): follows `recognizedIn` references
  from a credential toward an anchor.
- `discoverIdentifierChains` (Section 4.2): resolves the issuer identifier,
  fetches the WhoisService presentation, and returns candidate chains.
- `validateRecognition` (Section 4.3): returns `{recognized, actionRecognized}`
  for a chain.
- `ProblemDetailsError` and the error type URLs (Section 4.4).

The functions are pure. The caller supplies the network and identity steps:

- `fetchCredential(url)`: applies the retrieval policy. Throw to signal failure.
- `resolveIdentifier(did)`: returns the controlled identifier document.
- `verifyPresentation(presentation, issuerId)`: verifies the proof and that it is
  bound to `issuerId`.
- `validateOutputValidation(credential, schema)`: checks a credential against one
  data schema. Required when a recognized action declares `outputValidation`.

Credentials are assumed to have been verified individually (Section 4).

## Open questions

These follow the current spec text. See the issues filed against
w3c/vc-recognized-entities:

- A credential issued directly by an anchor is reported as not recognized
  (w3c/vc-recognized-entities#157).
- A failed presentation fetch returns no chains in Section 4.2, even though
  Section 4.4 lists it under RETRIEVAL_ERROR.
- The same depth limit raises an error in discovery and returns a false result
  in recognition validation.

## Development

```sh
npm install
npm test
npm run lint
```
