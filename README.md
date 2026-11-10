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

Discovery verifies the proof on every credential it adds to a chain, including
credentials the holder provided. It uses the caller's signature suites and
document loader, as the bitstring status list library does:

- `suite`: an array of Data Integrity suites for verification, such as
  eddsa-jcs-2022. Required when `verifyProofs` is true (the default).
- `documentLoader(url)`: loads contexts, DID documents, and verification
  methods. Required when `verifyProofs` is true.
- `verifyProofs`: set to `false` only for credentials that were verified
  elsewhere. A failed proof raises `CRYPTOGRAPHIC_SECURITY_ERROR`.

The functions do no network or I/O of their own. The caller also supplies:

- `fetchCredential(url)`: fetches a credential, and applies the retrieval
  policy. Throw to signal failure.
- `resolveIdentifier(did)`: returns the controlled identifier document.
- `verifyPresentation(presentation, issuerId)`: returns true when the
  presentation's proof verifies and is bound to `issuerId`. Discovery verifies
  the credentials inside the presentation separately.
- `validateOutputValidation(credential, schema)`: returns true when the
  credential conforms to one data schema. Required when a recognized action
  declares `outputValidation`.

The target credential is the caller's input. Verify its proof before calling
discovery.

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
