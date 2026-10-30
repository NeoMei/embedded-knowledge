# Managed search recovery contract

Search result lookup accepts the ordinary signed `SETTLED` result. An input-bound lookup may also receive exactly `{ "not_submitted_assertion": "..." }`; it cannot combine that assertion with settled content or other fields.

The dedicated Ed25519 envelope domain is `weknora-search-not-submitted-v1`. Its claims bind the complete durable `SearchBinding`, issuer, audience, fresh callback nonce, original call ID, model, operation, wire operation, SHA256 of the exact original provider input, and status `NOT_SUBMITTED`. Its issued/expires window is at most 30 seconds. Legacy bindings, malformed or mixed responses, ordinary HTTP failures, timeouts, unknown outcomes and invalid assertions never authorize submission.

`SearchResult` remains a settled-result-only API. `SearchResultForInput` supplies the original input digest and returns `ErrSearchNotSubmitted` only after verifying this dedicated assertion. The service first performs the ordinary read-only journal recovery. If that read returns verified absence, it rechecks live host authority and the unchanged `DISPATCHED` journal call, submits that original call once through the host's exclusive durable claim, then performs another read-only recovery to save `COMPLETED`. It never resets a journal record or invents a new call. Concurrent callers rely on the host's exact-record exclusive claim; that host must persist its claim before grant or provider submission.

Only `/internal/knowledge-work/dispatch` and `/internal/knowledge-search/dispatch` callbacks allow 120 seconds. Authorization, snapshot and result callbacks retain 5 seconds. Search/request assertions still expire under their original short windows. If work finishes after the delivery proof expires, a fresh request proof for the same logical work may recover the already completed operations; it does not replay provider requests.

An expired local search payload is different from an unsubmitted call. The
journal keeps its original ownership tombstone after clearing that payload.
Search can invoke the explicit `RecoverExpired` API only with the same complete
scope/input/call and a fresh, authenticated host `SETTLED` result. It rechecks
current search authority before and after that read and re-encrypts the result
with a cache deadline bounded by the live capability and retention. This path
never accepts an absence assertion or submits a provider request. Ordinary
`Recover` remains limited to `DISPATCHED`. If the host no longer retains an
accessible signed result, expired recovery fails closed without changing the
original row; it cannot reconstruct the result by calling the model again.
