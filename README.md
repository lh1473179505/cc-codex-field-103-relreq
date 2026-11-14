# relreq

Response HTTP Message Signatures (RFC 9421) bound to a request signature with `related-request`, plus Content-Digest (RFC 9530), over JSON exchanges.

`python -m relreq inspect --exchange fixtures/exchanges/ok-200.json` already prints the request target, status, and signature headers. `verify` and `sign` are still stubs.

Standard library only. No Docker, no live HTTP, no third-party signing libraries.
