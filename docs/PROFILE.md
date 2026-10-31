# framelens/strict-request-v1

The profile is a conservative request-only framing contract informed by RFC 9112, not a complete conformance validator or model of a named product. Offsets count captured bytes, not Unicode characters or TCP sequence numbers.

The parser requires exactly separated request-line components, strict CRLF, a token method of at most 64 bytes, HTTP/1.0 or HTTP/1.1, and origin/HTTP(S)-absolute/OPTIONS-asterisk target forms. URI parsing uses Go's standard URI parser after visible-byte and fragment checks. CONNECT and upgrades stop analysis. HTTP/1.1 requires a single nonempty Host; this extra restriction is conservative, especially for absolute-form/context-dependent authority handling. Host authority grammar/equivalence is not fully validated.

Field names use HTTP token syntax, capped at 256 bytes. Whitespace before the colon and obs-fold are rejected. Values may contain SP, HTAB, visible bytes and obs-text; C0 controls other than HTAB and DEL are rejected. SP/HTAB around a field value is trimmed for hashing. Raw values are not reported.

Requests with neither Content-Length nor Transfer-Encoding have zero body length. Content-Length must be a single decimal integer within signed 64-bit and configured body limits. Repeated fields or comma-separated values are rejected even if equal; RFC 9112 permits recovery of some equal-value forms, which this profile deliberately does not implement. TE with CL is rejected instead of choosing a precedence model. Only one `chunked` transfer-coding value without parameters is supported, and only in HTTP/1.1.

Chunk sizes are checked before arithmetic or body reads. Chunk extensions use token/quoted-string syntax with checked quoted-pair controls; unknown extension values are ignored for projection. Data chunks require CRLF afterward. A zero-size chunk ends the data stream; trailers are retained separately and terminate at the final empty CRLF line. Capture-wide chunk budgets include terminal chunks; per-request data-chunk counts do not.

Actual trailers must be declared. The profile rejects declared/actual framing, Host, Connection, Trailer, TE, Upgrade, authorization/cookie, content interpretation/range, cache-control, Max-Forwards and Expect trailer names, plus connection-nominated names. This denylist is a conservative application policy, not a registry of every field that could affect HTTP semantics. Connection options cannot nominate Content-Length, Transfer-Encoding, Host or Trailer. Full field semantics and connection lifecycle are not modeled.

Parsing stops at the first invalid, unsupported, incomplete or over-budget message. It never searches later bytes for a plausible request. Completed requests before that point remain a validated prefix. Failure codes such as `te-cl-conflict`, `repeated-length`, `invalid-chunk-size`, `forbidden-trailer`, `body-budget` and `incomplete-body` explain the decision without identifying a cause or attacker.

Primary reference: [RFC 9112: HTTP/1.1 message framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3), [chunked coding](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1). A proxy/server may reject additional forms or accept forms outside this profile. No differential-vulnerability or exploitability claim follows from this parser's result.
