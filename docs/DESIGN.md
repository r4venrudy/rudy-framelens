# Byte boundaries and projection identities

The core uses a buffered reader with a logical consumed-byte cursor. Buffered lookahead does not advance evidence offsets or wire hashes. Each completed request records a half-open wire range, its header boundary, framing mode, decoded length and scoped hashes. Payloads are streamed through bounded buffers; raw bodies are never accumulated for reporting. Chunk traces identify chunk-line starts, payload starts, decoded lengths and final wire ends.

Line, field, header, trailer, request, body and capture-wide chunk budgets have separate meanings. Checked decimal/hexadecimal accumulation prevents integer wrap before lengths are used. Per-message chunk traces and distinct field names are retained only up to fixed limits with omission counts. Full validation and summaries are independent of display limits.

The file wrapper requires a regular, non-symlink path, bounds the opened file's size, hashes the opened file, parses a section reader, then rechecks its length and whole-file digest. It does not reopen names found in captures. Source stability during this run is not proof of a consistent upstream acquisition or protection against every hostile path-substitution race.

## Hash scopes

- Whole-file SHA-256 identifies the entire capture, including an unparsed suffix.
- Wire SHA-256 identifies exactly one completed request's captured bytes.
- Body SHA-256 identifies transfer-decoded bytes after chunk framing removal; Content-Encoding is not decompressed.
- Target SHA-256 identifies the request-target bytes without URI canonicalization.
- Header/trailer digests use length-prefixed name/value pairs. Names are lowercased and sorted stably; same-name order remains significant. Value OWS is trimmed. Content-Length and Transfer-Encoding are omitted only from the header projection.
- Projection SHA-256 uses a versioned domain and length-prefixed method, HTTP version, target identity, header identity, trailer identity and body identity. This prevents delimiter ambiguity and keeps trailers distinct.

Comparison aligns ordinals. Added/removed/modified projections reach the explicit changed gate; equal projections with different wire hashes are wire-only observations. Any incomplete or display-truncated input makes a core comparison unavailable. The CLI compares full captures before display truncation. Unavailable equality is null, never true.

Reports use Go's JSON encoder and HTML templates. The HTML page has native expandable evidence, no JavaScript or external resources, and a restrictive CSP. Output files are created exclusively. A partial newly created report can remain after a write failure; exit status remains authoritative.
