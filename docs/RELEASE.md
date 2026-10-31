Rudy FrameLens is a native Go offline HTTP/1 request-framing investigation and regression tool.

- Bounded streaming parser for a versioned conservative request profile: fixed-length, chunked, trailers, strict line/field syntax and explicit unsupported modes.
- Request/header/body/chunk offsets, validated prefixes, scoped SHA-256 identities and omitted-evidence counts.
- Positional request projection comparisons with separate wire-only changes and fail-closed incomplete-input gates.
- Offline RUDY HTML/JSON/text, standard-library HTTP decoder oracles, randomized/fragmented/truncated cases, independent CLI tests, bounded fuzzing and cross-platform/race CI.

Native packages contain one command, invented captures with expected results, generated reports, documentation and Go notices. No language runtime or credentials are needed. Targets are Linux x64, Windows x64 and macOS ARM64; older OS compatibility is unverified. Check SHA256SUMS.txt before extraction.

Developer preview. Inputs must already be decrypted/reassembled request streams. This profile is deliberately stricter than some permitted/tolerated HTTP forms and does not model a named proxy/server or prove a vulnerability. Raw payload/field values are omitted, but hashes and metadata can still be identifying. Read the profile and report contracts before using CI gates.
