# Preview validation

Go tests use the independent standard-library net/http request decoder for supported captures and randomized chunked/fixed bodies. One hundred deterministic binary-body cases check projection equality, body bytes and 17 fragmented-reader sizes each. Representative requests are truncated at every byte. Tests cover exact prefixes, EOF with data, chunk grammar, framing/Host conflicts, malformed field controls, unsupported modes, arithmetic/budget edges, comparison prerequisites and report privacy. CLI unit tests exercise flags, output refusal, Unicode paths and unavailable comparisons.

The native fuzz target accepts bounded byte slices and checks parser termination/range/prefix invariants. A local ten-second smoke completed 117,455 executions without a failure. CI adds a bounded Linux fuzz run and race detection. This is smoke evidence, not an exhaustive fuzzing campaign or a production performance measurement.

Python standard-library black-box checks independently generate seven invented wire captures, expected file/body digests and byte boundaries. They exercise the compiled/installed command, chunk offsets, wire-only versus changed gates, malformed suffixes, private HTML, field/display omissions, source/hard-link preservation, Unicode paths, limits, and POSIX symlink/FIFO/output-mode checks where applicable.

CI validates Linux x64, Windows x64 and macOS ARM64 plus a Linux race job. Tagged packaging depends on validation, runs each native installed command's independent suite, generates synthetic reports and bundles Go licensing. Publication is verified through final-head workflow status, actual downloaded archive hashes, architecture and Windows execution. No real traffic or live network service is used in parser tests.

The tool does not establish behavior of real proxies/servers, protocol conformance beyond the declared subset, exploitable request smuggling, HTTP/2 downgrade behavior, connection-response pairing, TLS capture quality, or safe anonymization. No claim covers every possible valid HTTP extension or malicious filesystem race.
