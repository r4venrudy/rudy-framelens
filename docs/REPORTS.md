# Report contracts v1

Inspection schema: `rudy-framelens/inspection-v1`. Comparison schema: `rudy-framelens/comparison-v1`. Both carry the tool version and profile identifier.

For file inspection, `bytes` and `sha256` cover the entire source and `sourceRechecked` records the post-parse digest/size check. `complete` means every captured byte fits this profile. `summary.validatedBytes` is the end of the last completed request, not the furthest byte examined. `problem` is null on completion; otherwise it contains a static code/reason and detection cursor or the offending message start for a cross-field policy decision. It does not necessarily locate a uniquely causal byte.

Every completed request has ordinal, start/headerEnd/end offsets, method/version/target form, hash scopes, framing mode, decoded byte count, field counts/names and retained data-chunk traces. All byte ranges are relative to the input and end-exclusive. Header/trailer values, targets, extensions, body bytes and filenames are absent. Name/chunk/message omissions are explicit; digests and summary counts still use the complete validated data.

Comparison has two whole-input identities, message counts and nullable source problems. `comparable: false` and `projectionEqual: null` mean equality is unavailable. Counts must not be read as a clear result in that state. Comparable changes are ordinal `added`, `removed`, `modified` or `wire-only` observations, with projection/body identities and explicit omitted-change totals. Equal projections can have different wire boundaries and transport framing. A malformed input always produces exit 2 when a report can be generated.

CLI file limits and aggregate prefixes fit safe JSON integer ranges under the declared 2 GiB input bound. SHA-256 digests are byte identities, not signatures, anonymization or proof that traffic belongs to an authentic connection. Methods, field names, hashes and lengths can still be sensitive.
