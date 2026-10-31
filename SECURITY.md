# Security boundaries

FrameLens reads authorized stable offline files. It does not dial hosts, replay requests, obtain credentials, decrypt TLS, reconstruct PCAP/TCP streams, run captured code or model an actual proxy. Inspecting a conservative profile is not a vulnerability finding or a promise of how any service will frame traffic.

Byte/count/metadata/report limits bound the supported workload. Files are checked as regular non-symlink inputs and hashed before/after parsing. This is not an OS sandbox or acquisition protocol; analyze copies stored in a trusted directory. No input paths are interpreted as URLs or opened from captured field values.

Reports omit raw targets, values, chunk extensions and bodies. Field names, methods, hashes and sizes can still reveal information or support dictionary guesses; hashing is not anonymization. Source fixtures and releases use invented data only. Never send real captured credentials or traffic in a public issue; provide a minimal synthetic reproducer or use private GitHub vulnerability reporting.

Malformed, unsupported, incomplete and over-budget inputs fail closed. An unavailable comparison has nullable equality. Existing outputs cannot be overwritten, but I/O failures can leave a partial new report. Always check the exit status and report completeness.
