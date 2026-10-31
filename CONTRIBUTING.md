# Contributing

Describe the concrete byte-boundary or report-contract problem and add the smallest invented capture that reproduces it. Keep the framing core in Go and avoid external dependencies unless functionality requires one. Validate arithmetic, limits, prefix handling and unknown outcomes before making an acceptance/equality claim.

Run `go test ./...`, `go vet ./...` and the independent Python CLI suite. Use standard-library decoder oracles only for the supported shared subset; profile-restricted inputs must be labeled explicitly. Keep read segmentation irrelevant to parser results. Never add live target tests, real credentials/traffic, generated release binaries, or product-specific exploitability claims without evidence.
