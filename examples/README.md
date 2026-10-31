# Invented request streams

`make_capture.py NEW_DIRECTORY` creates seven synthetic captures and expected JSON without opening any connection. `fixed.http` and `chunked.http` carry the same projection using different framing. `changed.http` changes a body byte. `pipeline.http` adds a second request, while `incomplete.http` ends inside that request. `conflict.http` intentionally contains framing fields rejected by the profile. `trailers.http` uses a declared synthetic checksum trailer.

All hostnames use `.invalid`; bodies, query text and field values are invented. Expected values include whole-file/body SHA-256, decoded body size, fixed header boundary and the first completed request's end. Release packages also include generated JSON and HTML from the native command. Source checkouts generate captures into a new directory under `artifacts/`.
