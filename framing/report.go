package framing

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
)

const reportHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Rudy FrameLens / request framing</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#090f17;color:#edf4ff;font:15px/1.65 system-ui,sans-serif}main{max-width:1160px;margin:36px auto;padding:24px}header{border-left:4px solid #55e0b6;padding:24px 30px;background:linear-gradient(110deg,#101e2b,#0b121c)}small{font:12px monospace;letter-spacing:2px;color:#55e0b6}h1{font-size:clamp(38px,6vw,64px);line-height:1.1;letter-spacing:-2px;margin:18px 0}p,footer{color:#9fb3c9}.cards{display:flex;flex-wrap:wrap;gap:16px;margin:28px 0}.card{flex:1;min-width:190px;padding:20px;background:#101b28;border:1px solid #2c3f54;border-radius:10px}.card strong{display:block;font-size:32px;color:#55e0b6}.notice{border-left:3px solid #d3a56d;background:#272017;padding:14px 20px;color:#f1ca9a}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:12px;border-bottom:1px solid #26394b;vertical-align:top}th{color:#9fb3c9}code{font-size:12px}details{border:1px solid #2b3d51;padding:16px 20px;border-radius:10px;margin:24px 0}summary{cursor:pointer;font-weight:650}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:640px;overflow:auto;font:12px/1.6 ui-monospace,monospace;background:#070d14;padding:18px}footer{border-top:1px solid #26394b;margin-top:30px;padding-top:20px;font-size:13px}</style><main><header><small>RUDY SYSTEMS / HTTP FRAMING INVESTIGATIONS</small><h1>Rudy FrameLens</h1><p>Follow every boundary. Keep the payload private.</p></header><h2>{{.Title}}</h2>{{if .Capture}}<div class="cards"><div class="card">Validated requests<strong>{{.Capture.Summary.Messages}}</strong></div><div class="card">Validated prefix bytes<strong>{{.Capture.Summary.ValidatedBytes}}</strong></div><div class="card">Decoded body bytes<strong>{{.Capture.Summary.DecodedBodyBytes}}</strong></div><div class="card">Chunked requests<strong>{{.Capture.Summary.ChunkedMessages}}</strong></div></div>{{if .Capture.Problem}}<p class="notice">Stopped at byte {{.Capture.Problem.Offset}}: {{.Capture.Problem.Code}}. {{.Capture.Problem.Reason}} The excluded suffix has not been treated as valid request traffic.</p>{{end}}<h2>Request boundaries</h2><div class="scroll"><table><tr><th>Request</th><th>Method / form</th><th>Wire range</th><th>Framing</th><th>Body bytes</th><th>Data chunks</th></tr>{{range .Capture.Messages}}<tr><td>{{.Ordinal}}</td><td>{{.Method}} / {{.TargetForm}}</td><td><code>[{{.Start}}, {{.End}})</code></td><td>{{.Framing}}</td><td>{{.DecodedBodyBytes}}</td><td>{{.ChunkCount}}</td></tr>{{end}}</table></div><p>Omitted request rows: {{.Capture.OmittedMessages}}. Summary totals cover every validated request.</p>{{end}}{{if .Comparison}}<div class="cards"><div class="card">Added<strong>{{.Comparison.Added}}</strong></div><div class="card">Removed<strong>{{.Comparison.Removed}}</strong></div><div class="card">Projection changes<strong>{{.Comparison.Modified}}</strong></div><div class="card">Wire-only changes<strong>{{.Comparison.WireOnly}}</strong></div></div>{{if not .Comparison.Comparable}}<p class="notice">Comparison is unavailable because an input is incomplete or outside the profile. Zero change counts are not an equality result.</p>{{end}}<div class="scroll"><table><tr><th>Ordinal</th><th>Observation</th><th>Before projection</th><th>After projection</th></tr>{{range .Comparison.Changes}}<tr><td>{{.Ordinal}}</td><td>{{.Kind}}</td><td><code>{{.BeforeProjection}}</code></td><td><code>{{.AfterProjection}}</code></td></tr>{{end}}</table></div><p>Omitted change rows: {{.Comparison.OmittedChanges}}.</p>{{end}}<p class="notice">This is a conservative request-framing profile, not a prediction of any proxy/server, a complete HTTP validator, or proof of request smuggling. Projection equality covers only the documented normalization.</p><details><summary>Structured evidence, offsets, and content identities</summary><pre>{{.JSON}}</pre></details><details><summary>Interpretation boundaries</summary><p>Requests must already be reassembled and decrypted in one directional byte stream. Responses, CONNECT, upgrades, TLS, HTTP/2 and HTTP/3 are not analyzed. Raw targets, header/trailer values, chunk extensions and body bytes are omitted. Hashes, methods, field names and byte sizes can still be identifying.</p></details><footer>Go / standard library only / offline / preview {{.Version}}. No network calls, request replay, or source writes. New-file-only reports; no scripts or external page assets.</footer></main></html>`

func Render(value any, format string) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, errors.New("unable to serialize the report")
	}
	if len(data) > 16<<20 {
		return nil, errors.New("report exceeds the 16 MiB budget")
	}
	switch format {
	case "json":
		return append(data, '\n'), nil
	case "text":
		return append([]byte("Rudy FrameLens / offline request framing\n"), append(data, '\n')...), nil
	case "html":
		page := struct {
			Title, JSON, Version string
			Capture              *Capture
			Comparison           *Comparison
		}{JSON: string(data), Version: Version}
		switch v := value.(type) {
		case Capture:
			page.Title = "Capture investigation"
			page.Capture = &v
		case Comparison:
			page.Title = "Request projection comparison"
			page.Comparison = &v
		default:
			return nil, errors.New("unsupported report type")
		}
		t, err := template.New("report").Parse(reportHTML)
		if err != nil {
			return nil, errors.New("report template could not be parsed")
		}
		var out bytes.Buffer
		if err := t.Execute(&out, page); err != nil {
			return nil, errors.New("report could not be rendered")
		}
		if out.Len() > 16<<20 {
			return nil, errors.New("report exceeds the 16 MiB budget")
		}
		return out.Bytes(), nil
	default:
		return nil, errors.New("unsupported report format")
	}
}
