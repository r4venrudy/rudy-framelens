package framing

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"testing"
)

const plain = "POST /submit?private=demo HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
const chunked = "POST /submit?private=demo HTTP/1.1\r\nHost: example.invalid\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2;note=\"invented\\\"value\"\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"

func TestPolicies(t *testing.T) {
	valid := []string{"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n", "GET / HTTP/1.0\r\n\r\n", "OPTIONS * HTTP/1.1\r\nHost: example.invalid\r\n\r\n", "GET http://example.invalid/path HTTP/1.1\r\nHost: example.invalid\r\n\r\n", plain, chunked, "POST / HTTP/1.1\r\nHost: example.invalid\r\nTransfer-Encoding: Chunked\r\nTrailer: X-Checksum\r\n\r\n1\r\nx\r\n00;end=yes\r\nX-Checksum: demo\r\n\r\n"}
	for i, input := range valid {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := Analyze(strings.NewReader(input), DefaultLimits())
			if !got.Complete || len(got.Messages) != 1 || got.Messages[0].End != int64(len(input)) {
				t.Fatalf("%+v", got)
			}
			reader := bufio.NewReader(strings.NewReader(input))
			oracle, err := http.ReadRequest(reader)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(oracle.Body)
			if err != nil {
				t.Fatal(err)
			}
			oracle.Body.Close()
			sum := sha256.Sum256(body)
			if got.Messages[0].BodySHA256 != hex.EncodeToString(sum[:]) || got.Messages[0].Method != oracle.Method {
				t.Fatal("standard-library oracle differs")
			}
		})
	}
	cases := []struct{ input, code string }{
		{"GET / HTTP/1.1\nHost: x\n\n", "bare-lf"}, {"GET / HTTP/1.1\r\n\r\n", "host-policy"},
		{"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "host-policy"}, {"GET / HTTP/1.1\r\nHost : a\r\n\r\n", "field-name"},
		{"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", "field-name"}, {"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n", "field-control"},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", "repeated-length"},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0, 0\r\n\r\n", "invalid-length"},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\nx", "invalid-length"},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 9223372036854775808\r\n\r\n", "invalid-length"},
		{"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", "te-cl-conflict"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "unsupported-transfer-coding"},
		{"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", "version-transfer-coding"},
		{"POST / HTTP/1.1\r\nHost: a\r\nConnection: content-length\r\nContent-Length: 0\r\n\r\n", "connection-framing"},
		{"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid\r\n\r\n", "unsupported-tunnel"},
		{"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n", "unsupported-upgrade"},
		{"PRI * HTTP/2.0\r\n\r\n", "unsupported-version"}, {"GET /#fragment HTTP/1.1\r\nHost: a\r\n\r\n", "request-target"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!\n0\r\n\r\n", "chunk-data-crlf"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0x1\r\nx\r\n0\r\n\r\n", "invalid-chunk-size"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Unannounced: demo\r\n\r\n", "forbidden-trailer"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n0\r\n\r\n", "forbidden-trailer"},
		{"POST / HTTP/1.1\r\nHost: a\r\nTrailer: X-Demo\r\n\r\n", "trailer-without-chunked"},
	}
	for i, c := range cases {
		t.Run("reject-"+fmt.Sprint(i), func(t *testing.T) {
			got := Analyze(strings.NewReader(c.input), DefaultLimits())
			if got.Complete || got.Problem == nil || got.Problem.Code != c.code {
				t.Fatalf("want %s: %+v", c.code, got)
			}
		})
	}
}

func TestEveryTruncationAndPrefix(t *testing.T) {
	for _, input := range []string{plain, chunked} {
		for cut := 1; cut < len(input); cut++ {
			got := Analyze(strings.NewReader(input[:cut]), DefaultLimits())
			if got.Complete || len(got.Messages) != 0 {
				t.Fatalf("accepted truncation %d", cut)
			}
		}
		prefix := "GET /first HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
		got := Analyze(strings.NewReader(prefix+input[:len(input)-1]), DefaultLimits())
		if got.Complete || got.Summary.Messages != 1 || got.Summary.ValidatedBytes != int64(len(prefix)) {
			t.Fatalf("wrong validated prefix: %+v", got)
		}
	}
}

type segmented struct {
	data []byte
	size int
	eof  bool
}

func (r *segmented) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.size, len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	if r.eof && len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestSegmentationAndHTTPOracle(t *testing.T) {
	random := rand.New(rand.NewSource(3211))
	for trial := 0; trial < 100; trial++ {
		body := make([]byte, random.Intn(500))
		_, _ = random.Read(body)
		fixed := fmt.Sprintf("POST /item%d HTTP/1.1\r\nHost: example.invalid\r\nX-Demo: value\r\nContent-Length: %d\r\n\r\n", trial, len(body)) + string(body)
		var encoded strings.Builder
		fmt.Fprintf(&encoded, "POST /item%d HTTP/1.1\r\nHost: example.invalid\r\nX-Demo: value\r\nTransfer-Encoding: chunked\r\n\r\n", trial)
		for offset := 0; offset < len(body); {
			n := min(1+random.Intn(30), len(body)-offset)
			fmt.Fprintf(&encoded, "%x\r\n%s\r\n", n, body[offset:offset+n])
			offset += n
		}
		encoded.WriteString("0\r\n\r\n")
		a := Analyze(strings.NewReader(fixed), DefaultLimits())
		b := Analyze(strings.NewReader(encoded.String()), DefaultLimits())
		if !a.Complete || !b.Complete || a.Messages[0].ProjectionSHA256 != b.Messages[0].ProjectionSHA256 || a.Messages[0].WireSHA256 == b.Messages[0].WireSHA256 {
			t.Fatalf("projection mismatch at %d", trial)
		}
		oracle, err := http.ReadRequest(bufio.NewReader(strings.NewReader(encoded.String())))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(oracle.Body)
		oracle.Body.Close()
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("independent HTTP decoder mismatch")
		}
		for size := 1; size <= 17; size++ {
			got := Analyze(&segmented{[]byte(encoded.String()), size, true}, DefaultLimits())
			if !got.Complete || got.Messages[0].ProjectionSHA256 != b.Messages[0].ProjectionSHA256 {
				t.Fatalf("segmentation affected framing: %d/%d", trial, size)
			}
		}
	}
	// Exercise the direct buffered-reader path with an EOF attached to the final data read.
	body := strings.Repeat("z", 65536)
	input := fmt.Sprintf("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	got := Analyze(&segmented{[]byte(input), len(input), true}, DefaultLimits())
	if !got.Complete {
		t.Fatalf("EOF attached to complete body: %+v", got.Problem)
	}
	// Align the final read exactly to bufio's direct-read threshold.
	header := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 65500\r\n\r\n"
	length := 65536 - len(header)
	input = fmt.Sprintf("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", length, strings.Repeat("x", length))
	got = Analyze(&segmented{[]byte(input), len(input), true}, DefaultLimits())
	if !got.Complete {
		t.Fatalf("direct-read EOF attached to complete body: %+v", got.Problem)
	}
}

func TestChunkGrammarAndBudgets(t *testing.T) {
	for _, value := range []string{"1", "000", "a;flag", "1 ; name = token", "1;a=\"escaped\\\"value\""} {
		if _, ok := chunkSize(value); !ok {
			t.Fatal(value)
		}
	}
	for _, value := range []string{"", "-1", "+1", "0x1", "1 ", "1;", "1;x=", "1;x=\"unfinished", "8000000000000000", "1;x=\"\x00\""} {
		if _, ok := chunkSize(value); ok {
			t.Fatal(value)
		}
	}
	l := DefaultLimits()
	l.MaxBodyBytes = 4
	if Analyze(strings.NewReader(plain), l).Problem.Code != "body-budget" {
		t.Fatal("body limit")
	}
	l = DefaultLimits()
	l.MaxMessages = 1
	if Analyze(strings.NewReader(plain+plain), l).Problem.Code != "message-budget" {
		t.Fatal("message limit")
	}
	l = DefaultLimits()
	l.MaxChunks = 1
	if Analyze(strings.NewReader(chunked), l).Problem.Code != "chunk-budget" {
		t.Fatal("chunk limit")
	}
	l = DefaultLimits()
	l.MaxInputBytes = 8
	if Analyze(strings.NewReader(plain), l).Problem.Code != "input-budget" {
		t.Fatal("input limit")
	}
	l = DefaultLimits()
	l.MaxBodyBytes = -1
	if Analyze(strings.NewReader(plain), l).Problem.Code != "invalid-limits" {
		t.Fatal("invalid limit")
	}
}

func TestComparisonPrerequisitesAndPrivacy(t *testing.T) {
	a := Analyze(strings.NewReader(plain), DefaultLimits())
	b := Analyze(strings.NewReader(chunked), DefaultLimits())
	r := Compare(a, b, 100)
	if !r.Comparable || r.ProjectionEqual == nil || !*r.ProjectionEqual || r.WireOnly != 1 {
		t.Fatalf("%+v", r)
	}
	bad := Analyze(strings.NewReader(plain[:len(plain)-1]), DefaultLimits())
	r = Compare(a, bad, 100)
	if r.Comparable || r.ProjectionEqual != nil {
		t.Fatal("incomplete stream became equivalent")
	}
	r = Compare(Display(Analyze(strings.NewReader(plain+plain), DefaultLimits()), 1), a, 100)
	if r.Comparable {
		t.Fatal("display truncation became complete comparison")
	}
	for _, format := range []string{"json", "text", "html"} {
		data, err := Render(a, format)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{"private=demo", "example.invalid", "hello", "text/plain"} {
			if bytes.Contains(data, []byte(raw)) {
				t.Fatalf("raw value leaked: %s", raw)
			}
		}
		if format == "html" && bytes.Contains(data, []byte("<script")) {
			t.Fatal("script in offline report")
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, seed := range []string{plain, chunked, "", "GET / HTTP/1.1\n\n", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999999999999999999\r\n\r\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			t.Skip()
		}
		limits := DefaultLimits()
		limits.MaxInputBytes = 65536
		limits.MaxBodyBytes = 65536
		limits.MaxMessages = 100
		limits.MaxChunks = 1000
		got := Analyze(bytes.NewReader(input), limits)
		var last int64
		for _, m := range got.Messages {
			if m.Start != last || m.End <= m.Start || m.End > int64(len(input)) || m.HeaderEnd > m.End {
				t.Fatal("invalid frame range")
			}
			last = m.End
		}
		if last != got.Summary.ValidatedBytes {
			t.Fatal("prefix summary")
		}
		if got.Complete && last != int64(len(input)) {
			t.Fatal("complete capture left bytes")
		}
	})
}
