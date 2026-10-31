package framing

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"math"
	"net/url"
	"strings"
)

const maxLine = 8192
const maxHeaders = 65536
const maxFields = 256
const maxTrailers = 16384

type parser struct {
	reader *bufio.Reader
	offset int64
	limits Limits
	wire   hash.Hash
	chunks int
}

func fail(code string, offset int64, reason string) *Problem { return &Problem{code, offset, reason} }
func tokenByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}
func token(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !tokenByte(s[i]) {
			return false
		}
	}
	return true
}
func ows(s string) string { return strings.Trim(s, " \t") }

func (p *parser) byte() (byte, error) {
	b, err := p.reader.ReadByte()
	if err == nil {
		p.offset++
		if p.wire != nil {
			_, _ = p.wire.Write([]byte{b})
		}
	}
	return b, err
}

func (p *parser) line(limit int, budgetCode string) (string, *Problem) {
	start := p.offset
	data := make([]byte, 0, min(limit, 256))
	for len(data) < limit {
		b, err := p.byte()
		if err != nil {
			return "", fail("incomplete-line", p.offset, "A required CRLF-terminated line was incomplete.")
		}
		data = append(data, b)
		if b == '\n' {
			if len(data) < 2 || data[len(data)-2] != '\r' {
				return "", fail("bare-lf", p.offset-1, "Only CRLF line endings are accepted.")
			}
			return string(data[:len(data)-2]), nil
		}
	}
	return "", fail(budgetCode, start+int64(limit), "A line or metadata section exceeded its byte budget.")
}

func parseField(line string, offset int64) (field, *Problem) {
	i := strings.IndexByte(line, ':')
	if i <= 0 || !token(line[:i]) || i > 256 {
		return field{}, fail("field-name", offset, "A field name was invalid, oversized, folded, or separated from its colon by whitespace.")
	}
	v := line[i+1:]
	for j := range len(v) {
		if v[j] < 32 && v[j] != '\t' || v[j] == 127 {
			return field{}, fail("field-control", offset+int64(i+1+j), "A field value contained a forbidden control byte.")
		}
	}
	return field{strings.ToLower(line[:i]), ows(v)}, nil
}

func (p *parser) fields(start int64, budget, count int) ([]field, *Problem) {
	fields := []field{}
	for {
		remaining := int64(budget) - (p.offset - start)
		if remaining <= 0 {
			return nil, fail("metadata-budget", p.offset, "Header or trailer metadata exceeded its byte budget.")
		}
		offset := p.offset
		code := "line-budget"
		if remaining < maxLine {
			code = "metadata-budget"
		}
		line, problem := p.line(min(maxLine, int(remaining)), code)
		if problem != nil {
			return nil, problem
		}
		if line == "" {
			return fields, nil
		}
		if len(fields) >= count {
			return nil, fail("field-budget", offset, "The field-count budget was exceeded.")
		}
		f, problem := parseField(line, offset)
		if problem != nil {
			return nil, problem
		}
		fields = append(fields, f)
	}
}

func integer(s string, base uint64) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for i := range len(s) {
		b := s[i]
		var d uint64
		switch {
		case b >= '0' && b <= '9':
			d = uint64(b - '0')
		case base == 16 && b >= 'a' && b <= 'f':
			d = uint64(b-'a') + 10
		case base == 16 && b >= 'A' && b <= 'F':
			d = uint64(b-'A') + 10
		default:
			return 0, false
		}
		if d >= base || n > (math.MaxInt64-d)/base {
			return 0, false
		}
		n = n*base + d
	}
	return int64(n), true
}

// Validate chunk-extension syntax without retaining extension names or values.
func chunkSize(line string) (int64, bool) {
	i := 0
	for i < len(line) && (line[i] >= '0' && line[i] <= '9' || line[i] >= 'a' && line[i] <= 'f' || line[i] >= 'A' && line[i] <= 'F') {
		i++
	}
	n, ok := integer(line[:i], 16)
	if !ok {
		return 0, false
	}
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) || line[i] != ';' {
			return 0, false
		}
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		start := i
		for i < len(line) && tokenByte(line[i]) {
			i++
		}
		if start == i {
			return 0, false
		}
		// BWS without an equals sign belongs to the next semicolon.
		end := i
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) || line[i] != '=' {
			i = end
			continue
		}
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i == len(line) {
			return 0, false
		}
		if line[i] == '"' {
			i++
			closed := false
			for i < len(line) {
				b := line[i]
				i++
				if b == '"' {
					closed = true
					break
				}
				if b == '\\' {
					if i == len(line) {
						return 0, false
					}
					b = line[i]
					i++
					if b != '\t' && (b < 32 || b == 127) {
						return 0, false
					}
				} else if b != '\t' && (b < 32 || b == 127) {
					return 0, false
				}
			}
			if !closed {
				return 0, false
			}
		} else {
			start = i
			for i < len(line) && tokenByte(line[i]) {
				i++
			}
			if start == i {
				return 0, false
			}
		}
	}
	return n, true
}

func (p *parser) body(n int64, h hash.Hash) *Problem {
	buffer := make([]byte, 32768)
	for n > 0 {
		read, err := p.reader.Read(buffer[:min(int64(len(buffer)), n)])
		if read > 0 {
			p.offset += int64(read)
			_, _ = p.wire.Write(buffer[:read])
			_, _ = h.Write(buffer[:read])
			n -= int64(read)
		}
		if n == 0 {
			break
		}
		if err != nil {
			return fail("incomplete-body", p.offset, "The captured body ended before its declared boundary.")
		}
		if read == 0 {
			return fail("input-read", p.offset, "The input did not make progress.")
		}
	}
	return nil
}

func forbiddenTrailer(name string, connection map[string]bool) bool {
	if connection[name] {
		return true
	}
	switch name {
	case "host", "content-length", "transfer-encoding", "connection", "trailer", "te", "upgrade", "authorization", "proxy-authorization", "cookie", "set-cookie", "content-type", "content-encoding", "content-range", "range", "expect", "cache-control", "max-forwards":
		return true
	}
	return false
}

func (p *parser) request(ordinal int) (Message, *Problem) {
	m := Message{Ordinal: ordinal, Start: p.offset, Chunks: []Chunk{}}
	p.wire = sha256.New()
	line, problem := p.line(maxLine, "line-budget")
	if problem != nil {
		return m, problem
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !token(parts[0]) || len(parts[0]) > 64 {
		return m, fail("request-line", m.Start, "Expected a bounded method, one SP, request target, one SP, and supported HTTP version.")
	}
	m.Method, m.HTTPVersion = parts[0], parts[2]
	if m.HTTPVersion != "HTTP/1.1" && m.HTTPVersion != "HTTP/1.0" {
		return m, fail("unsupported-version", m.Start, "Only HTTP/1.0 and HTTP/1.1 request streams are supported.")
	}
	if m.Method == "CONNECT" {
		return m, fail("unsupported-tunnel", m.Start, "CONNECT tunnels are outside this request-stream profile.")
	}
	target := parts[1]
	for i := range len(target) {
		if target[i] < 33 || target[i] > 126 || target[i] == '#' {
			return m, fail("request-target", m.Start+int64(len(m.Method)+1+i), "Request targets must use visible URI bytes without fragments.")
		}
	}
	if target == "*" && m.Method == "OPTIONS" {
		m.TargetForm = "asterisk"
	} else {
		u, err := url.ParseRequestURI(target)
		if err != nil || u.User != nil {
			return m, fail("request-target", m.Start, "The request target was outside the supported URI forms.")
		}
		if strings.HasPrefix(target, "/") {
			m.TargetForm = "origin"
		} else if (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			m.TargetForm = "absolute"
		} else {
			return m, fail("request-target", m.Start, "Only origin, HTTP(S) absolute, or OPTIONS asterisk targets are supported.")
		}
	}
	m.TargetSHA256 = digest(target)
	fields, problem := p.fields(m.Start, maxHeaders, maxFields)
	if problem != nil {
		return m, problem
	}
	m.HeaderEnd = p.offset
	var cl, te, host []string
	declared := map[string]bool{}
	connection := map[string]bool{}
	for _, f := range fields {
		switch f.name {
		case "content-length":
			cl = append(cl, f.value)
		case "transfer-encoding":
			te = append(te, f.value)
		case "host":
			host = append(host, f.value)
		case "upgrade":
			return m, fail("unsupported-upgrade", m.Start, "Protocol upgrades are outside this profile.")
		}
		if f.name == "connection" {
			for _, value := range strings.Split(f.value, ",") {
				name := strings.ToLower(ows(value))
				if !token(name) {
					return m, fail("connection-token", m.Start, "A connection-option token was invalid.")
				}
				connection[name] = true
				if name == "upgrade" {
					return m, fail("unsupported-upgrade", m.Start, "Protocol upgrades are outside this profile.")
				}
			}
		}
		if f.name == "trailer" {
			for _, value := range strings.Split(f.value, ",") {
				name := strings.ToLower(ows(value))
				if !token(name) || len(declared) >= 64 {
					return m, fail("trailer-declaration", m.Start, "Trailer declarations must contain bounded field-name tokens.")
				}
				declared[name] = true
			}
		}
	}
	if len(host) > 1 || m.HTTPVersion == "HTTP/1.1" && (len(host) != 1 || host[0] == "") {
		return m, fail("host-policy", m.Start, "This profile requires one nonempty Host in HTTP/1.1 and rejects repeated Host fields.")
	}
	for _, v := range host {
		for i := range len(v) {
			if v[i] <= 32 || v[i] >= 127 || v[i] == ',' {
				return m, fail("host-policy", m.Start, "Host values must be visible ASCII without internal whitespace or commas.")
			}
		}
	}
	if len(cl) > 0 && len(te) > 0 {
		return m, fail("te-cl-conflict", m.Start, "Transfer-Encoding together with Content-Length is rejected by this conservative profile.")
	}
	for _, name := range []string{"content-length", "transfer-encoding", "host", "trailer"} {
		if connection[name] {
			return m, fail("connection-framing", m.Start, "Connection options must not nominate framing, Host, or Trailer fields in this profile.")
		}
	}
	if len(cl) > 1 {
		return m, fail("repeated-length", m.Start, "Repeated Content-Length fields are rejected even when values agree.")
	}
	if len(te) > 1 || len(te) == 1 && !strings.EqualFold(te[0], "chunked") {
		return m, fail("unsupported-transfer-coding", m.Start, "Only a single unparameterized chunked transfer coding is supported.")
	}
	if len(te) > 0 && m.HTTPVersion != "HTTP/1.1" {
		return m, fail("version-transfer-coding", m.Start, "Transfer coding in HTTP/1.0 is outside this profile.")
	}
	for name := range declared {
		if forbiddenTrailer(name, connection) {
			return m, fail("forbidden-trailer", m.Start, "A forbidden or connection-nominated trailer was declared.")
		}
	}
	if len(declared) > 0 && len(te) == 0 {
		return m, fail("trailer-without-chunked", m.Start, "Trailer declarations require chunked framing in this profile.")
	}
	body := sha256.New()
	trailers := []field{}
	m.Framing = "none"
	if len(cl) == 1 {
		n, ok := integer(cl[0], 10)
		if !ok {
			return m, fail("invalid-length", m.Start, "Content-Length must be one nonnegative decimal integer within signed 64-bit bounds.")
		}
		if n > p.limits.MaxBodyBytes {
			return m, fail("body-budget", m.HeaderEnd, "The declared body exceeds the decoded-body byte budget.")
		}
		m.Framing = "content-length"
		if problem := p.body(n, body); problem != nil {
			return m, problem
		}
		m.DecodedBodyBytes = n
	}
	if len(te) == 1 {
		m.Framing = "chunked"
		for {
			start := p.offset
			chunkLine, problem := p.line(4096, "chunk-line-budget")
			if problem != nil {
				return m, problem
			}
			n, ok := chunkSize(chunkLine)
			if !ok {
				return m, fail("invalid-chunk-size", start, "The chunk size or extension syntax was invalid or overflowed.")
			}
			p.chunks++
			if p.chunks > p.limits.MaxChunks {
				return m, fail("chunk-budget", start, "The capture-wide chunk-count budget was exceeded.")
			}
			if n == 0 {
				trailers, problem = p.fields(p.offset, maxTrailers, 64)
				if problem != nil {
					return m, problem
				}
				break
			}
			if n > p.limits.MaxBodyBytes-m.DecodedBodyBytes {
				return m, fail("body-budget", start, "The decoded chunked body exceeds its byte budget.")
			}
			c := Chunk{LineStart: start, DataStart: p.offset, Bytes: n}
			if problem := p.body(n, body); problem != nil {
				return m, problem
			}
			for _, expected := range []byte{'\r', '\n'} {
				b, err := p.byte()
				if err != nil || b != expected {
					return m, fail("chunk-data-crlf", p.offset, "Chunk data was not followed by the required CRLF.")
				}
			}
			c.WireEnd = p.offset
			m.ChunkCount++
			m.DecodedBodyBytes += n
			if len(m.Chunks) < 32 {
				m.Chunks = append(m.Chunks, c)
			} else {
				m.OmittedChunks++
			}
		}
		for _, f := range trailers {
			if forbiddenTrailer(f.name, connection) || !declared[f.name] {
				return m, fail("forbidden-trailer", m.Start, "Trailers must be declared and must not alter framing, routing, authentication, or connection-nominated fields.")
			}
		}
	}
	m.End = p.offset
	m.BodySHA256 = hexHash(body)
	m.WireSHA256 = hexHash(p.wire)
	m.HeadersSHA256 = fieldHash(fields, true)
	m.TrailersSHA256 = fieldHash(trailers, false)
	m.HeaderFields, m.TrailerFields = len(fields), len(trailers)
	m.HeaderNames, m.OmittedHeaderNames = fieldNames(fields)
	m.TrailerNames, m.OmittedTrailerNames = fieldNames(trailers)
	h := sha256.New()
	for _, value := range []string{"framelens/projection-v1", m.Method, m.HTTPVersion, m.TargetSHA256, m.HeadersSHA256, m.TrailersSHA256, m.BodySHA256} {
		part(h, value)
	}
	m.ProjectionSHA256 = hexHash(h)
	return m, nil
}

// Analyze consumes request framing until EOF or the first unsupported/invalid message.
// Capture file identities and stability are supplied separately by InspectFile.
func Analyze(reader io.Reader, limits Limits) Capture {
	r := Capture{Schema: "rudy-framelens/inspection-v1", Version: Version, Profile: Profile, Messages: []Message{}}
	if !limits.Valid() {
		r.Problem = fail("invalid-limits", 0, "Resource limits are outside supported bounds.")
		return r
	}
	p := &parser{reader: bufio.NewReaderSize(io.LimitReader(reader, limits.MaxInputBytes+1), 32768), limits: limits}
	for {
		_, err := p.reader.Peek(1)
		if errors.Is(err, io.EOF) {
			r.Complete = true
			break
		}
		if err != nil {
			r.Problem = fail("input-read", p.offset, "Unable to continue reading the capture.")
			break
		}
		if p.offset >= limits.MaxInputBytes {
			r.Problem = fail("input-budget", p.offset, "The input byte budget was exceeded.")
			break
		}
		if len(r.Messages) >= limits.MaxMessages {
			r.Problem = fail("message-budget", p.offset, "The request-count budget was exceeded.")
			break
		}
		m, problem := p.request(len(r.Messages) + 1)
		if problem != nil {
			r.Problem = problem
			if p.offset > limits.MaxInputBytes {
				r.Problem = fail("input-budget", limits.MaxInputBytes, "The input byte budget was exceeded.")
			}
			break
		}
		if p.offset > limits.MaxInputBytes {
			r.Problem = fail("input-budget", limits.MaxInputBytes, "The input byte budget was exceeded.")
			break
		}
		r.Messages = append(r.Messages, m)
		r.Summary.Messages++
		r.Summary.ValidatedBytes = m.End
		r.Summary.DecodedBodyBytes += m.DecodedBodyBytes
		if m.Framing == "chunked" {
			r.Summary.ChunkedMessages++
		}
	}
	r.Bytes = p.offset
	return r
}
