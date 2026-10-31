// Package framing investigates bounded, offline HTTP/1 request streams.
package framing

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"
)

const Version = "0.1.0-preview"
const Profile = "framelens/strict-request-v1"

type Limits struct {
	MaxInputBytes int64
	MaxBodyBytes  int64
	MaxMessages   int
	MaxChunks     int
}

func DefaultLimits() Limits {
	return Limits{256 << 20, 64 << 20, 2000, 100000}
}

func (l Limits) Valid() bool {
	return l.MaxInputBytes >= 1 && l.MaxInputBytes <= 2<<30 && l.MaxBodyBytes >= 0 && l.MaxBodyBytes <= 1<<30 && l.MaxMessages >= 1 && l.MaxMessages <= 10000 && l.MaxChunks >= 1 && l.MaxChunks <= 1000000
}

type Problem struct {
	Code   string `json:"code"`
	Offset int64  `json:"offset"`
	Reason string `json:"reason"`
}

func (p *Problem) Error() string { return p.Code }

type Chunk struct {
	LineStart int64 `json:"lineStart"`
	DataStart int64 `json:"dataStart"`
	Bytes     int64 `json:"bytes"`
	WireEnd   int64 `json:"wireEnd"`
}

type Message struct {
	Ordinal             int      `json:"ordinal"`
	Start               int64    `json:"start"`
	HeaderEnd           int64    `json:"headerEnd"`
	End                 int64    `json:"end"`
	Method              string   `json:"method"`
	HTTPVersion         string   `json:"httpVersion"`
	TargetForm          string   `json:"targetForm"`
	TargetSHA256        string   `json:"targetSha256"`
	Framing             string   `json:"framing"`
	DecodedBodyBytes    int64    `json:"decodedBodyBytes"`
	BodySHA256          string   `json:"bodySha256"`
	HeadersSHA256       string   `json:"headersSha256"`
	TrailersSHA256      string   `json:"trailersSha256"`
	ProjectionSHA256    string   `json:"projectionSha256"`
	WireSHA256          string   `json:"wireSha256"`
	HeaderNames         []string `json:"headerNames"`
	HeaderFields        int      `json:"headerFields"`
	OmittedHeaderNames  int      `json:"omittedHeaderNames"`
	TrailerNames        []string `json:"trailerNames"`
	TrailerFields       int      `json:"trailerFields"`
	OmittedTrailerNames int      `json:"omittedTrailerNames"`
	ChunkCount          int      `json:"chunkCount"`
	Chunks              []Chunk  `json:"chunks"`
	OmittedChunks       int      `json:"omittedChunks"`
}

type Summary struct {
	Messages         int   `json:"messages"`
	ValidatedBytes   int64 `json:"validatedBytes"`
	DecodedBodyBytes int64 `json:"decodedBodyBytes"`
	ChunkedMessages  int   `json:"chunkedMessages"`
}

type Capture struct {
	Schema          string    `json:"schema"`
	Version         string    `json:"version"`
	Profile         string    `json:"profile"`
	SHA256          string    `json:"sha256"`
	Bytes           int64     `json:"bytes"`
	Complete        bool      `json:"complete"`
	SourceRechecked bool      `json:"sourceRechecked"`
	Summary         Summary   `json:"summary"`
	Problem         *Problem  `json:"problem"`
	Messages        []Message `json:"messages"`
	OmittedMessages int       `json:"omittedMessages"`
}

type Change struct {
	Ordinal          int    `json:"ordinal"`
	Kind             string `json:"kind"`
	BeforeProjection string `json:"beforeProjection,omitempty"`
	AfterProjection  string `json:"afterProjection,omitempty"`
	BeforeBody       string `json:"beforeBody,omitempty"`
	AfterBody        string `json:"afterBody,omitempty"`
}

type Comparison struct {
	Schema          string   `json:"schema"`
	Version         string   `json:"version"`
	Profile         string   `json:"profile"`
	BeforeSHA256    string   `json:"beforeSha256"`
	AfterSHA256     string   `json:"afterSha256"`
	Comparable      bool     `json:"comparable"`
	ProjectionEqual *bool    `json:"projectionEqual"`
	BeforeProblem   *Problem `json:"beforeProblem"`
	AfterProblem    *Problem `json:"afterProblem"`
	BeforeMessages  int      `json:"beforeMessages"`
	AfterMessages   int      `json:"afterMessages"`
	Added           int      `json:"added"`
	Removed         int      `json:"removed"`
	Modified        int      `json:"modified"`
	WireOnly        int      `json:"wireOnly"`
	Unchanged       int      `json:"unchanged"`
	Changes         []Change `json:"changes"`
	OmittedChanges  int      `json:"omittedChanges"`
}

func Compare(before, after Capture, rows int) Comparison {
	r := Comparison{Schema: "rudy-framelens/comparison-v1", Version: Version, Profile: Profile, BeforeSHA256: before.SHA256, AfterSHA256: after.SHA256, BeforeMessages: before.Summary.Messages, AfterMessages: after.Summary.Messages, BeforeProblem: before.Problem, AfterProblem: after.Problem, Changes: []Change{}}
	// Display-truncated captures cannot support a complete sequence comparison.
	if !before.Complete || !after.Complete || len(before.Messages) != before.Summary.Messages || len(after.Messages) != after.Summary.Messages {
		return r
	}
	r.Comparable = true
	n := max(len(before.Messages), len(after.Messages))
	for i := 0; i < n; i++ {
		c := Change{Ordinal: i + 1}
		switch {
		case i >= len(before.Messages):
			c.Kind = "added"
			r.Added++
			c.AfterProjection = after.Messages[i].ProjectionSHA256
			c.AfterBody = after.Messages[i].BodySHA256
		case i >= len(after.Messages):
			c.Kind = "removed"
			r.Removed++
			c.BeforeProjection = before.Messages[i].ProjectionSHA256
			c.BeforeBody = before.Messages[i].BodySHA256
		default:
			a, b := before.Messages[i], after.Messages[i]
			c.BeforeProjection, c.AfterProjection, c.BeforeBody, c.AfterBody = a.ProjectionSHA256, b.ProjectionSHA256, a.BodySHA256, b.BodySHA256
			if a.ProjectionSHA256 != b.ProjectionSHA256 {
				c.Kind = "modified"
				r.Modified++
			} else if a.WireSHA256 != b.WireSHA256 {
				c.Kind = "wire-only"
				r.WireOnly++
			} else {
				r.Unchanged++
				continue
			}
		}
		if len(r.Changes) < rows {
			r.Changes = append(r.Changes, c)
		} else {
			r.OmittedChanges++
		}
	}
	equal := r.Added+r.Removed+r.Modified == 0
	r.ProjectionEqual = &equal
	return r
}

type field struct{ name, value string }

func digest(s string) string     { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func hexHash(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
func part(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

func fieldHash(fields []field, omitFraming bool) string {
	ordered := append([]field(nil), fields...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].name < ordered[j].name })
	h := sha256.New()
	part(h, "framelens/fields-v1")
	for _, f := range ordered {
		if omitFraming && (f.name == "content-length" || f.name == "transfer-encoding") {
			continue
		}
		part(h, f.name)
		part(h, f.value)
	}
	return hexHash(h)
}

func fieldNames(fields []field) ([]string, int) {
	seen := map[string]bool{}
	names := []string{}
	for _, f := range fields {
		if !seen[f.name] {
			seen[f.name] = true
			names = append(names, f.name)
		}
	}
	sort.Strings(names)
	omitted := max(0, len(names)-32)
	if len(names) > 32 {
		names = names[:32]
	}
	return names, omitted
}
