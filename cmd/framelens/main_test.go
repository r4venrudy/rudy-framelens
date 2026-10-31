package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIContracts(t *testing.T) {
	root := t.TempDir()
	before := filepath.Join(root, "capturé İ.http")
	after := filepath.Join(root, "after.http")
	raw := "GET /private-demo HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
	if err := os.WriteFile(before, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(after, []byte(strings.Replace(raw, "private-demo", "changed-demo", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"--help"}, 0}, {[]string{"--version"}, 0}, {nil, 2}, {[]string{"inspect", before, "--format", "json"}, 0},
		{[]string{"compare", before, after, "--fail-on", "changed", "--format", "json"}, 1},
		{[]string{"inspect", before, "--fail-on", "changed"}, 2}, {[]string{"compare", before}, 2},
		{[]string{"inspect", before, "--rows", "0"}, 2}, {[]string{"inspect", before, "--rows", "1001"}, 2},
		{[]string{"inspect", before, "--rows", "1", "--rows", "2"}, 2}, {[]string{"inspect", before, "--format", "yaml"}, 2},
		{[]string{"inspect", before, "--max-input-mib", "9999999999999999999999"}, 2}, {[]string{"inspect", before, "--max-body-mib", "-1"}, 2},
		{[]string{"inspect", before, "--max-chunks", "0"}, 2}, {[]string{"inspect", before, "--format"}, 2},
	}
	for i, tc := range tests {
		var out, errOut bytes.Buffer
		if code := run(tc.args, &out, &errOut); code != tc.code {
			t.Fatalf("%d: got %d: %s", i, code, errOut.String())
		}
	}
	output := filepath.Join(root, "report.html")
	var out, errOut bytes.Buffer
	if run([]string{"inspect", before, "--format", "html", "--output", output}, &out, &errOut) != 0 {
		t.Fatal(errOut.String())
	}
	first, _ := os.ReadFile(output)
	if run([]string{"inspect", before, "--output", output}, &out, &errOut) != 2 {
		t.Fatal("existing output replaced")
	}
	second, _ := os.ReadFile(output)
	if !bytes.Equal(first, second) {
		t.Fatal("report changed")
	}
	if run([]string{"inspect", before, "--output", before}, &out, &errOut) != 2 {
		t.Fatal("source replaced")
	}
	current, _ := os.ReadFile(before)
	if string(current) != raw {
		t.Fatal("source changed")
	}
	bad := filepath.Join(root, "incomplete.http")
	os.WriteFile(bad, []byte(raw[:len(raw)-1]), 0600)
	out.Reset()
	errOut.Reset()
	if run([]string{"compare", before, bad, "--format", "json", "--fail-on", "changed"}, &out, &errOut) != 2 {
		t.Fatal("incomplete comparison passed")
	}
	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["comparable"] != false || report["projectionEqual"] != nil {
		t.Fatal("unknown was reported as equal")
	}
}
