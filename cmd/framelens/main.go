package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/r4venrudy/rudy-framelens/framing"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	code, err := execute(args, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "framelens:", err.Error())
		return 2
	}
	return code
}

func execute(args []string, stdout io.Writer) (int, error) {
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintln(stdout, "framelens "+framing.Version)
		return 0, err
	}
	if len(args) == 1 && args[0] == "--help" {
		_, err := fmt.Fprintln(stdout, "Rudy FrameLens / offline HTTP/1 request framing\nframelens inspect CAPTURE [--format text|json|html]\nframelens compare BEFORE AFTER [--fail-on changed]\nCommon: --output NEW_FILE --rows 1..1000 --max-input-mib 1..2048\n        --max-body-mib 0..1024 --max-messages 1..10000 --max-chunks 1..1000000\nNo network requests, replay, TLS decryption, or server fingerprinting.")
		return 0, err
	}
	invalid := errors.New("invalid arguments; use --help")
	if len(args) < 2 || args[0] != "inspect" && args[0] != "compare" {
		return 2, invalid
	}
	first := 2
	if args[0] == "compare" {
		first = 3
	}
	if len(args) < first {
		return 2, invalid
	}
	for _, path := range args[1:first] {
		if strings.HasPrefix(path, "--") {
			return 2, invalid
		}
	}
	opts := map[string]string{}
	for i := first; i < len(args); i += 2 {
		if i+1 == len(args) {
			return 2, invalid
		}
		key := args[i]
		switch key {
		case "--format", "--output", "--rows", "--max-input-mib", "--max-body-mib", "--max-messages", "--max-chunks", "--fail-on":
		default:
			return 2, invalid
		}
		if _, exists := opts[key]; exists {
			return 2, invalid
		}
		opts[key] = args[i+1]
	}
	format := "text"
	if value, ok := opts["--format"]; ok {
		format = value
	}
	if format != "text" && format != "json" && format != "html" {
		return 2, invalid
	}
	if value, ok := opts["--fail-on"]; ok && (args[0] != "compare" || value != "changed") {
		return 2, invalid
	}
	number := func(key string, fallback, low, high int64) (int64, error) {
		value, ok := opts[key]
		if !ok {
			return fallback, nil
		}
		if value == "" {
			return 0, invalid
		}
		for i := range len(value) {
			if value[i] < '0' || value[i] > '9' {
				return 0, invalid
			}
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < low || n > high {
			return 0, invalid
		}
		return n, nil
	}
	rows, err := number("--rows", 100, 1, 1000)
	if err != nil {
		return 2, err
	}
	input, err := number("--max-input-mib", 256, 1, 2048)
	if err != nil {
		return 2, err
	}
	body, err := number("--max-body-mib", 64, 0, 1024)
	if err != nil {
		return 2, err
	}
	messages, err := number("--max-messages", 2000, 1, 10000)
	if err != nil {
		return 2, err
	}
	chunks, err := number("--max-chunks", 100000, 1, 1000000)
	if err != nil {
		return 2, err
	}
	limits := framing.Limits{MaxInputBytes: input << 20, MaxBodyBytes: body << 20, MaxMessages: int(messages), MaxChunks: int(chunks)}
	before, err := framing.InspectFile(args[1], limits)
	if err != nil {
		return 2, err
	}
	var report any
	code := 0
	if args[0] == "inspect" {
		report = framing.Display(before, int(rows))
		if !before.Complete {
			code = 2
		}
	} else {
		after, err := framing.InspectFile(args[2], limits)
		if err != nil {
			return 2, err
		}
		compared := framing.Compare(before, after, int(rows))
		report = compared
		if !compared.Comparable {
			code = 2
		} else if opts["--fail-on"] == "changed" && !*compared.ProjectionEqual {
			code = 1
		}
	}
	data, err := framing.Render(report, format)
	if err != nil {
		return 2, err
	}
	if output, ok := opts["--output"]; ok {
		file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return 2, errors.New("unable to create a new report file")
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return 2, errors.New("unable to finish writing the report")
		}
	} else {
		if _, err := stdout.Write(data); err != nil {
			return 2, errors.New("unable to write the report")
		}
	}
	return code, nil
}
