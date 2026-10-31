package framing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

func fileHash(file *os.File, size int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, 0, size))
	if err != nil || n != size {
		return "", errors.New("unable to hash the complete capture")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func InspectFile(path string, limits Limits) (Capture, error) {
	if !limits.Valid() {
		return Capture{}, errors.New("resource limits are outside supported bounds")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Capture{}, errors.New("input must be an accessible regular file, not a symbolic link")
	}
	if info.Size() > limits.MaxInputBytes {
		return Capture{}, errors.New("input exceeds the byte budget")
	}
	file, err := os.Open(path)
	if err != nil {
		return Capture{}, errors.New("unable to open the capture")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > limits.MaxInputBytes {
		return Capture{}, errors.New("opened input is unsupported or exceeds the byte budget")
	}
	identity, err := fileHash(file, opened.Size())
	if err != nil {
		return Capture{}, err
	}
	r := Analyze(io.NewSectionReader(file, 0, opened.Size()), limits)
	final, err := file.Stat()
	if err != nil || final.Size() != opened.Size() {
		return Capture{}, errors.New("input changed during analysis")
	}
	rechecked, err := fileHash(file, opened.Size())
	if err != nil || rechecked != identity {
		return Capture{}, errors.New("input changed during analysis")
	}
	r.SHA256, r.Bytes, r.SourceRechecked = identity, opened.Size(), true
	return r, nil
}

func Display(capture Capture, rows int) Capture {
	if len(capture.Messages) > rows {
		capture.OmittedMessages = len(capture.Messages) - rows
		capture.Messages = capture.Messages[:rows]
	}
	return capture
}
