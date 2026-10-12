package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

func TestTolerantMultiWriterWritesPastAFailingSink(t *testing.T) {
	var ring, stderr bytes.Buffer
	w := &tolerantMultiWriter{writers: []io.Writer{&ring, failingWriter{}, &stderr}}

	_, err := w.Write([]byte("hello\n"))
	if err == nil {
		t.Fatal("expected the failing sink's error to be reported")
	}
	if ring.String() != "hello\n" || stderr.String() != "hello\n" {
		t.Fatalf("sinks around the failure must still receive the line: ring=%q stderr=%q", ring.String(), stderr.String())
	}
}
