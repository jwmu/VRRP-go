package logger

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewLoggerDefaultsToStdout(t *testing.T) {
	l := NewLogger(nil)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	if l.level != INFO {
		t.Fatalf("expected default level INFO, got %v", l.level)
	}
}

func TestNewLoggerWithCustomWriter(t *testing.T) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	l := NewLogger(&w)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
	l.Printf(INFO, "hello %s", "world")
	if !strings.Contains(buf.String(), "hello world") {
		t.Fatalf("expected output to contain 'hello world', got %q", buf.String())
	}
}

func TestSetLevel(t *testing.T) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	l := NewLogger(&w)

	l.SetLevel(ERROR)
	l.Printf(INFO, "should not appear")
	if buf.Len() != 0 {
		t.Fatalf("expected no output for INFO when level is ERROR, got %q", buf.String())
	}

	l.Printf(ERROR, "should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Fatalf("expected ERROR message to appear, got %q", buf.String())
	}
}

func TestSetLevelDebugSetsFlags(t *testing.T) {
	l := NewLogger(nil)
	l.SetLevel(DEBUG)
	if l.level != DEBUG {
		t.Fatalf("expected level DEBUG, got %v", l.level)
	}
}

func TestSetPrefix(t *testing.T) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	l := NewLogger(&w)
	l.SetPrefix("[TEST] ")
	l.Printf(INFO, "prefixed")
	if !strings.Contains(buf.String(), "[TEST]") {
		t.Fatalf("expected prefix in output, got %q", buf.String())
	}
}

func TestPrintfBelowLevelIsFiltered(t *testing.T) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	l := NewLogger(&w)
	l.SetLevel(ERROR)

	l.Printf(DEBUG, "debug msg")
	l.Printf(INFO, "info msg")
	if buf.Len() != 0 {
		t.Fatalf("expected no output for messages below ERROR level, got %q", buf.String())
	}
}

func TestPrintfFATALPanics(t *testing.T) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	l := NewLogger(&w)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected FATAL to panic")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic value to be string, got %T", r)
		}
		if !strings.Contains(msg, "fatal error") {
			t.Fatalf("expected panic message to contain 'fatal error', got %q", msg)
		}
	}()

	l.Printf(FATAL, "fatal error: %d", 42)
}

func TestGlobalLoggerInitialized(t *testing.T) {
	if GLoger == nil {
		t.Fatal("expected global logger to be initialized")
	}
	if GLoger.level != INFO {
		t.Fatalf("expected global logger level INFO, got %v", GLoger.level)
	}
}
