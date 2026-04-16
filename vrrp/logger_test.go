package vrrp

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
	attrs   []slog.Attr
	group   string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	clone := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		clone.AddAttrs(attr)
		return true
	})
	h.records = append(h.records, clone)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := &recordingHandler{
		records: h.records,
		attrs:   append(append([]slog.Attr{}, h.attrs...), attrs...),
		group:   h.group,
	}
	return clone
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	clone := &recordingHandler{
		records: h.records,
		attrs:   append([]slog.Attr{}, h.attrs...),
		group:   name,
	}
	return clone
}

func (h *recordingHandler) snapshot() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

func TestGetLoggerReturnsDefaultLoggerWhenUnset(t *testing.T) {
	SetLogger(nil)

	logger := getLogger()
	if logger == nil {
		t.Fatal("expected default logger, got nil")
	}
}

func TestSetLoggerRoutesVirtualRouterLogsToCustomLogger(t *testing.T) {
	handler := &recordingHandler{}
	SetLogger(slog.New(handler))
	t.Cleanup(func() { SetLogger(nil) })

	vr := &VirtualRouter{}
	vr.SetGratuitousARPThrottleInterval(-1)

	records := handler.snapshot()
	if len(records) != 1 {
		t.Fatalf("expected exactly one log record, got %d", len(records))
	}
	if records[0].Level != slog.LevelError {
		t.Fatalf("expected error level, got %v", records[0].Level)
	}
	if !strings.Contains(records[0].Message, "interval") {
		t.Fatalf("expected log message to mention interval, got %q", records[0].Message)
	}
	if vr.garpThrottleInterval != 0 {
		t.Fatalf("expected negative interval to be ignored, got %v", vr.garpThrottleInterval)
	}
}

func TestSetLoggerNilRestoresDefaultLogger(t *testing.T) {
	custom := slog.New(&recordingHandler{})
	SetLogger(custom)
	if getLogger() != custom {
		t.Fatal("expected installed logger to be returned")
	}

	SetLogger(nil)
	if getLogger() == nil {
		t.Fatal("expected default logger after reset, got nil")
	}
	if getLogger() == custom {
		t.Fatal("expected reset to discard custom logger")
	}
}

func TestSetLoggerNilTracksCurrentSlogDefault(t *testing.T) {
	oldDefault := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(oldDefault)
		SetLogger(nil)
	})

	custom := slog.New(&recordingHandler{})
	SetLogger(custom)
	SetLogger(nil)

	newDefault := slog.New(slog.NewTextHandler(io.Discard, nil))
	slog.SetDefault(newDefault)

	if getLogger() != newDefault {
		t.Fatal("expected package logger to follow current slog default after reset")
	}
}

func TestSetLoggerConcurrentAccessIsSafe(t *testing.T) {
	SetLogger(nil)
	defer SetLogger(nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(50 * time.Millisecond)
			for time.Now().Before(deadline) {
				SetLogger(slog.New(&recordingHandler{}))
				_ = getLogger()
				SetLogger(nil)
			}
		}()
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(50 * time.Millisecond)
			for time.Now().Before(deadline) {
				vr := &VirtualRouter{}
				vr.SetGratuitousARPThrottleInterval(-1)
			}
		}()
	}

	wg.Wait()
	if getLogger() == nil {
		t.Fatal("expected logger to remain available after concurrent access")
	}
}
