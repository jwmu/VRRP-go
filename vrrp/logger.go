package vrrp

import (
	"log/slog"
	"sync/atomic"
)

var packageLogger atomic.Pointer[slog.Logger]

func SetLogger(logger *slog.Logger) {
	if logger == nil {
		packageLogger.Store(nil)
		return
	}
	packageLogger.Store(logger)
}

func getLogger() *slog.Logger {
	if logger := packageLogger.Load(); logger != nil {
		return logger
	}
	return slog.Default()
}
