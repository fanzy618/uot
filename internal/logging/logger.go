package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New returns a JSON zap logger tuned for operational logs.
func New(level string) (*zap.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	cfg.EncoderConfig.StacktraceKey = ""

	return cfg.Build()
}

// MustNew is a convenience helper for bootstrap paths.
func MustNew(level string) *zap.Logger {
	logger, err := New(level)
	if err != nil {
		panic(err)
	}
	return logger
}

// LevelFromEnv fetches UT_LOG_LEVEL, defaulting to info.
func LevelFromEnv() string {
	lvl := os.Getenv("UT_LOG_LEVEL")
	if lvl == "" {
		return "info"
	}
	return lvl
}

func parseLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info", "":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unsupported log level %q", level)
	}
}
