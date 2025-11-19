package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/fanzy618/uot/internal/agent"
	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/logging"
	"github.com/fanzy618/uot/internal/metrics"
	"github.com/fanzy618/uot/internal/version"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "Path to YAML configuration file")
	flag.Parse()

	if cfgPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := logging.MustNew(logging.LevelFromEnv())
	defer logger.Sync() //nolint:errcheck

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Fatal("failed to load config", zap.String("path", cfgPath), zap.Error(err))
	}

	logger.Info("starting uot agent",
		zap.String("version", version.Version),
		zap.String("commit", version.GitCommit),
		zap.String("build_time", version.BuildTime),
		zap.Any("config", cfg.Loggable()),
	)

	exp := metrics.NewExporter(cfg.Metrics)
	go func() {
		if err := exp.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("metrics server exited", zap.Error(err))
		}
	}()

	ag, err := agent.New(cfg, logger, exp.MetricSet())
	if err != nil {
		logger.Fatal("failed to init agent", zap.Error(err))
	}

	if err := ag.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Info("shutdown complete", zap.Error(err))
		} else {
			logger.Fatal("agent exited", zap.Error(err))
		}
	}
}
