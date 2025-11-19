package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fanzy618/uot/internal/logging"
)

func main() {
	var (
		mode          string
		listenAddr    string
		targetAddr    string
		interval      time.Duration
		timeout       time.Duration
		payloadBytes  int
		metricsListen string
		logInterval   time.Duration
	)

	flag.StringVar(&mode, "mode", "probe", "probe or reflector")
	flag.StringVar(&listenAddr, "listen", ":0", "local UDP listen address")
	flag.StringVar(&targetAddr, "target", "", "remote UDP address (probe mode)")
	flag.DurationVar(&interval, "interval", time.Second, "probe send interval")
	flag.DurationVar(&timeout, "timeout", 3*time.Second, "probe drop timeout")
	flag.IntVar(&payloadBytes, "payload-bytes", 32, "payload bytes to append after the telemetry header")
	flag.StringVar(&metricsListen, "metrics-listen", "", "HTTP listen address for Prometheus metrics (disabled when empty)")
	flag.DurationVar(&logInterval, "log-interval", 10*time.Second, "summary logging interval (probe mode)")
	flag.Parse()

	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "probe" && mode != "reflector" {
		fmt.Fprintf(os.Stderr, "unsupported mode %q (must be probe or reflector)\n", mode)
		os.Exit(2)
	}

	if interval <= 0 {
		fmt.Fprintln(os.Stderr, "-interval must be > 0")
		os.Exit(2)
	}
	if timeout <= 0 {
		fmt.Fprintln(os.Stderr, "-timeout must be > 0")
		os.Exit(2)
	}
	if payloadBytes < 0 || payloadBytes > maxPayloadBytes {
		fmt.Fprintf(os.Stderr, "-payload-bytes must be between 0 and %d\n", maxPayloadBytes)
		os.Exit(2)
	}
	if logInterval <= 0 {
		fmt.Fprintln(os.Stderr, "-log-interval must be > 0")
		os.Exit(2)
	}
	if mode == "probe" && targetAddr == "" {
		fmt.Fprintln(os.Stderr, "-target is required in probe mode")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := logging.MustNew(logging.LevelFromEnv())
	defer logger.Sync() //nolint:errcheck

	if metricsListen != "" {
		go serveMetrics(ctx, metricsListen, logger)
	}

	var err error
	switch mode {
	case "probe":
		err = runProbe(ctx, logger.Named("probe"), probeConfig{
			ListenAddr:   listenAddr,
			TargetAddr:   targetAddr,
			Interval:     interval,
			Timeout:      timeout,
			PayloadBytes: payloadBytes,
			LogInterval:  logInterval,
		})
	case "reflector":
		err = runReflector(ctx, logger.Named("reflector"), reflectorConfig{
			ListenAddr: listenAddr,
		})
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatal("udp telemetry exited", zap.Error(err))
	}
}

func serveMetrics(ctx context.Context, addr string, logger *zap.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("metrics server exited", zap.Error(err))
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
}
