package main

import (
	"context"
	"errors"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	reflectorRecvCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_reflector_received_total",
		Help: "Number of inbound packets received by the reflector.",
	})
	reflectorEchoCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_reflector_echo_total",
		Help: "Number of packets echoed back to peers.",
	})
)

func init() {
	prometheus.MustRegister(reflectorRecvCounter, reflectorEchoCounter)
}

type reflectorConfig struct {
	ListenAddr string
}

func runReflector(ctx context.Context, logger *zap.Logger, cfg reflectorConfig) error {
	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	logger.Info("starting reflector", zap.Stringer("listen", conn.LocalAddr()))

	buf := make([]byte, packetHeaderSize+maxPayloadBytes+512)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, peerAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			logger.Warn("reflector recv error", zap.Error(err))
			continue
		}

		reflectorRecvCounter.Inc()
		if n < packetHeaderSize {
			logger.Debug("dropping short packet", zap.Int("bytes", n))
			continue
		}

		if _, err := conn.WriteToUDP(buf[:n], peerAddr); err != nil {
			logger.Warn("failed to echo packet", zap.Stringer("peer", peerAddr), zap.Error(err))
			continue
		}
		reflectorEchoCounter.Inc()
	}
}
