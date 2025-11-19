package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	packetHeaderSize = 16
	maxPayloadBytes  = 1400
)

var (
	probeSentCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_probe_sent_total",
		Help: "Number of probe packets transmitted.",
	})
	probeRecvCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_probe_received_total",
		Help: "Number of probe responses received from remote site.",
	})
	probeDropCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_probe_dropped_total",
		Help: "Number of probe packets that were considered dropped due to timeout.",
	})
	probeUnexpectedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "udpmon_probe_unexpected_total",
		Help: "Number of probe responses carrying unknown or expired sequence numbers.",
	})
	probeRTTHistogram = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "udpmon_probe_rtt_seconds",
		Help:    "Observed round-trip latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})
)

func init() {
	prometheus.MustRegister(
		probeSentCounter,
		probeRecvCounter,
		probeDropCounter,
		probeUnexpectedCounter,
		probeRTTHistogram,
	)
}

type probeConfig struct {
	ListenAddr   string
	TargetAddr   string
	Interval     time.Duration
	Timeout      time.Duration
	PayloadBytes int
	LogInterval  time.Duration
}

func runProbe(ctx context.Context, logger *zap.Logger, cfg probeConfig) error {
	localAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return err
	}

	targetAddr, err := net.ResolveUDPAddr("udp", cfg.TargetAddr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", localAddr, targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	logger.Info("starting probe",
		zap.Stringer("local", conn.LocalAddr()),
		zap.Stringer("remote", conn.RemoteAddr()),
		zap.Duration("interval", cfg.Interval),
		zap.Duration("timeout", cfg.Timeout),
		zap.Int("payload_bytes", cfg.PayloadBytes),
	)

	stats := newProbeStats()
	pending := newPendingTracker()

	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()
	go probeReceiveLoop(recvCtx, conn, pending, stats, logger)
	go stats.LogLoop(ctx, logger, cfg.LogInterval)

	sendTicker := time.NewTicker(cfg.Interval)
	defer sendTicker.Stop()

	expireTicker := time.NewTicker(time.Second)
	defer expireTicker.Stop()

	var seq uint64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sendTicker.C:
			seq++
			if err := sendProbePacket(conn, seq, cfg.PayloadBytes, pending, stats); err != nil {
				logger.Warn("send failed", zap.Error(err))
			}
		case <-expireTicker.C:
			expired := pending.Expire(time.Now().Add(-cfg.Timeout))
			if expired > 0 {
				stats.AddDrops(uint64(expired))
			}
		}
	}
}

func sendProbePacket(conn *net.UDPConn, seq uint64, payloadBytes int, pending *pendingTracker, stats *probeStats) error {
	now := time.Now()
	buf := make([]byte, packetHeaderSize+payloadBytes)
	binary.BigEndian.PutUint64(buf[0:8], seq)
	binary.BigEndian.PutUint64(buf[8:16], uint64(now.UnixNano()))

	if _, err := conn.Write(buf); err != nil {
		return err
	}

	pending.Add(seq, now)
	stats.AddSent()
	return nil
}

func probeReceiveLoop(ctx context.Context, conn *net.UDPConn, pending *pendingTracker, stats *probeStats, logger *zap.Logger) {
	buf := make([]byte, packetHeaderSize+maxPayloadBytes+256)

	for {
		if ctx.Err() != nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			logger.Warn("receive failed", zap.Error(err))
			continue
		}

		if n < packetHeaderSize {
			logger.Debug("ignoring short packet", zap.Int("bytes", n))
			continue
		}

		seq := binary.BigEndian.Uint64(buf[0:8])
		sentTime, ok := pending.Remove(seq)
		if !ok {
			probeUnexpectedCounter.Inc()
			logger.Debug("received unknown seq", zap.Uint64("seq", seq))
			continue
		}

		rtt := time.Since(sentTime)
		stats.AddReceived(rtt)
	}
}

type probeStats struct {
	sent     atomic.Uint64
	received atomic.Uint64
	dropped  atomic.Uint64

	mu       sync.Mutex
	minRTT   time.Duration
	maxRTT   time.Duration
	sumRTT   time.Duration
	countRTT uint64
}

func newProbeStats() *probeStats {
	return &probeStats{
		minRTT: time.Duration(0),
	}
}

func (s *probeStats) AddSent() {
	s.sent.Add(1)
	probeSentCounter.Inc()
}

func (s *probeStats) AddReceived(rtt time.Duration) {
	s.received.Add(1)
	probeRecvCounter.Inc()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.countRTT == 0 || rtt < s.minRTT {
		s.minRTT = rtt
	}
	if rtt > s.maxRTT {
		s.maxRTT = rtt
	}
	s.sumRTT += rtt
	s.countRTT++
	probeRTTHistogram.Observe(rtt.Seconds())
}

func (s *probeStats) AddDrops(n uint64) {
	if n == 0 {
		return
	}
	s.dropped.Add(n)
	probeDropCounter.Add(float64(n))
}

func (s *probeStats) snapshot() statsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := statsSnapshot{
		Sent:     s.sent.Load(),
		Received: s.received.Load(),
		Dropped:  s.dropped.Load(),
	}

	if s.countRTT > 0 {
		snapshot.MinRTT = s.minRTT
		snapshot.MaxRTT = s.maxRTT
		snapshot.AvgRTT = s.sumRTT / time.Duration(s.countRTT)
		snapshot.PacketsWithRTT = s.countRTT
	}

	return snapshot
}

func (s *probeStats) LogLoop(ctx context.Context, logger *zap.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ss := s.snapshot()
			var dropPct float64
			if ss.Sent > 0 {
				dropPct = float64(ss.Sent-ss.Received) / float64(ss.Sent) * 100
			}

			fields := []zap.Field{
				zap.Uint64("sent", ss.Sent),
				zap.Uint64("received", ss.Received),
				zap.Uint64("dropped", ss.Dropped),
				zap.Float64("drop_pct", dropPct),
			}

			if ss.PacketsWithRTT > 0 {
				fields = append(fields,
					zap.Duration("rtt_min", ss.MinRTT),
					zap.Duration("rtt_avg", ss.AvgRTT),
					zap.Duration("rtt_max", ss.MaxRTT),
				)
			}

			logger.Info("probe summary", fields...)
		}
	}
}

type statsSnapshot struct {
	Sent           uint64
	Received       uint64
	Dropped        uint64
	PacketsWithRTT uint64
	MinRTT         time.Duration
	MaxRTT         time.Duration
	AvgRTT         time.Duration
}

type pendingTracker struct {
	mu      sync.Mutex
	pending map[uint64]time.Time
}

func newPendingTracker() *pendingTracker {
	return &pendingTracker{
		pending: make(map[uint64]time.Time),
	}
}

func (p *pendingTracker) Add(seq uint64, ts time.Time) {
	p.mu.Lock()
	p.pending[seq] = ts
	p.mu.Unlock()
}

func (p *pendingTracker) Remove(seq uint64) (time.Time, bool) {
	p.mu.Lock()
	ts, ok := p.pending[seq]
	if ok {
		delete(p.pending, seq)
	}
	p.mu.Unlock()
	return ts, ok
}

func (p *pendingTracker) Expire(before time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	expired := 0
	for seq, ts := range p.pending {
		if ts.Before(before) {
			delete(p.pending, seq)
			expired++
		}
	}
	return expired
}
