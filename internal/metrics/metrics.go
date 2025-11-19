package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fanzy618/uot/internal/config"
)

// Exporter exposes Prometheus metrics as described in AGENTS.md.
type Exporter struct {
	cfg      config.MetricsConfig
	registry *prometheus.Registry
	metrics  MetricSet
}

// MetricSet bundles the core collectors; values can be updated by other packages.
type MetricSet struct {
	SessionsActive     prometheus.Gauge
	LanesActive        prometheus.Gauge
	UDPInBytes         *prometheus.CounterVec
	UDPInPackets       *prometheus.CounterVec
	UDPOutBytes        *prometheus.CounterVec
	UDPOutPackets      *prometheus.CounterVec
	UDPDropTotal       *prometheus.CounterVec
	TLSHandshakeSecs   prometheus.Observer
	LaneReconnectTotal prometheus.Counter
	QueueLen           prometheus.Gauge
}

// NewExporter builds a registry with all process + application collectors registered.
func NewExporter(cfg config.MetricsConfig) *Exporter {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	reg.MustRegister(prometheus.NewGoCollector())

	handshake := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ut_tls_handshake_seconds",
		Help:    "TLS handshake latency in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	metricSet := MetricSet{
		SessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ut_sessions_active",
			Help: "Current number of active sessions.",
		}),
		LanesActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ut_lanes_active_total",
			Help: "Number of active TCP+TLS lanes.",
		}),
		UDPInBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ut_udp_in_bytes_total",
			Help: "Total UDP bytes received from local adapter.",
		}, []string{"dir"}),
		UDPInPackets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ut_udp_in_packets_total",
			Help: "Total UDP packets received from local adapter.",
		}, []string{"dir"}),
		UDPOutBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ut_udp_out_bytes_total",
			Help: "Total UDP bytes forwarded to peer adapter.",
		}, []string{"dir"}),
		UDPOutPackets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ut_udp_out_packets_total",
			Help: "Total UDP packets forwarded to peer adapter.",
		}, []string{"dir"}),
		UDPDropTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ut_udp_drop_total",
			Help: "Count of UDP drops by reason (e.g. oldest).",
		}, []string{"reason"}),
		TLSHandshakeSecs: handshake,
		LaneReconnectTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ut_lane_reconnect_total",
			Help: "Count of lane reconnect attempts.",
		}),
		QueueLen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ut_queue_len",
			Help: "Current queued packet count.",
		}),
	}

	reg.MustRegister(
		metricSet.SessionsActive,
		metricSet.LanesActive,
		metricSet.UDPInBytes,
		metricSet.UDPInPackets,
		metricSet.UDPOutBytes,
		metricSet.UDPOutPackets,
		metricSet.UDPDropTotal,
		handshake,
		metricSet.LaneReconnectTotal,
		metricSet.QueueLen,
	)

	return &Exporter{cfg: cfg, registry: reg, metrics: metricSet}
}

// Registry exposes the wrapped Prometheus registry for advanced scenarios.
func (e *Exporter) Registry() *prometheus.Registry {
	return e.registry
}

// MetricSet returns the registered collectors for direct instrumentation.
func (e *Exporter) MetricSet() MetricSet {
	return e.metrics
}

// Handler returns an HTTP handler exposing metrics at cfg.Path.
func (e *Exporter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(e.cfg.Path, promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{}))
	return mux
}

// Serve blocks and exports metrics until the context is canceled.
func (e *Exporter) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:    e.cfg.ListenAddr,
		Handler: e.Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx) // best-effort; errors logged by caller
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
