package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/metrics"
	"github.com/fanzy618/uot/internal/tlsutil"
)

type serverAgent struct {
	cfg      *config.Config
	log      *zap.Logger
	metrics  metrics.MetricSet
	tlsConf  *tls.Config
	tlsOff   bool
	sessions *sessionManager
}

func newServerAgent(cfg *config.Config, log *zap.Logger, metricSet metrics.MetricSet) (Agent, error) {
	var tlsConf *tls.Config
	var err error
	if !cfg.TLS.Disable {
		tlsConf, err = tlsutil.ServerConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
	}
	wgAddr, err := net.ResolveUDPAddr("udp", cfg.UDP.WGAddr)
	if err != nil {
		return nil, err
	}
	return &serverAgent{
		cfg:      cfg,
		log:      log,
		metrics:  metricSet,
		tlsConf:  tlsConf,
		tlsOff:   cfg.TLS.Disable,
		sessions: newSessionManager(cfg, log, metricSet, wgAddr),
	}, nil
}

func (a *serverAgent) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.cfg.TCP.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer a.sessions.Close()

	a.log.Info("server listening", zap.String("addr", a.cfg.TCP.ListenAddr))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				a.log.Warn("accept temporary error", zap.Error(err))
				continue
			}
			return err
		}
		go a.handleConn(ctx, conn)
	}
}

func (a *serverAgent) handleConn(ctx context.Context, rawConn net.Conn) {
	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		rawConn.Close()
		a.log.Warn("non tcp connection received")
		return
	}
	_ = tcpConn.SetNoDelay(a.cfg.TCP.TCPNoDelay)
	if a.cfg.TCP.TCPBuf > 0 {
		_ = tcpConn.SetReadBuffer(a.cfg.TCP.TCPBuf)
		_ = tcpConn.SetWriteBuffer(a.cfg.TCP.TCPBuf)
	}

	conn := net.Conn(tcpConn)
	clientCN := "insecure"
	if !a.tlsOff {
		tlsConn := tls.Server(tcpConn, a.tlsConf.Clone())
		start := time.Now()
		if err := tlsConn.Handshake(); err != nil {
			a.log.Warn("tls handshake failed", zap.Error(err))
			tlsConn.Close()
			return
		}
		a.metrics.TLSHandshakeSecs.Observe(time.Since(start).Seconds())

		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			clientCN = state.PeerCertificates[0].Subject.CommonName
		}
		conn = tlsConn
	}

	sess, err := a.sessions.Get(ctx, clientCN)
	if err != nil {
		a.log.Error("session init failed", zap.String("client_cn", clientCN), zap.Error(err))
		conn.Close()
		return
	}

	a.metrics.SessionsActive.Inc()
	a.metrics.LanesActive.Inc()
	a.log.Info("lane accepted", zap.String("client_cn", clientCN))

	defer func() {
		conn.Close()
		a.metrics.SessionsActive.Dec()
		a.metrics.LanesActive.Dec()
	}()

	laneCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- sess.pipeLaneToWG(laneCtx, conn)
	}()
	go func() {
		errCh <- sess.forwardQueueToLane(laneCtx, conn)
	}()

	select {
	case <-ctx.Done():
		return
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			a.log.Warn("lane closed", zap.Error(err), zap.String("client_cn", clientCN))
		}
		return
	}
}
