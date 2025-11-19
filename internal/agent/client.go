package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/metrics"
	"github.com/fanzy618/uot/internal/pdu"
	"github.com/fanzy618/uot/internal/queue"
	"github.com/fanzy618/uot/internal/tlsutil"
)

type clientAgent struct {
	cfg      *config.Config
	log      *zap.Logger
	metrics  metrics.MetricSet
	tlsConf  *tls.Config
	tlsOff   bool
	idleTime time.Duration
}

func newClientAgent(cfg *config.Config, log *zap.Logger, metricSet metrics.MetricSet) (Agent, error) {
	host, _, err := net.SplitHostPort(cfg.TCP.ServerAddr)
	if err != nil {
		host = cfg.TCP.ServerAddr
	}
	var tlsConf *tls.Config
	if !cfg.TLS.Disable {
		tlsConf, err = tlsutil.ClientConfig(cfg.TLS, host)
		if err != nil {
			return nil, err
		}
	}
	metricSet.QueueLen.Set(0)
	return &clientAgent{
		cfg:      cfg,
		log:      log,
		metrics:  metricSet,
		tlsConf:  tlsConf,
		tlsOff:   cfg.TLS.Disable,
		idleTime: cfg.TCP.IdleDuration(),
	}, nil
}

func (a *clientAgent) Run(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", a.cfg.UDP.ListenAddr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	a.log.Info("client UDP adapter ready", zap.Stringer("listen_addr", udpAddr))

	q := queue.New(a.cfg.Queue.MaxPackets, a.cfg.Queue.MaxBytes)
	defer q.Close()

	var wgRemote atomic.Pointer[net.UDPAddr]
	var wg sync.WaitGroup

	udpCtx, udpCancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.udpIngressLoop(udpCtx, udpConn, q, &wgRemote)
	}()

	for i := 0; i < a.cfg.TCP.Lanes; i++ {
		laneID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.laneLoop(ctx, laneID, udpConn, &wgRemote, q)
		}()
	}

	<-ctx.Done()
	udpCancel()
	q.Close()
	wg.Wait()
	return ctx.Err()
}

func (a *clientAgent) laneLoop(ctx context.Context, laneID int, udpConn *net.UDPConn, remote *atomic.Pointer[net.UDPAddr], q *queue.PacketQueue) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := a.runLane(ctx, laneID, udpConn, remote, q); err != nil && ctx.Err() == nil {
			a.metrics.LaneReconnectTotal.Inc()
			a.log.Warn("lane exited", zap.Int("lane_id", laneID), zap.Error(err))
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

func (a *clientAgent) runLane(ctx context.Context, laneID int, udpConn *net.UDPConn, remote *atomic.Pointer[net.UDPAddr], q *queue.PacketQueue) error {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rawConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, "tcp", a.cfg.TCP.ServerAddr)
	if err != nil {
		return err
	}
	tcpConn, ok := rawConn.(*net.TCPConn)
	if !ok {
		rawConn.Close()
		return fmt.Errorf("unexpected conn type %T", rawConn)
	}
	_ = tcpConn.SetNoDelay(a.cfg.TCP.TCPNoDelay)
	if a.cfg.TCP.TCPBuf > 0 {
		_ = tcpConn.SetReadBuffer(a.cfg.TCP.TCPBuf)
		_ = tcpConn.SetWriteBuffer(a.cfg.TCP.TCPBuf)
	}

	conn := net.Conn(tcpConn)
	if !a.tlsOff {
		tlsConn := tls.Client(tcpConn, a.tlsConf.Clone())
		start := time.Now()
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return err
		}
		a.metrics.TLSHandshakeSecs.Observe(time.Since(start).Seconds())
		conn = tlsConn
	}
	a.metrics.SessionsActive.Inc()
	a.metrics.LanesActive.Inc()
	a.log.Info("lane established", zap.Int("lane_id", laneID))

	laneCtx, cancelLane := context.WithCancel(ctx)
	defer cancelLane()
	defer func() {
		conn.Close()
		a.metrics.SessionsActive.Dec()
		a.metrics.LanesActive.Dec()
	}()

	errCh := make(chan error, 2)
	go func() {
		errCh <- a.queueToLane(laneCtx, laneID, conn, q)
	}()
	go func() {
		errCh <- a.pipeLaneToUDP(laneCtx, conn, udpConn, remote)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (a *clientAgent) udpIngressLoop(ctx context.Context, udpConn *net.UDPConn, q *queue.PacketQueue, remote *atomic.Pointer[net.UDPAddr]) {
	buf := make([]byte, pdu.MaxPayload+1)
	for ctx.Err() == nil {
		if err := udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			a.log.Warn("set udp read deadline", zap.Error(err))
			return
		}
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("udp read failed", zap.Error(err))
			return
		}
		remote.Store(addr)
		if n > pdu.MaxPayload {
			a.log.Warn("udp packet exceeds limit", zap.Int("size", n))
			continue
		}
		if dropped := q.Enqueue(buf[:n]); dropped > 0 {
			a.metrics.UDPDropTotal.WithLabelValues("oldest").Add(float64(dropped))
		}
		a.metrics.QueueLen.Set(float64(q.Len()))
		a.metrics.UDPInPackets.WithLabelValues(dirUp).Inc()
		a.metrics.UDPInBytes.WithLabelValues(dirUp).Add(float64(n))
	}
}

func (a *clientAgent) queueToLane(ctx context.Context, laneID int, lane net.Conn, q *queue.PacketQueue) error {
	for {
		pkt, err := q.Dequeue(ctx)
		if err != nil {
			return err
		}
		a.metrics.QueueLen.Set(float64(q.Len()))
		if a.idleTime > 0 {
			_ = lane.SetWriteDeadline(time.Now().Add(a.idleTime))
		}
		if err := pdu.Encode(lane, pdu.Frame{Type: pdu.TypeData, Data: pkt}); err != nil {
			q.RequeueFront(pkt)
			return err
		}
	}
}

func (a *clientAgent) pipeLaneToUDP(ctx context.Context, lane net.Conn, udpConn *net.UDPConn, remote *atomic.Pointer[net.UDPAddr]) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if a.idleTime > 0 {
			_ = lane.SetReadDeadline(time.Now().Add(a.idleTime))
		}
		frame, err := pdu.Decode(lane)
		if err != nil {
			return err
		}
		if frame.Type != pdu.TypeData || len(frame.Data) == 0 {
			continue
		}
		dst := remote.Load()
		if dst == nil {
			a.log.Warn("no wg remote yet; dropping downlink")
			continue
		}
		if err := udpConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		n, err := udpConn.WriteToUDP(frame.Data, dst)
		if err != nil {
			return err
		}
		a.metrics.UDPOutPackets.WithLabelValues(dirDown).Inc()
		a.metrics.UDPOutBytes.WithLabelValues(dirDown).Add(float64(n))
	}
}
