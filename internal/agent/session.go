package agent

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/metrics"
	"github.com/fanzy618/uot/internal/pdu"
	"github.com/fanzy618/uot/internal/queue"
)

type sessionManager struct {
	cfg     *config.Config
	log     *zap.Logger
	metrics metrics.MetricSet
	wgAddr  *net.UDPAddr
	idle    time.Duration

	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionManager(cfg *config.Config, log *zap.Logger, metrics metrics.MetricSet, wgAddr *net.UDPAddr) *sessionManager {
	return &sessionManager{
		cfg:      cfg,
		log:      log,
		metrics:  metrics,
		wgAddr:   wgAddr,
		idle:     cfg.TCP.IdleDuration(),
		sessions: make(map[string]*session),
	}
}

func (m *sessionManager) Get(ctx context.Context, cn string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, ok := m.sessions[cn]; ok {
		return sess, nil
	}
	sess, err := newSession(ctx, cn, m.wgAddr, m.cfg, m.log.Named("session"), m.metrics)
	if err != nil {
		return nil, err
	}
	m.sessions[cn] = sess
	return sess, nil
}

func (m *sessionManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for cn, sess := range m.sessions {
		sess.Close()
		delete(m.sessions, cn)
	}
}

type session struct {
	cn      string
	udpConn *net.UDPConn
	queue   *queue.PacketQueue
	log     *zap.Logger
	metrics metrics.MetricSet
	idle    time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	writeMu sync.Mutex
}

func newSession(parent context.Context, cn string, wgAddr *net.UDPAddr, cfg *config.Config, log *zap.Logger, metrics metrics.MetricSet) (*session, error) {
	udpConn, err := net.DialUDP("udp", nil, wgAddr)
	if err != nil {
		return nil, err
	}
	queue := queue.New(cfg.Queue.MaxPackets, cfg.Queue.MaxBytes)
	ctx, cancel := context.WithCancel(parent)
	sess := &session{
		cn:      cn,
		udpConn: udpConn,
		queue:   queue,
		log:     log.With(zap.String("client_cn", cn)),
		metrics: metrics,
		idle:    cfg.TCP.IdleDuration(),
		ctx:     ctx,
		cancel:  cancel,
	}
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		sess.readFromWG()
	}()
	return sess, nil
}

func (s *session) Close() {
	s.cancel()
	s.queue.Close()
	s.udpConn.Close()
	s.wg.Wait()
}

func (s *session) readFromWG() {
	buf := make([]byte, pdu.MaxPayload+1)
	for {
		if s.ctx.Err() != nil {
			return
		}
		if err := s.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			s.log.Warn("set wg read deadline", zap.Error(err))
			return
		}
		n, err := s.udpConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			s.log.Warn("wg read failed", zap.Error(err))
			return
		}
		if n > pdu.MaxPayload {
			s.log.Warn("wg packet exceeds limit", zap.Int("size", n))
			continue
		}
		if dropped := s.queue.Enqueue(buf[:n]); dropped > 0 {
			s.metrics.UDPDropTotal.WithLabelValues("oldest").Add(float64(dropped))
		}
		s.metrics.QueueLen.Set(float64(s.queue.Len()))
		s.metrics.UDPInPackets.WithLabelValues(dirDown).Inc()
		s.metrics.UDPInBytes.WithLabelValues(dirDown).Add(float64(n))
	}
}

func (s *session) forwardQueueToLane(ctx context.Context, lane net.Conn) error {
	for {
		pkt, err := s.queue.Dequeue(ctx)
		if err != nil {
			return err
		}
		s.metrics.QueueLen.Set(float64(s.queue.Len()))
		if s.idle > 0 {
			_ = lane.SetWriteDeadline(time.Now().Add(s.idle))
		}
		if err := pdu.Encode(lane, pdu.Frame{Type: pdu.TypeData, Data: pkt}); err != nil {
			s.queue.RequeueFront(pkt)
			return err
		}
	}
}

func (s *session) pipeLaneToWG(ctx context.Context, lane net.Conn) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.idle > 0 {
			_ = lane.SetReadDeadline(time.Now().Add(s.idle))
		}
		frame, err := pdu.Decode(lane)
		if err != nil {
			return err
		}
		if frame.Type != pdu.TypeData || len(frame.Data) == 0 {
			continue
		}
		if err := s.writeToWG(frame.Data); err != nil {
			return err
		}
	}
}

func (s *session) writeToWG(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.udpConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	n, err := s.udpConn.Write(data)
	if err != nil {
		return err
	}
	s.metrics.UDPOutPackets.WithLabelValues(dirUp).Inc()
	s.metrics.UDPOutBytes.WithLabelValues(dirUp).Add(float64(n))
	return nil
}
