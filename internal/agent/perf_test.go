//go:build !short

package agent_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/fanzy618/uot/internal/agent"
	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/metrics"
)

func BenchmarkLocalhostTunnel(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wgBackend := listenUDPOrSkip(b, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer wgBackend.Close()

	serverTCPAddr := fmt.Sprintf("127.0.0.1:%d", mustFreePort(b))
	clientUDPPort := mustFreePort(b)
	clientUDPAddr := fmt.Sprintf("127.0.0.1:%d", clientUDPPort)

	serverCfg := &config.Config{
		Role: config.RoleServer,
		TCP: config.TCPConfig{
			ListenAddr:  serverTCPAddr,
			Lanes:       2,
			TCPNoDelay:  true,
			TCPBuf:      16384,
			IdleSeconds: 10,
		},
		UDP: config.UDPConfig{WGAddr: wgBackend.LocalAddr().String()},
		Queue: config.QueueConfig{
			MaxPackets: 4096,
			MaxBytes:   8 << 20,
			DropPolicy: "oldest",
		},
		Metrics: config.MetricsConfig{
			ListenAddr: "127.0.0.1:0",
			Path:       "/metrics",
		},
		TLS: config.TLSConfig{
			Disable: true,
		},
	}
	if err := serverCfg.Validate(); err != nil {
		b.Fatalf("server cfg invalid: %v", err)
	}

	clientCfg := &config.Config{
		Role: config.RoleClient,
		TCP: config.TCPConfig{
			ServerAddr:  serverTCPAddr,
			Lanes:       2,
			TCPNoDelay:  true,
			TCPBuf:      16384,
			IdleSeconds: 10,
		},
		UDP:   config.UDPConfig{ListenAddr: clientUDPAddr},
		Queue: serverCfg.Queue,
		Metrics: config.MetricsConfig{
			ListenAddr: "127.0.0.1:0",
			Path:       "/metrics",
		},
		TLS: config.TLSConfig{
			Disable: true,
		},
	}
	if err := clientCfg.Validate(); err != nil {
		b.Fatalf("client cfg invalid: %v", err)
	}

	serverExp := metrics.NewExporter(serverCfg.Metrics)
	serverAgent, err := agent.New(serverCfg, zap.NewNop(), serverExp.MetricSet())
	if err != nil {
		b.Fatalf("new server agent: %v", err)
	}
	clientExp := metrics.NewExporter(clientCfg.Metrics)
	clientAgent, err := agent.New(clientCfg, zap.NewNop(), clientExp.MetricSet())
	if err != nil {
		b.Fatalf("new client agent: %v", err)
	}

	grp, grpCtx := errgroup.WithContext(ctx)
	grp.Go(func() error { return serverAgent.Run(grpCtx) })
	grp.Go(func() error { return clientAgent.Run(grpCtx) })
	b.Cleanup(func() {
		cancel()
		grp.Wait()
	})

	wgHomeConn := listenUDPOrSkip(b, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	b.Cleanup(func() { wgHomeConn.Close() })

	serverAddrCh := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 65535)
		for {
			wgBackend.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := wgBackend.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
					}
					continue
				}
				return
			}
			select {
			case serverAddrCh <- addr:
			default:
			}
			wgBackend.WriteToUDP(buf[:n], addr) // echo back for RTT measurement
		}
	}()

	payload := make([]byte, 1400)
	totalBytes := int64(0)
	totalLatency := time.Duration(0)
	b.SetBytes(int64(len(payload)))

	buf := make([]byte, 65535)
	target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientUDPPort}

	// Warm-up
	wgHomeConn.WriteToUDP(payload, target)
	wgHomeConn.ReadFromUDP(buf)
	select {
	case <-serverAddrCh:
	case <-time.After(time.Second):
		b.Fatalf("server never reported udp addr")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if _, err := wgHomeConn.WriteToUDP(payload, target); err != nil {
			b.Fatalf("udp send: %v", err)
		}
		if err := wgHomeConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			b.Fatalf("set read deadline: %v", err)
		}
		n, _, err := wgHomeConn.ReadFromUDP(buf)
		if err != nil {
			b.Fatalf("udp read: %v", err)
		}
		totalLatency += time.Since(start)
		totalBytes += int64(n)
	}
	b.StopTimer()

	if totalLatency > 0 {
		throughput := float64(totalBytes) / totalLatency.Seconds()
		b.ReportMetric(throughput, "B/s")
		b.ReportMetric(float64(totalLatency)/float64(b.N)/float64(time.Millisecond), "ms/op")
	}
}
