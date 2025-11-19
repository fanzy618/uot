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

func TestClientServerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath := generateTLSMaterial(t, tempDir)

	wgBackend := listenUDPOrSkip(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer wgBackend.Close()

	serverTCPAddr := fmt.Sprintf("127.0.0.1:%d", mustFreePort(t))
	clientUDPPort := mustFreePort(t)
	clientUDPAddr := fmt.Sprintf("127.0.0.1:%d", clientUDPPort)

	serverCfg := &config.Config{
		Role: config.RoleServer,
		TCP: config.TCPConfig{
			ListenAddr:  serverTCPAddr,
			Lanes:       1,
			TCPNoDelay:  true,
			TCPBuf:      16384,
			IdleSeconds: 5,
		},
		UDP: config.UDPConfig{
			WGAddr: wgBackend.LocalAddr().String(),
		},
		Queue: config.QueueConfig{
			MaxPackets: 64,
			MaxBytes:   1 << 20,
			DropPolicy: "oldest",
		},
		Metrics: config.MetricsConfig{
			ListenAddr:  "127.0.0.1:0",
			Path:        "/metrics",
			PerClientCN: true,
		},
		TLS: config.TLSConfig{
			CACert: caCertPath,
			Cert:   serverCertPath,
			Key:    serverKeyPath,
		},
	}
	if err := serverCfg.Validate(); err != nil {
		t.Fatalf("server config invalid: %v", err)
	}

	clientCfg := &config.Config{
		Role: config.RoleClient,
		TCP: config.TCPConfig{
			ServerAddr:  serverTCPAddr,
			Lanes:       2,
			TCPNoDelay:  true,
			TCPBuf:      16384,
			IdleSeconds: 5,
		},
		UDP: config.UDPConfig{
			ListenAddr: clientUDPAddr,
		},
		Queue: serverCfg.Queue,
		Metrics: config.MetricsConfig{
			ListenAddr:  "127.0.0.1:0",
			Path:        "/metrics",
			PerClientCN: true,
		},
		TLS: config.TLSConfig{
			CACert: caCertPath,
			Cert:   clientCertPath,
			Key:    clientKeyPath,
		},
	}
	if err := clientCfg.Validate(); err != nil {
		t.Fatalf("client config invalid: %v", err)
	}

	serverExp := metrics.NewExporter(serverCfg.Metrics)
	serverAgent, err := agent.New(serverCfg, zap.NewNop(), serverExp.MetricSet())
	if err != nil {
		t.Fatalf("new server agent: %v", err)
	}

	clientExp := metrics.NewExporter(clientCfg.Metrics)
	clientAgent, err := agent.New(clientCfg, zap.NewNop(), clientExp.MetricSet())
	if err != nil {
		t.Fatalf("new client agent: %v", err)
	}

	grp, grpCtx := errgroup.WithContext(ctx)
	grp.Go(func() error {
		return serverAgent.Run(grpCtx)
	})
	grp.Go(func() error {
		return clientAgent.Run(grpCtx)
	})

	defer func() {
		cancel()
		if err := grp.Wait(); err != nil && err != context.Canceled {
			t.Errorf("agents exited with error: %v", err)
		}
	}()

	wgHomeConn := listenUDPOrSkip(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer wgHomeConn.Close()

	backendRecv := make(chan []byte, 1)
	serverUDPAddr := make(chan *net.UDPAddr, 1)
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
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case backendRecv <- pkt:
			default:
			}
			select {
			case serverUDPAddr <- addr:
			default:
			}
		}
	}()

	upPayload := []byte("hello-upstream")
	sendDeadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := wgHomeConn.WriteToUDP(upPayload, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientUDPPort}); err != nil {
			t.Fatalf("send to client udp: %v", err)
		}
		select {
		case got := <-backendRecv:
			if string(got) != string(upPayload) {
				t.Fatalf("backend payload mismatch: got %q want %q", got, upPayload)
			}
			goto Downlink
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(sendDeadline) {
			t.Fatalf("timeout waiting for upstream delivery")
		}
	}

Downlink:
	var srvAddr *net.UDPAddr
	select {
	case srvAddr = <-serverUDPAddr:
	case <-time.After(time.Second):
		t.Fatalf("missing server udp addr for downlink")
	}

	downPayload := []byte("hello-downstream")
	if _, err := wgBackend.WriteToUDP(downPayload, srvAddr); err != nil {
		t.Fatalf("backend write downlink: %v", err)
	}

	buf := make([]byte, 65535)
	if err := wgHomeConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set wg read deadline: %v", err)
	}
	n, _, err := wgHomeConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read downlink: %v", err)
	}
	if string(buf[:n]) != string(downPayload) {
		t.Fatalf("downlink mismatch: got %q want %q", buf[:n], downPayload)
	}
}
