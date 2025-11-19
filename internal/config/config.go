package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Role identifies whether the current process runs in client or server mode.
type Role string

const (
	RoleClient Role = "client"
	RoleServer Role = "server"
)

// Config captures the full YAML configuration surface described in AGENTS.md.
type Config struct {
	Role    Role          `yaml:"role"`
	TCP     TCPConfig     `yaml:"tcp"`
	UDP     UDPConfig     `yaml:"udp"`
	Queue   QueueConfig   `yaml:"queue"`
	Metrics MetricsConfig `yaml:"metrics"`
	TLS     TLSConfig     `yaml:"tls"`
}

// TCPConfig controls TLS-wrapped TCP lane behaviour.
type TCPConfig struct {
	ServerAddr  string `yaml:"server_addr"`
	ListenAddr  string `yaml:"listen_addr"`
	Lanes       int    `yaml:"lanes"`
	TCPNoDelay  bool   `yaml:"tcp_nodelay"`
	TCPBuf      int    `yaml:"tcp_buf"`
	IdleSeconds int    `yaml:"idle_seconds"`
}

// UDPConfig describes the local UDP ingress/egress sockets.
type UDPConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	WGAddr     string `yaml:"wg_udp_addr"`
}

// QueueConfig configures backpressure logic.
type QueueConfig struct {
	MaxPackets int    `yaml:"max_packets"`
	MaxBytes   int    `yaml:"max_bytes"`
	DropPolicy string `yaml:"drop_policy"`
}

// MetricsConfig controls Prometheus exposition.
type MetricsConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	Path         string `yaml:"path"`
	PerClientCN  bool   `yaml:"per_client_cn"`
	PerLaneLabel bool   `yaml:"per_lane_label"`
}

// TLSConfig contains filesystem paths for all TLS material.
type TLSConfig struct {
	CACert  string `yaml:"ca_cert"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
	Disable bool   `yaml:"disable"`
}

// Load reads, unmarshals, default-fills, and validates a Config document.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate asserts the resulting configuration obeys spec.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	switch c.Role {
	case RoleClient:
		if c.TCP.ServerAddr == "" {
			return errors.New("tcp.server_addr required for client role")
		}
		if c.UDP.ListenAddr == "" {
			return errors.New("udp.listen_addr required for client role")
		}
	case RoleServer:
		if c.TCP.ListenAddr == "" {
			return errors.New("tcp.listen_addr required for server role")
		}
		if c.UDP.WGAddr == "" {
			return errors.New("udp.wg_udp_addr required for server role")
		}
	default:
		return fmt.Errorf("role must be %q or %q", RoleClient, RoleServer)
	}

	if c.TCP.Lanes <= 0 {
		return errors.New("tcp.lanes must be > 0")
	}
	if c.TCP.TCPBuf <= 0 {
		return errors.New("tcp.tcp_buf must be > 0")
	}
	if c.TCP.IdleSeconds <= 0 {
		return errors.New("tcp.idle_seconds must be > 0")
	}

	if c.Queue.MaxPackets <= 0 {
		return errors.New("queue.max_packets must be > 0")
	}
	if c.Queue.MaxBytes <= 0 {
		return errors.New("queue.max_bytes must be > 0")
	}

	switch c.Queue.DropPolicy {
	case "oldest":
	case "":
		return errors.New("queue.drop_policy required")
	default:
		return fmt.Errorf("queue.drop_policy %q unsupported", c.Queue.DropPolicy)
	}

	if c.Metrics.ListenAddr == "" {
		return errors.New("metrics.listen_addr required")
	}
	if c.Metrics.Path == "" {
		return errors.New("metrics.path required")
	}

	if !c.TLS.Disable {
		if err := validateReadableFile(c.TLS.CACert); err != nil {
			return fmt.Errorf("tls.ca_cert: %w", err)
		}
		if err := validateReadableFile(c.TLS.Cert); err != nil {
			return fmt.Errorf("tls.cert: %w", err)
		}
		if err := validateReadableFile(c.TLS.Key); err != nil {
			return fmt.Errorf("tls.key: %w", err)
		}
	}

	return nil
}

func (c *Config) applyDefaults() {
	if c.TCP.Lanes == 0 {
		c.TCP.Lanes = 5
	}
	if c.TCP.TCPBuf == 0 {
		c.TCP.TCPBuf = 16384
	}
	if c.TCP.IdleSeconds == 0 {
		c.TCP.IdleSeconds = 120
	}
	if c.Queue.MaxPackets == 0 {
		c.Queue.MaxPackets = 4096
	}
	if c.Queue.MaxBytes == 0 {
		c.Queue.MaxBytes = 8 << 20
	}
	if c.Queue.DropPolicy == "" {
		c.Queue.DropPolicy = "oldest"
	}
	if c.Metrics.ListenAddr == "" {
		c.Metrics.ListenAddr = "127.0.0.1:5080"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
}

func validateReadableFile(path string) error {
	if path == "" {
		return errors.New("path empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("file %s does not exist", path)
		}
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is directory", path)
	}
	return nil
}

// IdleDuration returns the idle timeout as a time.Duration.
func (t TCPConfig) IdleDuration() time.Duration {
	if t.IdleSeconds <= 0 {
		return 0
	}
	return time.Duration(t.IdleSeconds) * time.Second
}

// Loggable returns a configuration snapshot suitable for structured logging.
func (c *Config) Loggable() map[string]any {
	if c == nil {
		return nil
	}
	return map[string]any{
		"role": c.Role,
		"tcp": map[string]any{
			"server_addr": c.TCP.ServerAddr,
			"listen_addr": c.TCP.ListenAddr,
			"lanes":       c.TCP.Lanes,
			"tcp_nodelay": c.TCP.TCPNoDelay,
			"tcp_buf":     c.TCP.TCPBuf,
			"idle_sec":    c.TCP.IdleSeconds,
		},
		"udp": map[string]any{
			"listen_addr": c.UDP.ListenAddr,
			"wg_udp_addr": c.UDP.WGAddr,
		},
		"queue": map[string]any{
			"max_packets": c.Queue.MaxPackets,
			"max_bytes":   c.Queue.MaxBytes,
			"drop_policy": c.Queue.DropPolicy,
		},
		"metrics": map[string]any{
			"listen_addr":    c.Metrics.ListenAddr,
			"path":           c.Metrics.Path,
			"per_client_cn":  c.Metrics.PerClientCN,
			"per_lane_label": c.Metrics.PerLaneLabel,
		},
		"tls": map[string]any{
			"ca_cert": c.TLS.CACert,
			"cert":    c.TLS.Cert,
			"key":     c.TLS.Key,
			"disable": c.TLS.Disable,
		},
	}
}
