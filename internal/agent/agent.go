package agent

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/fanzy618/uot/internal/config"
	"github.com/fanzy618/uot/internal/metrics"
)

// Agent is the long-running component for a specific role.
type Agent interface {
	Run(ctx context.Context) error
}

// New wires the right agent based on role.
func New(cfg *config.Config, logger *zap.Logger, metricSet metrics.MetricSet) (Agent, error) {
	switch cfg.Role {
	case config.RoleClient:
		return newClientAgent(cfg, logger.Named("client"), metricSet)
	case config.RoleServer:
		return newServerAgent(cfg, logger.Named("server"), metricSet)
	default:
		return nil, fmt.Errorf("unsupported role %q", cfg.Role)
	}
}
