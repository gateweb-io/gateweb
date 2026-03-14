package contracts

import "context"

// GatewayRegistry manages gateway lifecycle with the management plane.
// Local implementation is a no-op; remote registers via management API.
type GatewayRegistry interface {
	// Register announces this gateway to the management plane.
	Register(ctx context.Context, info *GatewayInfo) error

	// Heartbeat sends health metrics to the management plane.
	Heartbeat(ctx context.Context, health *GatewayHealth) error
}
