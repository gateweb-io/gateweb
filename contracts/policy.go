package contracts

import "context"

// PolicyProvider evaluates requests against policy rules.
// Local implementation reads from YAML; remote reads from management API + Kafka.
type PolicyProvider interface {
	// Evaluate a request against policy rules, return the decision.
	Evaluate(ctx context.Context, req PolicyRequest) (*Decision, error)

	// Version returns the current policy version.
	Version(ctx context.Context) (int, error)

	// Watch subscribes to policy updates. The callback is invoked when
	// the policy set changes (e.g. file modified or Kafka message received).
	Watch(ctx context.Context, callback func()) error

	// NeedsInspection returns true if any rule requires TLS inspection
	// (e.g. path-based conditions, DLP, app-level rules).
	// When false, the proxy can enforce policy on CONNECT without MITM.
	NeedsInspection() bool
}
