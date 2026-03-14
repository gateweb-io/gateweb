package contracts

import "time"

// --- Policy ---

// RuleType categorizes the kind of policy rule.
type RuleType string

const (
	RuleTypeAccess RuleType = "access"
	RuleTypeDLP    RuleType = "dlp"
	RuleTypeAI     RuleType = "ai"
	RuleTypeSaaS   RuleType = "saas"
	RuleTypeSSL    RuleType = "ssl"
)

// Action defines what the proxy should do when a rule matches.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionBlock   Action = "block"
	ActionLog     Action = "log"
	ActionAlert   Action = "alert"
	ActionWarn    Action = "warn"
	ActionIsolate Action = "isolate"
	ActionDecrypt Action = "decrypt"
	ActionBypass  Action = "bypass"
)

// PolicyRule defines a single rule in the policy engine.
type PolicyRule struct {
	ID         string      `yaml:"id" json:"id"`
	Name       string      `yaml:"name" json:"name"`
	Priority   int         `yaml:"priority" json:"priority"`
	Enabled    bool        `yaml:"enabled" json:"enabled"`
	Type       RuleType    `yaml:"type" json:"type"`
	Action     Action      `yaml:"action" json:"action"`
	Targets    []Target    `yaml:"targets" json:"targets"`
	Conditions []Condition `yaml:"conditions" json:"conditions"`
	DLP        *DLPConfig  `yaml:"dlp,omitempty" json:"dlp,omitempty"`
	Version    int         `yaml:"version" json:"version"`
}

// Target specifies who a rule applies to.
type Target struct {
	Type string `yaml:"type" json:"type"` // "user", "group", "gateway", "all"
	ID   string `yaml:"id" json:"id"`
}

// Condition specifies when a rule matches.
type Condition struct {
	Type  string `yaml:"type" json:"type"`   // "domain", "category", "app", "time_range"
	Value string `yaml:"value" json:"value"` // "*.gambling.com", "malware", "chatgpt", "09:00-17:00"
}

// DLPConfig holds data loss prevention patterns for a rule.
type DLPConfig struct {
	Patterns []DLPPattern `yaml:"patterns" json:"patterns"`
}

// DLPPattern defines a single DLP detection pattern.
type DLPPattern struct {
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
}

// --- Events ---

// Event represents a proxy event for logging, analytics, or SIEM integration.
// Modeled after Envoy access logs: typed JSON, one line per event.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	GatewayID string    `json:"gateway_id,omitempty"`

	// Request
	RequestMethod string `json:"request_method"`
	RequestHost   string `json:"request_host"`
	RequestPath   string `json:"request_path"`
	RequestSize   int64  `json:"request_size"`

	// Response
	ResponseStatus int   `json:"response_status"`
	ResponseSize   int64 `json:"response_size"`

	// Timing
	DurationMs int64 `json:"duration_ms"`

	// DLP
	DLPPattern string `json:"dlp_pattern,omitempty"`
	DLPMatched string `json:"dlp_matched,omitempty"`

	// Classification
	Category   string   `json:"category,omitempty"`
	Categories []string `json:"categories,omitempty"`
	AppName    string   `json:"app_name,omitempty"`

	// Policy decision
	PolicyRuleID string `json:"policy_rule_id,omitempty"`
	PolicyAction Action `json:"policy_action,omitempty"`
}

// --- Gateway ---

// GatewayInfo identifies a gateway instance for registration.
type GatewayInfo struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // "cloud", "desktop"
	Version  string `json:"version"`
	Status   string `json:"status"` // "online", "offline"
}

// GatewayHealth reports runtime health metrics for a gateway.
type GatewayHealth struct {
	GatewayID     string  `json:"gateway_id"`
	Connections   int     `json:"connections"`
	RequestsPerS  int     `json:"requests_per_s"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemPercent    float64 `json:"mem_percent"`
	PolicyVersion int     `json:"policy_version"`
}

// --- Policy evaluation result ---

// Decision is the result of evaluating a request against policy rules.
type Decision struct {
	Action   Action `json:"action"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Reason   string `json:"reason"`
}

// PolicyRequest contains the information needed to evaluate policy rules.
type PolicyRequest struct {
	UserID     string   `json:"user_id"`
	GroupIDs   []string `json:"group_ids"`
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	AppName    string   `json:"app_name"`
	Category   string   `json:"category"`
	Categories []string `json:"categories,omitempty"`
	Body       []byte   `json:"-"` // for DLP scanning
}
