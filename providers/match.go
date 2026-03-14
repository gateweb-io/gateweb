package providers

import (
	"regexp"
	"strings"
	"sync"

	"gateweb/contracts"
)

// regexCache caches compiled regex patterns to avoid recompilation on every request.
var (
	regexCache   sync.Map // map[string]*regexp.Regexp
)

func getRegexp(pattern string) (*regexp.Regexp, bool) {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	regexCache.Store(pattern, re)
	return re, true
}

// MatchesTargets checks if a request matches any of the rule's targets.
// An empty target list means the rule applies to all requests.
func MatchesTargets(targets []contracts.Target, req contracts.PolicyRequest) bool {
	if len(targets) == 0 {
		return true // no target restriction = applies to all
	}
	for _, t := range targets {
		switch t.Type {
		case "all":
			return true
		case "user":
			if t.ID == req.UserID {
				return true
			}
		case "group":
			for _, gid := range req.GroupIDs {
				if t.ID == gid {
					return true
				}
			}
		}
	}
	return false
}

// MatchesConditions checks if a request satisfies all conditions.
// An empty condition list means the rule always matches.
func MatchesConditions(conditions []contracts.Condition, req contracts.PolicyRequest) bool {
	if len(conditions) == 0 {
		return true // no conditions = always matches
	}
	for _, c := range conditions {
		if !MatchCondition(c, req) {
			return false // all conditions must match
		}
	}
	return true
}

// MatchCondition checks a single condition against a request.
func MatchCondition(c contracts.Condition, req contracts.PolicyRequest) bool {
	switch c.Type {
	case "domain":
		return MatchDomain(c.Value, req.Host)
	case "category":
		if strings.EqualFold(c.Value, req.Category) {
			return true
		}
		for _, cat := range req.Categories {
			if strings.EqualFold(c.Value, cat) {
				return true
			}
		}
		return false
	case "path":
		return MatchPath(c.Value, req.Path)
	case "url":
		return MatchURL(c.Value, req.Host, req.Path)
	case "app":
		return strings.EqualFold(c.Value, req.AppName)
	default:
		return false
	}
}

// MatchPath supports exact, prefix (ending with *), and suffix (starting with *) matching.
func MatchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(path, pattern[1:])
	}
	if strings.ContainsAny(pattern, "^$+()[]{}|") {
		if re, ok := getRegexp(pattern); ok {
			return re.MatchString(path)
		}
	}
	return false
}

// MatchURL matches "domain/path" patterns against a request's host and path.
// Example: "example.com/api/*" matches host=example.com path=/api/foo.
func MatchURL(pattern, host, path string) bool {
	parts := strings.SplitN(pattern, "/", 2)
	if len(parts) != 2 {
		return MatchDomain(pattern, host)
	}
	return MatchDomain(parts[0], host) && MatchPath("/"+parts[1], path)
}

// MatchDomain supports exact match and wildcards like "*.gambling.com".
// Comparison is case-insensitive per RFC 4343.
func MatchDomain(pattern, host string) bool {
	if strings.EqualFold(pattern, host) {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.ToLower(pattern[1:]) // ".gambling.com"
		hostLower := strings.ToLower(host)
		return strings.HasSuffix(hostLower, suffix) || hostLower == strings.ToLower(pattern[2:])
	}
	// Try as a regex pattern.
	if strings.ContainsAny(pattern, "^$+()[]{}|") {
		if re, ok := getRegexp(pattern); ok {
			return re.MatchString(host)
		}
	}
	return false
}
