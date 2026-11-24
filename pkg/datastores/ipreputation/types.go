package ipreputation

import (
	"fmt"
	"strings"
	"time"
)

// ReputationStatus indicates the reputation classification of an IP address
type ReputationStatus int

const (
	ReputationUnknown ReputationStatus = iota
	ReputationAllow
	ReputationDeny
	ReputationSuspicious
)

// String returns the string representation of the reputation status
func (r ReputationStatus) String() string {
	switch r {
	case ReputationAllow:
		return "allow"
	case ReputationDeny:
		return "deny"
	case ReputationSuspicious:
		return "suspicious"
	default:
		return "unknown"
	}
}

// IPReputation represents threat intelligence data for an IP address or network
type IPReputation struct {
	IP          string
	Status      ReputationStatus
	Source      string // Source that provided this data
	Severity    int    // 1-10 severity score
	Tags        []string
	LastUpdated time.Time
	Metadata    map[string]string

	// TTL is the entry lifetime starting when the entry is written. Zero means
	// the entry never expires. It is accepted on write and is not preserved as
	// such: read results carry the absolute ExpiresAt instead.
	TTL time.Duration

	// ExpiresAt is the absolute expiry time. It is computed from TTL (or taken
	// from the feed when an absolute time is supplied) on write, and is always
	// populated on read. The zero value means the entry never expires.
	ExpiresAt time.Time

	// MatchedPrefix is set on read results only when the entry that matched was
	// written as a network (CIDR). It stays empty for exact-address entries so
	// exact lookups keep the same result shape as before.
	MatchedPrefix string
}

// clone returns a deep copy so callers cannot mutate published store state.
func (r *IPReputation) clone() *IPReputation {
	if r == nil {
		return nil
	}
	c := *r
	if r.Tags != nil {
		c.Tags = append([]string(nil), r.Tags...)
	}
	if r.Metadata != nil {
		c.Metadata = make(map[string]string, len(r.Metadata))
		for k, v := range r.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// ConflictResolutionPolicy defines how to handle multiple sources writing different data for the same key
type ConflictResolutionPolicy int

const (
	// LastWriteWins - most recent write takes precedence (based on LastUpdated timestamp)
	LastWriteWins ConflictResolutionPolicy = iota
	// MaxSeverity - highest severity value across all sources wins
	MaxSeverity
	// PriorityBased - source with highest priority wins (based on source priority map)
	PriorityBased
)

// String returns the string representation of the conflict resolution policy
func (c ConflictResolutionPolicy) String() string {
	switch c {
	case LastWriteWins:
		return "last_write_wins"
	case MaxSeverity:
		return "max_severity"
	case PriorityBased:
		return "priority_based"
	default:
		return "unknown"
	}
}

// ParseConflictResolutionPolicy parses a policy name accepted by configuration.
func ParseConflictResolutionPolicy(s string) (ConflictResolutionPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "last_write_wins", "last-write-wins", "lastwritewins":
		return LastWriteWins, nil
	case "max_severity", "max-severity", "maxseverity":
		return MaxSeverity, nil
	case "priority_based", "priority-based", "prioritybased":
		return PriorityBased, nil
	default:
		return LastWriteWins, fmt.Errorf("unknown conflict resolution policy %q", s)
	}
}
