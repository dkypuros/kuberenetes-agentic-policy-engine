package policy

import (
	"strings"
	"sync"
	"time"
)

// DecisionCache provides O(1) lookups for policy decisions.
// This is the AVC (Access Vector Cache) pattern from SELinux.
//
// The cache dramatically improves performance for repeated tool calls:
//   - First call: ~100μs (policy evaluation)
//   - Cached call: ~1μs (map lookup)
//
// Cache is invalidated when policies are updated.
type DecisionCache struct {
	entries sync.Map
	ttl     time.Duration
	hits    uint64
	misses  uint64
	mu      sync.RWMutex // protects hits/misses counters
}

type cacheEntry struct {
	decision  Decision
	reason    string
	expiresAt time.Time
}

// NewDecisionCache creates a cache with the given TTL.
// Recommended TTL: 60 seconds (balance freshness vs. performance)
func NewDecisionCache(ttl time.Duration) *DecisionCache {
	return &DecisionCache{
		ttl: ttl,
	}
}

// CacheKey generates a lookup key from agent type and tool name.
// Format: "agentType:toolName"
func CacheKey(agentType, toolName string) string {
	return agentType + ":" + toolName
}

// Get retrieves a cached decision.
// Returns (decision, reason, true) on hit, (Deny, "", false) on miss/expired.
func (c *DecisionCache) Get(key string) (Decision, string, bool) {
	val, ok := c.entries.Load(key)
	if !ok {
		c.recordMiss()
		return Deny, "", false
	}

	entry := val.(cacheEntry)
	if time.Now().After(entry.expiresAt) {
		// Entry expired, delete it
		c.entries.Delete(key)
		c.recordMiss()
		return Deny, "", false
	}

	c.recordHit()
	return entry.decision, entry.reason, true
}

// Set stores a decision in the cache.
func (c *DecisionCache) Set(key string, decision Decision, reason string) {
	c.entries.Store(key, cacheEntry{
		decision:  decision,
		reason:    reason,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// InvalidatePrefix removes all entries matching a prefix.
// Used when a policy for a specific agent type is updated.
// Example: InvalidatePrefix("coding-assistant:") clears all coding-assistant decisions.
func (c *DecisionCache) InvalidatePrefix(prefix string) int {
	count := 0
	c.entries.Range(func(key, _ interface{}) bool {
		if k, ok := key.(string); ok {
			if strings.HasPrefix(k, prefix) {
				c.entries.Delete(key)
				count++
			}
		}
		return true
	})
	return count
}

// InvalidateAll clears the entire cache.
// Used when global policy changes occur.
func (c *DecisionCache) InvalidateAll() int {
	count := 0
	c.entries.Range(func(key, _ interface{}) bool {
		c.entries.Delete(key)
		count++
		return true
	})
	return count
}

// Stats returns cache hit/miss statistics.
func (c *DecisionCache) Stats() (hits, misses uint64, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return
}

func (c *DecisionCache) recordHit() {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
}

func (c *DecisionCache) recordMiss() {
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()
}

// Size returns the approximate number of entries in the cache.
func (c *DecisionCache) Size() int {
	count := 0
	c.entries.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
