// Package policy implements Multi-Tenant Sandboxing (MTS) for agent isolation.
// This follows the SELinux MCS (Multi-Category Security) pattern where each
// tenant receives unique category labels for access control isolation.
package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MTSLabel represents a Multi-Tenant Sandboxing label following SELinux MCS format.
// Format: sensitivity:category1,category2 (e.g., "s0:c42,c108")
//
// The sensitivity level (s0, s1, etc.) represents classification.
// Categories (c0-c1023) represent compartments for tenant isolation.
//
// Access rules:
//   - Subject can access object if subject categories dominate object categories
//   - Dominance means subject has all categories that object has (superset or equal)
type MTSLabel struct {
	// Sensitivity level (typically s0 for tenant isolation)
	Sensitivity int

	// Categories are the compartment labels (e.g., [42, 108])
	Categories []int
}

// MaxCategory is the highest valid category number (SELinux MCS default)
const MaxCategory = 1023

// DefaultSensitivity is the default sensitivity level for tenant isolation
const DefaultSensitivity = 0

// ErrInvalidMTSLabel indicates a malformed MTS label string
var ErrInvalidMTSLabel = errors.New("invalid MTS label format")

// ErrCategoryOutOfRange indicates a category number exceeds MaxCategory
var ErrCategoryOutOfRange = errors.New("category out of range (0-1023)")

// ParseMTSLabel parses an SELinux MCS-style label string.
// Valid formats:
//   - "s0:c42,c108" - sensitivity 0 with categories 42 and 108
//   - "s0:c42"      - sensitivity 0 with single category
//   - "s0"          - sensitivity 0 with no categories (empty compartment)
//   - ""            - empty label (no restrictions)
func ParseMTSLabel(s string) (*MTSLabel, error) {
	if s == "" {
		return &MTSLabel{Sensitivity: DefaultSensitivity, Categories: nil}, nil
	}

	s = strings.TrimSpace(s)

	// Split sensitivity from categories
	parts := strings.SplitN(s, ":", 2)
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "s") {
		return nil, ErrInvalidMTSLabel
	}

	// Parse sensitivity level
	sensStr := parts[0][1:] // Remove 's' prefix
	sensitivity, err := strconv.Atoi(sensStr)
	if err != nil || sensitivity < 0 {
		return nil, ErrInvalidMTSLabel
	}

	label := &MTSLabel{
		Sensitivity: sensitivity,
		Categories:  make([]int, 0),
	}

	// Parse categories if present
	if len(parts) == 2 && parts[1] != "" {
		catStrs := strings.Split(parts[1], ",")
		for _, catStr := range catStrs {
			catStr = strings.TrimSpace(catStr)
			if !strings.HasPrefix(catStr, "c") {
				return nil, ErrInvalidMTSLabel
			}

			catNum, err := strconv.Atoi(catStr[1:])
			if err != nil {
				return nil, ErrInvalidMTSLabel
			}
			if catNum < 0 || catNum > MaxCategory {
				return nil, ErrCategoryOutOfRange
			}

			label.Categories = append(label.Categories, catNum)
		}

		// Sort and deduplicate categories for canonical form
		label.Categories = uniqueSorted(label.Categories)
	}

	return label, nil
}

// String returns the canonical SELinux MCS format string.
func (l *MTSLabel) String() string {
	if l == nil {
		return ""
	}

	if len(l.Categories) == 0 {
		return fmt.Sprintf("s%d", l.Sensitivity)
	}

	catStrs := make([]string, len(l.Categories))
	for i, c := range l.Categories {
		catStrs[i] = fmt.Sprintf("c%d", c)
	}
	return fmt.Sprintf("s%d:%s", l.Sensitivity, strings.Join(catStrs, ","))
}

// GenerateMTSLabel creates a deterministic MTS label from a tenant ID.
// Uses two categories for better isolation (birthday problem mitigation).
// The same tenant ID always produces the same label.
func GenerateMTSLabel(tenantID string) *MTSLabel {
	if tenantID == "" {
		return &MTSLabel{Sensitivity: DefaultSensitivity}
	}

	// Generate two deterministic categories from tenant ID
	cat1 := hashToCategory(tenantID, 0)
	cat2 := hashToCategory(tenantID, 1)

	// Ensure they're different (if collision, adjust second)
	if cat1 == cat2 {
		cat2 = (cat2 + 1) % (MaxCategory + 1)
	}

	return &MTSLabel{
		Sensitivity: DefaultSensitivity,
		Categories:  uniqueSorted([]int{cat1, cat2}),
	}
}

// hashToCategory generates a deterministic category from tenant ID and seed.
// Uses SHA-256 to ensure uniform distribution across category space.
func hashToCategory(tenantID string, seed int) int {
	h := sha256.New()
	h.Write([]byte(tenantID))
	h.Write([]byte{byte(seed)})
	sum := h.Sum(nil)

	// Use first 2 bytes for category (big endian)
	val := binary.BigEndian.Uint16(sum[:2])
	return int(val) % (MaxCategory + 1)
}

// CanAccess checks if a subject with this label can access an object with the given label.
// Implements SELinux MCS dominance rules:
//   - Subject sensitivity must be >= object sensitivity
//   - Subject categories must be a superset of (or equal to) object categories
//   - Empty subject categories can only access empty object categories
//
// Returns true if access is permitted.
func (l *MTSLabel) CanAccess(object *MTSLabel) bool {
	if l == nil || object == nil {
		// Nil labels permit access (no MTS enforcement)
		return true
	}

	// Check sensitivity dominance
	if l.Sensitivity < object.Sensitivity {
		return false
	}

	// Empty subject can only access empty object
	if len(l.Categories) == 0 {
		return len(object.Categories) == 0
	}

	// Empty object is accessible by any subject with categories
	if len(object.Categories) == 0 {
		return true
	}

	// Subject must have all categories that object has (dominance)
	return containsAll(l.Categories, object.Categories)
}

// Equals checks if two MTS labels are identical.
func (l *MTSLabel) Equals(other *MTSLabel) bool {
	if l == nil && other == nil {
		return true
	}
	if l == nil || other == nil {
		return false
	}
	if l.Sensitivity != other.Sensitivity {
		return false
	}
	if len(l.Categories) != len(other.Categories) {
		return false
	}
	for i, c := range l.Categories {
		if c != other.Categories[i] {
			return false
		}
	}
	return true
}

// --- Helper functions ---

// uniqueSorted returns a sorted slice with duplicates removed.
func uniqueSorted(cats []int) []int {
	if len(cats) == 0 {
		return cats
	}

	sort.Ints(cats)
	result := make([]int, 0, len(cats))
	prev := -1
	for _, c := range cats {
		if c != prev {
			result = append(result, c)
			prev = c
		}
	}
	return result
}

// containsAll checks if a contains all elements of b (both must be sorted).
func containsAll(a, b []int) bool {
	j := 0
	for i := 0; i < len(b); i++ {
		for j < len(a) && a[j] < b[i] {
			j++
		}
		if j >= len(a) || a[j] != b[i] {
			return false
		}
	}
	return true
}
