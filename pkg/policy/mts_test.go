package policy

import (
	"testing"
)

// TestParseMTSLabel verifies parsing of SELinux MCS-style labels
func TestParseMTSLabel(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantSens    int
		wantCats    []int
		wantErr     bool
	}{
		{
			name:     "full label",
			input:    "s0:c42,c108",
			wantSens: 0,
			wantCats: []int{42, 108},
		},
		{
			name:     "single category",
			input:    "s0:c42",
			wantSens: 0,
			wantCats: []int{42},
		},
		{
			name:     "sensitivity only",
			input:    "s0",
			wantSens: 0,
			wantCats: []int{},
		},
		{
			name:     "empty string",
			input:    "",
			wantSens: 0,
			wantCats: nil,
		},
		{
			name:     "higher sensitivity",
			input:    "s3:c100",
			wantSens: 3,
			wantCats: []int{100},
		},
		{
			name:     "multiple categories unsorted",
			input:    "s0:c500,c100,c250",
			wantSens: 0,
			wantCats: []int{100, 250, 500}, // Should be sorted
		},
		{
			name:     "duplicate categories",
			input:    "s0:c42,c42,c108",
			wantSens: 0,
			wantCats: []int{42, 108}, // Should be deduplicated
		},
		{
			name:     "with whitespace",
			input:    "  s0:c42, c108  ",
			wantSens: 0,
			wantCats: []int{42, 108},
		},
		{
			name:    "invalid no s prefix",
			input:   "0:c42",
			wantErr: true,
		},
		{
			name:    "invalid no c prefix",
			input:   "s0:42",
			wantErr: true,
		},
		{
			name:    "negative sensitivity",
			input:   "s-1:c42",
			wantErr: true,
		},
		{
			name:    "category out of range",
			input:   "s0:c1500",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, err := ParseMTSLabel(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if label.Sensitivity != tt.wantSens {
				t.Errorf("sensitivity: got %d, want %d", label.Sensitivity, tt.wantSens)
			}

			if tt.wantCats == nil {
				if label.Categories != nil {
					t.Errorf("categories: got %v, want nil", label.Categories)
				}
			} else {
				if len(label.Categories) != len(tt.wantCats) {
					t.Errorf("categories length: got %d, want %d", len(label.Categories), len(tt.wantCats))
				}
				for i, c := range tt.wantCats {
					if i < len(label.Categories) && label.Categories[i] != c {
						t.Errorf("category[%d]: got %d, want %d", i, label.Categories[i], c)
					}
				}
			}
		})
	}
}

// TestMTSLabelString verifies canonical string output
func TestMTSLabelString(t *testing.T) {
	tests := []struct {
		label *MTSLabel
		want  string
	}{
		{
			label: &MTSLabel{Sensitivity: 0, Categories: []int{42, 108}},
			want:  "s0:c42,c108",
		},
		{
			label: &MTSLabel{Sensitivity: 0, Categories: []int{42}},
			want:  "s0:c42",
		},
		{
			label: &MTSLabel{Sensitivity: 0, Categories: []int{}},
			want:  "s0",
		},
		{
			label: &MTSLabel{Sensitivity: 3, Categories: []int{100, 200}},
			want:  "s3:c100,c200",
		},
		{
			label: nil,
			want:  "",
		},
	}

	for _, tt := range tests {
		got := tt.label.String()
		if got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

// TestCanAccess verifies SELinux MCS dominance rules
func TestCanAccess(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		object  string
		want    bool
	}{
		// Same label - should access
		{
			name:    "identical labels",
			subject: "s0:c42,c108",
			object:  "s0:c42,c108",
			want:    true,
		},
		// Subject has superset - should access
		{
			name:    "subject superset",
			subject: "s0:c42,c100,c108",
			object:  "s0:c42,c108",
			want:    true,
		},
		// Subject has subset - should NOT access
		{
			name:    "subject subset",
			subject: "s0:c42",
			object:  "s0:c42,c108",
			want:    false,
		},
		// Different categories - should NOT access
		{
			name:    "disjoint categories",
			subject: "s0:c42,c108",
			object:  "s0:c200,c300",
			want:    false,
		},
		// Partial overlap - should NOT access
		{
			name:    "partial overlap",
			subject: "s0:c42,c108",
			object:  "s0:c42,c200",
			want:    false,
		},
		// Empty object - any subject with categories can access
		{
			name:    "empty object",
			subject: "s0:c42",
			object:  "s0",
			want:    true,
		},
		// Empty subject - can only access empty object
		{
			name:    "empty subject empty object",
			subject: "s0",
			object:  "s0",
			want:    true,
		},
		{
			name:    "empty subject non-empty object",
			subject: "s0",
			object:  "s0:c42",
			want:    false,
		},
		// Sensitivity dominance
		{
			name:    "higher sensitivity subject",
			subject: "s1:c42",
			object:  "s0:c42",
			want:    true,
		},
		{
			name:    "lower sensitivity subject",
			subject: "s0:c42",
			object:  "s1:c42",
			want:    false,
		},
		// Empty string parses to empty label (s0 with no categories)
		// Empty subject (no categories) accessing object with categories = deny
		{
			name:    "empty string subject with categorized object",
			subject: "",
			object:  "s0:c42",
			want:    false, // Empty categories cannot access categorized objects
		},
		// Subject with categories accessing empty object = allow
		{
			name:    "categorized subject with empty string object",
			subject: "s0:c42",
			object:  "",
			want:    true, // Any subject can access empty objects
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, _ := ParseMTSLabel(tt.subject)
			object, _ := ParseMTSLabel(tt.object)

			got := subject.CanAccess(object)
			if got != tt.want {
				t.Errorf("CanAccess(%q, %q) = %v, want %v", tt.subject, tt.object, got, tt.want)
			}
		})
	}

	// Test actual nil pointers (no MTS enforcement)
	t.Run("nil pointers", func(t *testing.T) {
		var nilLabel *MTSLabel
		categorized, _ := ParseMTSLabel("s0:c42")

		// Nil subject can access anything
		if !nilLabel.CanAccess(categorized) {
			t.Error("nil subject should be able to access any object")
		}

		// Any subject can access nil object
		if !categorized.CanAccess(nilLabel) {
			t.Error("any subject should be able to access nil object")
		}

		// Nil subject can access nil object
		if !nilLabel.CanAccess(nilLabel) {
			t.Error("nil subject should be able to access nil object")
		}
	})
}

// TestGenerateMTSLabel verifies deterministic label generation
func TestGenerateMTSLabel(t *testing.T) {
	// Test determinism: same tenant always gets same label
	t.Run("deterministic", func(t *testing.T) {
		label1 := GenerateMTSLabel("tenant-123")
		label2 := GenerateMTSLabel("tenant-123")

		if label1.String() != label2.String() {
			t.Errorf("labels not deterministic: %s vs %s", label1, label2)
		}
	})

	// Test uniqueness: different tenants get different labels
	t.Run("unique", func(t *testing.T) {
		tenants := []string{"tenant-a", "tenant-b", "tenant-c", "org-123", "user-456"}
		labels := make(map[string]string)

		for _, tenant := range tenants {
			label := GenerateMTSLabel(tenant)
			if existing, ok := labels[label.String()]; ok {
				t.Errorf("collision: %s and %s both got %s", tenant, existing, label)
			}
			labels[label.String()] = tenant
		}
	})

	// Test two categories generated
	t.Run("two categories", func(t *testing.T) {
		label := GenerateMTSLabel("tenant-123")
		if len(label.Categories) != 2 {
			t.Errorf("expected 2 categories, got %d", len(label.Categories))
		}
	})

	// Test empty tenant
	t.Run("empty tenant", func(t *testing.T) {
		label := GenerateMTSLabel("")
		if len(label.Categories) != 0 {
			t.Errorf("empty tenant should have no categories, got %v", label.Categories)
		}
	})

	// Test categories are sorted
	t.Run("sorted categories", func(t *testing.T) {
		label := GenerateMTSLabel("tenant-xyz")
		if len(label.Categories) == 2 && label.Categories[0] > label.Categories[1] {
			t.Errorf("categories not sorted: %v", label.Categories)
		}
	})
}

// TestMTSLabelEquals verifies label equality check
func TestMTSLabelEquals(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"identical", "s0:c42,c108", "s0:c42,c108", true},
		{"different categories", "s0:c42", "s0:c108", false},
		{"different sensitivity", "s0:c42", "s1:c42", false},
		{"different count", "s0:c42", "s0:c42,c108", false},
		{"both empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := ParseMTSLabel(tt.a)
			b, _ := ParseMTSLabel(tt.b)

			if got := a.Equals(b); got != tt.want {
				t.Errorf("Equals(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestMTSRoundTrip verifies parse -> string -> parse consistency
func TestMTSRoundTrip(t *testing.T) {
	inputs := []string{
		"s0:c42,c108",
		"s0:c42",
		"s0",
		"s3:c100,c200,c500",
	}

	for _, input := range inputs {
		label, err := ParseMTSLabel(input)
		if err != nil {
			t.Fatalf("parse %q: %v", input, err)
		}

		str := label.String()
		label2, err := ParseMTSLabel(str)
		if err != nil {
			t.Fatalf("parse round-trip %q: %v", str, err)
		}

		if !label.Equals(label2) {
			t.Errorf("round-trip failed: %q -> %q -> %v", input, str, label2)
		}
	}
}
