package resolver

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input    string
		epoch    int
		numbers  []int
		suffix   string
		suffNum  int
		revision int
	}{
		{"3.1.0-r1", 0, []int{3, 1, 0}, "", 0, 1},
		{"1.0_rc2-r0", 0, []int{1, 0}, "rc", 2, 0},
		{"2.4.3_p1-r5", 0, []int{2, 4, 3}, "p", 1, 5},
		{"1:2.3.4-r0", 1, []int{2, 3, 4}, "", 0, 0},
		{"0.12_alpha1-r0", 0, []int{0, 12}, "alpha", 1, 0},
		{"3.12.8-r3", 0, []int{3, 12, 8}, "", 0, 3},
		{"20250127.1-r4", 0, []int{20250127, 1}, "", 0, 4},
	}

	for _, tt := range tests {
		v := ParseVersion(tt.input)
		if v.Epoch != tt.epoch {
			t.Errorf("ParseVersion(%q).Epoch = %d, want %d", tt.input, v.Epoch, tt.epoch)
		}
		if len(v.Numbers) != len(tt.numbers) {
			t.Errorf("ParseVersion(%q).Numbers = %v, want %v", tt.input, v.Numbers, tt.numbers)
			continue
		}
		for i, n := range tt.numbers {
			if v.Numbers[i] != n {
				t.Errorf("ParseVersion(%q).Numbers[%d] = %d, want %d", tt.input, i, v.Numbers[i], n)
			}
		}
		if v.Suffix != tt.suffix {
			t.Errorf("ParseVersion(%q).Suffix = %q, want %q", tt.input, v.Suffix, tt.suffix)
		}
		if v.SuffixNum != tt.suffNum {
			t.Errorf("ParseVersion(%q).SuffixNum = %d, want %d", tt.input, v.SuffixNum, tt.suffNum)
		}
		if v.Revision != tt.revision {
			t.Errorf("ParseVersion(%q).Revision = %d, want %d", tt.input, v.Revision, tt.revision)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int // -1, 0, 1
	}{
		// Equal
		{"3.1.0-r0", "3.1.0-r0", 0},
		{"1.0-r0", "1.0-r0", 0},

		// Numeric ordering
		{"3.1.0-r0", "3.2.0-r0", -1},
		{"3.2.0-r0", "3.1.0-r0", 1},
		{"3.1.0-r0", "3.1.1-r0", -1},
		{"4.0.0-r0", "3.9.9-r0", 1},

		// Revision ordering
		{"3.1.0-r0", "3.1.0-r1", -1},
		{"3.1.0-r5", "3.1.0-r3", 1},

		// Different segment counts
		{"3.1-r0", "3.1.0-r0", 0},
		{"3.1.1-r0", "3.1-r0", 1},

		// Pre-release suffixes (lower than release)
		{"1.0_alpha1-r0", "1.0-r0", -1},
		{"1.0_beta1-r0", "1.0-r0", -1},
		{"1.0_rc1-r0", "1.0-r0", -1},
		{"1.0_rc2-r0", "1.0_rc1-r0", 1},

		// Post-release patch (higher than release)
		{"1.0_p1-r0", "1.0-r0", 1},
		{"1.0_p2-r0", "1.0_p1-r0", 1},

		// Suffix ordering
		{"1.0_alpha1-r0", "1.0_beta1-r0", -1},
		{"1.0_beta1-r0", "1.0_rc1-r0", -1},
		{"1.0_rc1-r0", "1.0_p1-r0", -1},

		// Epoch takes precedence
		{"1:1.0-r0", "2.0-r0", 1},
		{"0:3.0-r0", "1:1.0-r0", -1},

		// Real-world Wolfi versions
		{"3.12.8-r3", "3.12.12-r5", -1},
		{"20250127.1-r4", "20250127.1-r3", 1},
		{"8.0.122-r2", "8.0.123-r0", -1},
	}

	for _, tt := range tests {
		got := CompareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestParseDependency(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantOp   string
		wantVer  string
	}{
		{"libcrypto3>=3.1.0", "libcrypto3", ">=", "3.1.0"},
		{"busybox", "busybox", "", ""},
		{"python-3.12=3.12.8-r3", "python-3.12", "=", "3.12.8-r3"},
		{"libssl3<4.0", "libssl3", "<", "4.0"},
		{"glibc>=2.38-r0", "glibc", ">=", "2.38-r0"},
		{"so:libc.musl-x86_64.so.1", "so:libc.musl-x86_64.so.1", "", ""},
		{"abseil-cpp=20250127.1-r4", "abseil-cpp", "=", "20250127.1-r4"},
		{"!uclibc-utils", "!uclibc-utils", "", ""},
	}

	for _, tt := range tests {
		name, op, ver := ParseDependency(tt.input)
		if name != tt.wantName || op != tt.wantOp || ver != tt.wantVer {
			t.Errorf("ParseDependency(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, name, op, ver, tt.wantName, tt.wantOp, tt.wantVer)
		}
	}
}

func TestMatchConstraint(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		// Exact match
		{"3.1.0-r1", "=3.1.0-r1", true},
		{"3.1.0-r1", "=3.1.0-r0", false},

		// Greater/less
		{"3.2.0-r0", ">=3.1.0", true},
		{"3.1.0-r0", ">=3.1.0", true},
		{"3.0.9-r0", ">=3.1.0", false},
		{"3.0.0-r0", "<4.0.0", true},
		{"4.0.0-r0", "<4.0.0", false},
		{"3.9.9-r9", "<=4.0.0", true},

		// Empty constraint matches everything
		{"1.0-r0", "", true},

		// Checksum constraints always match
		{"3.1.0-r0", "><abc123", true},
	}

	for _, tt := range tests {
		got := MatchConstraint(tt.version, tt.constraint)
		if got != tt.want {
			t.Errorf("MatchConstraint(%q, %q) = %v, want %v",
				tt.version, tt.constraint, got, tt.want)
		}
	}
}
