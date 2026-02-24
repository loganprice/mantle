package resolver

import (
	"strconv"
	"strings"
	"unicode"
)

// Version represents a parsed APK version string.
// Format: [epoch:]major[.minor[.patch[...]]][_suffix[N]][-rRevision]
//
// Examples:
//   - "3.1.0-r1"       → Numbers=[3,1,0], Suffix="", SuffixNum=0, Revision=1
//   - "1.0_rc2-r0"     → Numbers=[1,0], Suffix="rc", SuffixNum=2, Revision=0
//   - "2.4.3_p1-r5"    → Numbers=[2,4,3], Suffix="p", SuffixNum=1, Revision=5
type Version struct {
	Epoch     int
	Numbers   []int
	Letters   []string // letter suffixes on numeric segments (e.g., "3.1a" → Letters=["","","a"])
	Suffix    string   // pre/post-release suffix: alpha, beta, pre, rc, p, or ""
	SuffixNum int      // numeric part of suffix (e.g., _rc2 → 2)
	Revision  int      // -rN revision number
	Raw       string   // original unparsed string
}

// suffixOrder defines the ordering of APK version suffixes.
// Lower index = lower precedence.
var suffixOrder = map[string]int{
	"alpha": 0,
	"beta":  1,
	"pre":   2,
	"rc":    3,
	"":      4, // no suffix = release
	"cvs":   5,
	"svn":   6,
	"git":   7,
	"hg":    8,
	"p":     9, // post-release patch
}

// ParseVersion parses an APK version string into its components.
func ParseVersion(s string) Version {
	v := Version{Raw: s}

	// Handle epoch (e.g., "1:2.3.4-r0")
	if idx := strings.Index(s, ":"); idx > 0 {
		if epoch, err := strconv.Atoi(s[:idx]); err == nil {
			v.Epoch = epoch
			s = s[idx+1:]
		}
	}

	// Split off revision (-rN)
	if idx := strings.LastIndex(s, "-r"); idx > 0 {
		revStr := s[idx+2:]
		if rev, err := strconv.Atoi(revStr); err == nil {
			v.Revision = rev
			s = s[:idx]
		}
	}

	// Split off suffix (_alpha, _beta, _pre, _rc, _p, etc.)
	if idx := strings.LastIndex(s, "_"); idx > 0 {
		suffixPart := s[idx+1:]
		// Extract suffix name and optional number
		name, num := splitSuffixNum(suffixPart)
		if _, ok := suffixOrder[name]; ok {
			v.Suffix = name
			v.SuffixNum = num
			s = s[:idx]
		}
	}

	// Parse dot-separated version segments (e.g., "3.1.0" or "3.1a")
	parts := strings.Split(s, ".")
	for _, part := range parts {
		num, letter := splitNumLetter(part)
		v.Numbers = append(v.Numbers, num)
		v.Letters = append(v.Letters, letter)
	}

	return v
}

// splitSuffixNum splits a suffix like "rc2" into ("rc", 2) or "alpha" into ("alpha", 0).
func splitSuffixNum(s string) (name string, num int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	name = s[:i]
	num = 0
	if i < len(s) {
		num, _ = strconv.Atoi(s[i:])
	}
	return name, num
}

// splitNumLetter splits "3" into (3, "") or "1a" into (1, "a").
func splitNumLetter(s string) (num int, letter string) {
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') {
		i++
	}
	num = 0
	if i > 0 {
		num, _ = strconv.Atoi(s[:i])
	}
	return num, s[i:]
}

// CompareVersions compares two APK version strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b string) int {
	va := ParseVersion(a)
	vb := ParseVersion(b)

	// 1. Epoch
	if c := cmpInt(va.Epoch, vb.Epoch); c != 0 {
		return c
	}

	// 2. Numeric segments
	maxLen := len(va.Numbers)
	if len(vb.Numbers) > maxLen {
		maxLen = len(vb.Numbers)
	}
	for i := 0; i < maxLen; i++ {
		na, nb := getNum(va.Numbers, i), getNum(vb.Numbers, i)
		if c := cmpInt(na, nb); c != 0 {
			return c
		}
		// Compare letter suffixes on the same segment
		la, lb := getLetter(va.Letters, i), getLetter(vb.Letters, i)
		if c := cmpStr(la, lb); c != 0 {
			// No letter suffix > letter suffix (e.g., "1" > "1a" is wrong;
			// actually in APK, "1a" > "1" because letter indicates a sub-release)
			if la == "" && lb != "" {
				return -1
			}
			if la != "" && lb == "" {
				return 1
			}
			return c
		}
	}

	// 3. Suffix ordering
	sa := suffixOrder[va.Suffix]
	sb := suffixOrder[vb.Suffix]
	if c := cmpInt(sa, sb); c != 0 {
		return c
	}
	// Same suffix type: compare suffix numbers
	if c := cmpInt(va.SuffixNum, vb.SuffixNum); c != 0 {
		return c
	}

	// 4. Revision
	return cmpInt(va.Revision, vb.Revision)
}

// MatchConstraint checks if a version satisfies a constraint string.
// Constraint format: "operator version" (e.g., ">=3.1.0-r1", "=2.0", "<4.0_rc1").
// For a plain version with no operator, it's treated as exact match (=).
func MatchConstraint(version, constraint string) bool {
	op, constraintVer := ParseConstraint(constraint)
	if constraintVer == "" {
		return true // no constraint — matches anything
	}

	cmp := CompareVersions(version, constraintVer)

	switch op {
	case "=":
		return cmp == 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case "~=":
		// Compatible release: >= specified version AND < next major
		// "~=3.1" matches >= 3.1.0, < 4.0.0
		if cmp < 0 {
			return false
		}
		cv := ParseVersion(constraintVer)
		if len(cv.Numbers) > 0 {
			nextMajor := strconv.Itoa(cv.Numbers[0] + 1)
			return CompareVersions(version, nextMajor) < 0
		}
		return true
	case "><":
		// Checksum constraint — used internally by APK, always matches
		return true
	default:
		return true
	}
}

// ParseConstraint splits a dependency string like "libcrypto3>=3.1.0" into
// the package name, operator, and version. Returns (operator, version).
// If there is no constraint, returns ("", "").
func ParseConstraint(dep string) (op, ver string) {
	// Order matters: two-char operators before single-char
	for _, op := range []string{">=", "<=", "~=", "><", ">", "<", "="} {
		if idx := strings.Index(dep, op); idx >= 0 {
			return op, dep[idx+len(op):]
		}
	}
	return "", ""
}

// ParseDependency splits a dependency string into (name, operator, version).
// Examples:
//   - "libcrypto3>=3.1.0"   → ("libcrypto3", ">=", "3.1.0")
//   - "busybox"             → ("busybox", "", "")
//   - "python-3.12=3.12.8"  → ("python-3.12", "=", "3.12.8")
func ParseDependency(dep string) (name, op, ver string) {
	// Order matters: two-char operators before single-char
	for _, operator := range []string{">=", "<=", "~=", "><"} {
		if idx := strings.Index(dep, operator); idx > 0 {
			return dep[:idx], operator, dep[idx+len(operator):]
		}
	}
	// Single-char operators: need special care for package names with digits
	// e.g. "python-3.12=3.12.8" — the '=' after the name
	// Strategy: find the LAST occurrence of single-char operators that has
	// a reasonable version string after it
	for _, operator := range []string{"=", ">", "<"} {
		idx := findOperatorIndex(dep, operator)
		if idx > 0 {
			return dep[:idx], operator, dep[idx+1:]
		}
	}
	return dep, "", ""
}

// findOperatorIndex finds the position of a single-char version operator
// in a dependency string, distinguishing it from characters in package names.
// We scan right-to-left to find the operator that starts a valid version string.
func findOperatorIndex(dep, op string) int {
	for i := len(dep) - 1; i > 0; i-- {
		if string(dep[i]) == op {
			// Check that what follows looks like a version (starts with digit)
			if i+1 < len(dep) && unicode.IsDigit(rune(dep[i+1])) {
				return i
			}
		}
	}
	return -1
}

// Helper functions for comparison
func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpStr(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func getNum(nums []int, i int) int {
	if i < len(nums) {
		return nums[i]
	}
	return 0
}

func getLetter(letters []string, i int) string {
	if i < len(letters) {
		return letters[i]
	}
	return ""
}
