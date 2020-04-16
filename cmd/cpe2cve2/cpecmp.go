package main

import (
	"flag"
	"strings"
)

var safeMatching = flag.Bool("-validate_cpes", false, "check the CPE is well-formed before trying to match it, ignore malformed ones; slower, but nerver panics.")

// CPEmatch returns true if a and b match character-by-character or at least one of those is ANY logical type ('*').
// For performance reasons, this function makes assumptions about a and b structure and may panic if those aren't valid WFNs serialized as formatted strings.
func CPEmatch(a, b string) bool {
	if *safeMatching {
		if !validCPE(a) || !validCPE(b) {
			return false
		}
	}

	for i, j := 0, 0; i < len(a) && j < len(b); i, j = i+1, j+1 {
		if a[i] == b[j] {
			continue
		}

		// The only way non-equal parts of WFN can match is if one of them is of ANY logic type
		// in which case it should be immediately followed by ':' or be the last character of the string.
		// First check a...
		if a[i] == '*' {
			i++ // i should be either at the end of a or ':' now; otherwise, no match
			if i != len(a) && a[i] != ':' {
				return false
			}
			for j < len(b) && b[j] != ':' {
				j++
			}
			continue
		}
		// ...and now b.
		if b[j] == '*' {
			j++ // j should be either at the end of b or ':' now; otherwise, no match
			if j != len(b) && b[i] != ':' {
				return false
			}
			for i < len(b) && b[i] != ':' {
				i++
			}
			continue
		}
		// otherwise it's a no-match
		return false
	}
	return true
}

func getCPEversion(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return "*"
	}
	return parts[5]
}

func validCPE(cpe string) bool {
	if !strings.HasPrefix(cpe, "cpe:2.3:") || !hasAllParts(cpe) {
		return false
	}
	return true
}

func hasAllParts(cpe string) bool {
	n := 0
	for _, c := range cpe {
		if c == ':' {
			n++
		}
	}
	// cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*
	return n == 12
}
